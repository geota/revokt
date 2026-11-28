// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class, dev.revokt.RevoktTestingApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.LogLevel
import dev.revokt.RevoktPolicy
import dev.revokt.SeedSource
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.engine.fetch.client
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.seed.SeedFixture
import dev.revokt.engine.update.PollSchedule
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import java.io.IOException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The result each sync returns for the public `sync()` (spec §4 `sync`, §5.1 "The sync schedule"): the start task's
 * first sync and a later one ([CrliteRuntime.startTaskWithSync], [CrliteRuntime.syncStep]), `UNCHANGED` with no fetching
 * source, `FAILED`/`STORE_FAILED` while the store read stays unresolved, `INTERNAL_ERROR` for a throw before the sync
 * ended and the sync's own result for one after, and why no first sync ran. The binding's delivery of these results is
 * `RevoktSyncTest`'s (revokt-jsse); the schedule itself is `CrliteRuntimePollTest`'s.
 */
internal class CrliteRuntimeSyncResultTest : SeedFixture() {
    private val minute = 60_000L
    private val seedRandom = 7

    private fun source(seed: Seed): SeedSource {
        val bytes = seed.bytes()
        return Counted { bytes }.source
    }

    private fun runtime(
        seed: SeedSource?,
        server: Server,
        random: Random = Random(seedRandom),
    ): CrliteRuntime =
        CrliteRuntime(
            seed = seed,
            channel = CrliteChannel.COMPAT,
            crlite = true,
            fetchingSource = true,
            engine = TestEngine(),
            verifier = verifier,
            policy = RevoktPolicy.DEFAULT,
            pinnedRootSpkis = pinned,
            storage = storage,
            logger = logger,
            client = client(server.fetcher, source),
            random = random,
        )

    private fun CrliteRuntime.crlite(): DatasetGeneration = assertNotNull(snapshot.snapshot.datasets[Dataset.CRLITE])

    /** The jitter the runtime draws, in order, from its fixed random source. */
    private val jitters = Random(seedRandom).let { r -> List(2) { PollSchedule.jitterMillis(r) } }

    @Test
    fun `the start task's first sync and each later sync return their result for sync() (spec §4)`() {
        val now = ts - 25 * hour
        val server = Server(ts = ts + 2 * hour)
        val runtime = runtime(source(Seed()), server)
        runtime.startSeed(soleSeed = false, nowMillis = now)
        val end = runtime.startTaskWithSync(loadSeed = true) { now }
        val first = assertNotNull(end.firstSync)
        assertEquals(SyncOutcome.INSTALLED, first.outcome)
        assertEquals(mapOf(Dataset.CRLITE to "${server.ts}/${delta.id}"), first.installed)
        assertEquals(now, first.atMillis)
        assertEquals(source.sourceId, first.sourceId)
        assertNull(end.notRun)
        assertNull(end.fatal)
        assertEquals(now + 6 * hour + jitters[0], end.nextAtMillis)
        // The next sync, at the time the schedule returned: a 304, UNCHANGED, and the next poll from it.
        val at = checkNotNull(end.nextAtMillis)
        val step = runtime.syncStep(at)
        assertEquals(SyncOutcome.UNCHANGED, step.result.outcome)
        assertNull(step.result.failure)
        assertEquals(at + 6 * hour + jitters[1], step.nextAtMillis)
        assertNull(step.fatal)
    }

    @Test
    fun `a throw after the sync ended keeps its result, and the next sync is in 15 min`() {
        val now = ts - 25 * hour
        val server = Server(ts = ts + 2 * hour)
        // The jitter draw, after the install was logged and the gate opened: the schedule step throws.
        val jitter = IllegalStateException("random")
        val throwing =
            object : Random() {
                override fun nextBits(bitCount: Int): Int = throw jitter
            }
        val runtime = runtime(source(Seed()), server, random = throwing)
        runtime.startSeed(soleSeed = false, nowMillis = now)
        val end = runtime.startTaskWithSync(loadSeed = true) { now }
        val first = assertNotNull(end.firstSync)
        assertEquals(SyncOutcome.INSTALLED, first.outcome, "the sync's own result, not INTERNAL_ERROR")
        assertNull(first.cause)
        assertEquals("${server.ts}/${delta.id}", runtime.crlite().generationId)
        assertEquals(now + 15 * minute, end.nextAtMillis)
        assertNull(end.fatal)
        assertTrue(recording.messages.any { it.first == LogLevel.ERROR && it.second == "the sync threw" })
    }

    @Test
    fun `with no fetching source a sync is UNCHANGED, fetches nothing and schedules nothing`() {
        val server = Server()
        val runtime =
            CrliteRuntime(
                seed = null,
                channel = CrliteChannel.COMPAT,
                crlite = false,
                fetchingSource = false,
                engine = TestEngine(),
                verifier = verifier,
                policy = RevoktPolicy.DEFAULT,
                pinnedRootSpkis = pinned,
                storage = storage,
                logger = logger,
            )
        val end = runtime.startTaskWithSync(loadSeed = false) { ts }
        assertNull(end.firstSync)
        assertNull(end.notRun, "nothing polls, so no first sync was due")
        val step = runtime.syncStep(ts + hour)
        assertEquals(SyncOutcome.UNCHANGED, step.result.outcome)
        assertEquals(ts + hour, step.result.atMillis)
        assertNull(step.result.sourceId)
        assertNull(step.nextAtMillis)
        assertTrue(server.fetcher.requests.isEmpty())
        assertFailsWith<IllegalStateException> { runtime.sync(ts + hour) }
    }

    @Test
    fun `an unresolved store read fails a sync with STORE_FAILED, and a fatal re-read with INTERNAL_ERROR`() {
        installedAt(ts)
        reset(keepStore = true)
        storage.failRead = { name -> if (name == pointerKey) IOException("the generation read") else null }
        val server = Server(ts = ts + 30 * minute)
        val runtime = runtime(null, server)
        val now = ts + hour
        val end = runtime.startTaskWithSync(loadSeed = false) { now }
        val first = assertNotNull(end.firstSync)
        assertEquals(SyncOutcome.FAILED, first.outcome)
        assertEquals(SyncFailure.STORE_FAILED, first.failure)
        assertEquals(now + 15 * minute, end.nextAtMillis)
        assertTrue(server.fetcher.requests.isEmpty(), "nothing fetched")
        // A fatal error from the re-read: the result says INTERNAL_ERROR with it as the cause, and it is returned.
        val oom = OutOfMemoryError("the generation read")
        storage.failRead = { name -> if (name == pointerKey) oom else null }
        val step = runtime.syncStep(now + hour)
        assertEquals(SyncOutcome.FAILED, step.result.outcome)
        assertEquals(SyncFailure.INTERNAL_ERROR, step.result.failure)
        assertSame(oom, step.result.cause)
        assertSame(oom, step.fatal)
        assertEquals(now + hour + 15 * minute, step.nextAtMillis)
        assertSame(oom, assertFailsWith<OutOfMemoryError> { runtime.sync(now + 2 * hour) })
    }

    @Test
    fun `a sync called during the unresolved re-read's wait re-reads at once`() {
        installedAt(ts)
        reset(keepStore = true)
        var pointerReads = 0
        storage.failRead = { name ->
            if (name == pointerKey) {
                pointerReads++
                IOException("the generation read")
            } else {
                null
            }
        }
        val server = Server(ts = ts + 30 * minute)
        val runtime = runtime(null, server)
        val now = ts + hour
        // The start task's read, then its first sync's re-read, which waits 15 min.
        assertEquals(now + 15 * minute, runtime.startTaskWithSync(loadSeed = false) { now }.nextAtMillis)
        val reads = pointerReads
        // A sync() 1 min into that wait: the caller asked, so it re-reads now, and the next wait doubles from it.
        val step = runtime.syncStep(now + minute)
        assertEquals(reads + 1, pointerReads, "re-read at once")
        assertEquals(SyncFailure.STORE_FAILED, step.result.failure)
        assertEquals(now + minute + 30 * minute, step.nextAtMillis)
        assertTrue(server.fetcher.requests.isEmpty())
    }

    @Test
    fun `a start task whose store step throws a fatal error runs no first sync and says why`() {
        installedAt(ts)
        reset(keepStore = true)
        val oom = OutOfMemoryError("the generation read")
        storage.failRead = { name -> if (name == pointerKey) oom else null }
        val server = Server(ts = ts + 30 * minute)
        val runtime = runtime(null, server)
        val end = runtime.startTaskWithSync(loadSeed = false) { ts + hour }
        assertNull(end.firstSync)
        assertSame(oom, end.notRun)
        assertSame(oom, end.fatal)
        assertNull(end.nextAtMillis, "the binding retries in 15 min")
        assertTrue(server.fetcher.requests.isEmpty())
        assertFalse(runtime.crlite().pending)
    }

    @Test
    fun `a start task whose clock throws before the first sync says why no result came`() {
        val server = Server()
        val runtime = runtime(seed = null, server = server)
        val clock = IllegalStateException("clock")
        val end = runtime.startTaskWithSync(loadSeed = false) { throw clock }
        assertNull(end.firstSync)
        assertSame(clock, end.notRun)
        assertNull(end.fatal)
        assertNull(end.nextAtMillis)
    }
}
