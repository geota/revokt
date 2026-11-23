// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class, dev.revokt.RevoktTestingApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.EvaluationRequest
import dev.revokt.EvaluatorRig
import dev.revokt.LogLevel
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLifecycle
import dev.revokt.RevoktPolicy
import dev.revokt.SeedSource
import dev.revokt.engine.fetch.client
import dev.revokt.engine.fetch.response
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.seed.SeedFixture
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.PollSchedule
import dev.revokt.engine.update.UpdateFixtures
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.walker.FixtureCert
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.WalkerHarness
import java.io.IOException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * #147's acceptance test on the data side: the loader's start task runs the seed and then the first sync (spec §5.1
 * "the seed then the first sync"), each scheduled sync returns when the next one runs ([PollSchedule], spec §7.1), the
 * store read the start task left unresolved is re-read before any sync (the #273 review moved from #143), the seed's
 * `STALE` gate opens after the first attempt (§8), and the §9 content-signature sequence runs through the schedule with
 * no rule on the local clock (#273). The loader thread, the timer and `close()` are `RevoktPollTest`'s (revokt-jsse).
 */
internal class CrliteRuntimePollTest : SeedFixture() {
    private val minute = 60_000L
    private val seedRandom = 7

    private fun source(seed: Seed): SeedSource {
        val bytes = seed.bytes()
        return Counted { bytes }.source
    }

    private fun runtime(
        seed: SeedSource?,
        server: Server,
        engine: RevocationEngine = TestEngine(),
    ): CrliteRuntime =
        CrliteRuntime(
            seed = seed,
            channel = CrliteChannel.COMPAT,
            crlite = true,
            fetchingSource = true,
            engine = engine,
            verifier = verifier,
            policy = RevoktPolicy.DEFAULT,
            pinnedRootSpkis = pinned,
            collection = collection,
            storage = storage,
            logger = logger,
            client = client(server.fetcher, source),
            random = Random(seedRandom),
        )

    private fun CrliteRuntime.crlite(): DatasetGeneration = assertNotNull(snapshot.snapshot.datasets[Dataset.CRLITE])

    private fun CrliteRuntime.epoch(): Long = snapshot.snapshot.generationEpoch

    /** The jitter the runtime draws, in order, from its fixed random source. */
    private val jitters = Random(seedRandom).let { r -> List(4) { PollSchedule.jitterMillis(r) } }

    private fun warnings(): List<String> = recording.messages.filter { it.first == LogLevel.WARN }.map { it.second }

    @Test
    fun `the start task installs the seed then the first sync's newer generation, which the next evaluation sees`() {
        val h = Honest()
        val indexed = EvaluatorRig.indexed(listOf(h.root.der), WalkerHarness.SNAPSHOT_ID)
        val engine =
            object : RevocationEngine by TestEngine() {
                override fun query(q: CrliteQuery): CrliteQueryResult = CrliteQueryResult.NOT_REVOKED
            }
        val server = Server(ts = ts + 2 * hour)
        val runtime = runtime(source(Seed()), server, engine)
        val now = ts + 3 * hour
        assertTrue(runtime.startSeed(soleSeed = false, nowMillis = now))
        assertTrue(runtime.crlite().pending)
        val next = runtime.startTask(loadSeed = true) { now }
        // The seed's install (epoch 1), then the first sync's (epoch 2); pending already cleared by the installs.
        assertEquals(2, runtime.epoch())
        assertEquals("${server.ts}/${delta.id}", runtime.crlite().generationId)
        assertFalse(runtime.crlite().fromSeed)
        assertFalse(runtime.crlite().pending)
        val evaluator = runtime.evaluator({ RevoktLifecycle.STARTED }, { indexed }, null) { now }
        val verdict = evaluator.evaluate(EvaluationRequest.Builder().verifiedPath(h.path.map(FixtureCert::der)).build())
        assertEquals("${server.ts}/${delta.id}", assertNotNull(verdict.dataStates[Dataset.CRLITE]).generationId)
        // The next poll: no sooner than 6 h after the first, by the jitter of the runtime's fixed random source.
        assertEquals(now + 6 * hour + jitters[0], next)
        assertTrue(next!! >= now + 6 * hour)
    }

    @Test
    fun `with no fetching source the start task syncs nothing and returns no next poll`() {
        val server = Server()
        val runtime =
            CrliteRuntime(
                seed = source(Seed()),
                channel = CrliteChannel.COMPAT,
                crlite = true,
                fetchingSource = false,
                engine = TestEngine(),
                verifier = verifier,
                policy = RevoktPolicy.DEFAULT,
                pinnedRootSpkis = pinned,
                collection = collection,
                storage = storage,
                logger = logger,
            )
        assertFalse(runtime.polls)
        runtime.startSeed(soleSeed = false, nowMillis = ts + hour)
        assertNull(runtime.startTask(loadSeed = true) { ts + hour })
        assertTrue(server.fetcher.requests.isEmpty())
    }

    @Test
    fun `with no seed pending holds through the first sync, and clears once it ends`() {
        val server = Server()
        server.overrides[monitor] = { _ -> response(503) }
        val runtime = runtime(seed = null, server = server)
        assertTrue(runtime.crlite().pending)
        val now = ts + hour
        val next = runtime.startTask(loadSeed = false) { now }
        assertFalse(runtime.crlite().pending)
        assertNull(runtime.crlite().generationId)
        assertEquals(1, runtime.epoch())
        assertEquals(now + 15 * minute, next, "the first feed failure's backoff")
    }

    @Test
    fun `content-signature sequence through the schedule - ahead installs, then a 304, then the next ts`() {
        // A seed 25 h ahead of local now, and a changeset 2 h ahead of the seed: no rule reads the local clock (#273).
        val now = ts - 25 * hour
        val server = Server(ts = ts + 2 * hour)
        val runtime = runtime(source(Seed()), server)
        runtime.startSeed(soleSeed = false, nowMillis = now)
        val first = runtime.startTask(loadSeed = true) { now }
        assertEquals("${server.ts}/${delta.id}", runtime.crlite().generationId)
        val record = updater(now)
        assertEquals(server.ts, record.watermarkMillis)
        val s = record.sources.getValue(source.sourceId)
        assertEquals(server.ts, s.lastVerifiedLastModified)
        assertEquals(now, s.lastVerifiedAtMillis)
        assertEquals(listOf(), warnings(), "no warning: neither the seed nor the changeset is a clock fault")
        // The next poll, 6 h and the jitter later: the cursor is sent and the server answers 304, UNCHANGED.
        val second = checkNotNull(first)
        assertEquals(now + 6 * hour + jitters[0], second)
        server.fetcher.requests.clear()
        val epoch = runtime.epoch()
        val third = runtime.sync(second)
        val conditional = server.fetcher.requests.single { "_since" in it.url }
        assertEquals(server.sinceUrl(server.ts), conditional.url)
        assertEquals("\"${server.ts}\"", conditional.headers["If-None-Match"])
        assertEquals(epoch, runtime.epoch(), "UNCHANGED installs nothing")
        assertEquals(0, sourceRecord(second).consecutiveFailures)
        assertEquals(second + 6 * hour + jitters[1], third)
        // 30 h on, the next server <ts> installs normally and raises the watermark.
        val later = second + 30 * hour
        val delta2 =
            Rec(
                "e7d1f0a2-0000-4000-8000-000000000002",
                true,
                ts + 3 * hour,
                "20261022-1-compat.filter.delta",
                UpdateFixtures.v4(listOf(UpdateFixtures.log(2) to (1_000L to 2_000L))),
                parent = full.id,
            )
        server.ts += 2 * hour
        server.records = listOf(full, delta, delta2).map { it.json() }
        server.bodies = listOf(full, delta, delta2).associate { it.location to it.body }
        runtime.sync(later)
        assertEquals("${server.ts}/${delta2.id}", runtime.crlite().generationId)
        assertEquals(server.ts, updater(later).watermarkMillis)
        assertEquals(listOf(), warnings())
    }

    @Test
    fun `an unresolved store read is re-read by the first sync, which is refused below the watermark`() {
        // The store: a generation at ts, pointed and live in an earlier process, and a watermark raised to ts + 50 min.
        installedAt(ts)
        val stored = updater()
        store.writeUpdater(stored.copy(watermarkMillis = ts + 50 * minute), ts + hour)
        reset(keepStore = true)
        // The seed at ts + 20 min, newer than the stored generation; a changeset at ts + 30 min, below the watermark.
        val server = Server(ts = ts + 30 * minute)
        var pointerReads = 0
        storage.failRead = { name ->
            if (name == pointerKey && pointerReads++ == 0) IOException("the first generation read") else null
        }
        val runtime = runtime(source(Seed(ts = ts + 20 * minute)), server)
        val now = ts + hour
        runtime.startSeed(soleSeed = false, nowMillis = now)
        runtime.startTask(loadSeed = true) { now }
        // The re-read installed the seed beside the stored generation (the watermark kept), then the sync refused.
        assertFalse(runtime.storeReadUnresolved)
        assertTrue(runtime.crlite().fromSeed)
        assertEquals(ts + 20 * minute, runtime.crlite().sourceTimestampMillis)
        assertEquals(ts + 50 * minute, updater(now).watermarkMillis)
        assertTrue(server.attachmentRequests().isEmpty(), "refused before any body")
        assertTrue(
            recording.messages.none { "installed" in it.second && it.first == LogLevel.INFO },
            "${recording.messages}",
        )
    }

    @Test
    fun `while the store read stays unresolved nothing is fetched or written and the next try is in 15 min`() {
        installedAt(ts)
        reset(keepStore = true)
        storage.failRead = { name -> if (name == pointerKey) IOException("the generation read") else null }
        val before = contents()
        val server = Server(ts = ts + 30 * minute)
        val runtime = runtime(source(Seed(ts = ts + 20 * minute)), server)
        val now = ts + hour
        runtime.startSeed(soleSeed = false, nowMillis = now)
        val next = runtime.startTask(loadSeed = true) { now }
        assertTrue(runtime.storeReadUnresolved)
        assertTrue(server.fetcher.requests.isEmpty(), "no sync runs: ${server.fetcher.requests.map { it.url }}")
        assertEquals(before, contents(), "nothing written")
        assertEquals(now + 15 * minute, next)
        assertFalse(runtime.crlite().pending)
        assertNull(runtime.crlite().generationId)
        // A later sync re-reads again, and syncs once the read resolves.
        assertEquals(now + 2 * hour + 15 * minute, runtime.sync(now + 2 * hour))
        storage.failRead = { null }
        runtime.sync(now + 3 * hour)
        assertFalse(runtime.storeReadUnresolved)
        assertTrue(server.fetcher.requests.any { it.url == monitor })
    }

    @Test
    fun `a stored generation 0_2 does not load keeps the store read unresolved, and nothing syncs`() {
        // The stored generation is newer than the seed, so the load is Skipped: nothing is live beside it in 0.2.
        installedAt(ts)
        reset(keepStore = true)
        val server = Server(ts = ts + 30 * minute)
        val runtime = runtime(source(Seed(ts = ts - hour)), server)
        val now = ts + hour
        runtime.startSeed(soleSeed = false, nowMillis = now)
        assertEquals(now + 15 * minute, runtime.startTask(loadSeed = true) { now })
        assertTrue(runtime.storeReadUnresolved)
        assertTrue(server.fetcher.requests.isEmpty())
        assertTrue(warnings().any { "unresolved" in it }, "${warnings()}")
    }

    @Test
    fun `the seed's STALE gate opens once a sync attempt completed, even a failed one`() {
        val server = Server()
        server.overrides[monitor] = { _ -> response(503) }
        val runtime = runtime(source(Seed()), server)
        val now = ts + hour
        runtime.startSeed(soleSeed = false, nowMillis = now)
        // The seed installs with the gate shut, since a fetching source is configured (§8); the sync then fails.
        runtime.startTask(loadSeed = true) { now }
        assertTrue(runtime.crlite().fromSeed)
        assertTrue(runtime.crlite().staleGateOpen, "the FAILED first sync was an attempt")
        assertEquals(2, runtime.epoch(), "the seed's install, then the gate's publish")
        val record = updater(now)
        assertTrue(checkNotNull(record.datasetLastAttemptAtMillis) >= checkNotNull(record.seedInstalledAtMillis))
    }

    @Test
    fun `a sync that wrote no updater json is no attempt, and the seed's gate stays shut`() {
        val server = Server()
        val runtime = runtime(source(Seed()), server)
        val now = ts + hour
        runtime.startSeed(soleSeed = false, nowMillis = now)
        // The seed load writes updater.json; every read of it after that throws, so the sync writes nothing.
        var written = false
        storage.failWrite = { name ->
            if (name == updaterKey) written = true
            null
        }
        storage.failRead = { name -> if (name == updaterKey && written) IOException("updater") else null }
        val next = runtime.startTask(loadSeed = true) { now }
        assertTrue(runtime.crlite().fromSeed)
        assertFalse(runtime.crlite().staleGateOpen)
        assertEquals(1, runtime.epoch())
        assertEquals(now + 15 * minute, next)
    }

    @Test
    fun `after a fallback the cursor is not sent, so the whole collection reinstalls instead of a 304`() {
        // A sync installed the server's <ts> (the cursor); then the snapshot serves an older generation, as after a
        // start that fell back to the seed or to previous while the pointer still names the cursor's generation.
        val server = Server()
        val runtime = runtime(seed = null, server = server)
        runtime.startTask(loadSeed = false) { ts + hour }
        assertEquals("$ts/${delta.id}", runtime.crlite().generationId)
        val live = runtime.crlite()
        runtime.snapshot.publish(
            GenerationSnapshot(
                runtime.epoch() + 1,
                mapOf(Dataset.CRLITE to live.copy(generationId = "older", sourceTimestampMillis = ts - hour)),
                null,
            ),
        )
        server.fetcher.requests.clear()
        runtime.sync(ts + 7 * hour)
        assertTrue(server.fetcher.requests.none { "_since" in it.url || "If-None-Match" in it.headers })
        assertTrue(server.fetcher.requests.any { it.url == server.changesetUrl })
        assertEquals("$ts/${delta.id}", runtime.crlite().generationId, "the cursor's generation is live again")
        assertEquals(ts, (store.updater(ts) as StoreRead.Found).value.record.watermarkMillis)
    }

    @Test
    fun `a sync step that throws is logged and retried in 15 min, and a fatal error is rethrown`() {
        val server = Server()
        var thrown: Throwable? = null
        val random =
            object : Random() {
                override fun nextBits(bitCount: Int): Int = throw checkNotNull(thrown)
            }
        val runtime =
            CrliteRuntime(
                seed = null,
                channel = CrliteChannel.COMPAT,
                crlite = true,
                fetchingSource = true,
                engine = TestEngine(),
                verifier = verifier,
                policy = RevoktPolicy.DEFAULT,
                pinnedRootSpkis = pinned,
                collection = collection,
                storage = storage,
                logger = logger,
                client = client(server.fetcher, source),
                random = random,
            )
        val now = ts + hour
        // The first sync installs; drawing its jitter throws: logged, swallowed, retried in 15 min.
        thrown = IllegalStateException("random")
        assertEquals(now + 15 * minute, runtime.startTask(loadSeed = false) { now })
        assertTrue(recording.messages.any { it.first == LogLevel.ERROR && "the sync threw" in it.second })
        // A fatal one is rethrown, for the loader to reschedule first; the sync itself completed (UNCHANGED).
        thrown = OutOfMemoryError("random")
        assertFailsWith<OutOfMemoryError> { runtime.sync(now + 7 * hour) }
        assertTrue(recording.messages.any { it.first == LogLevel.ERROR && "fatal error, rethrown" in it.second })
        assertEquals(now + 7 * hour, sourceRecord(now + 7 * hour).lastAttemptAtMillis)
        // A store read that throws, even fatally, is the sync's own catch: nothing written, so retried in 15 min.
        storage.failRead = { name -> if (name == updaterKey) OutOfMemoryError("updater") else null }
        assertEquals(now + 8 * hour + 15 * minute, runtime.sync(now + 8 * hour))
    }

    @Test
    fun `a clock that throws before the first sync is logged, and the start task still clears pending`() {
        val server = Server()
        val runtime = runtime(seed = null, server = server)
        var reads = 0
        val clock = {
            check(reads++ > 0) { "clock" }
            ts
        }
        assertNull(runtime.startTask(loadSeed = false, nowMillis = clock), "no next time: the loader retries in 15 min")
        assertTrue(server.fetcher.requests.isEmpty())
        assertFalse(runtime.crlite().pending)
        assertEquals(1, recording.messages.count { it.first == LogLevel.ERROR && "the clock threw" in it.second })
        // A fatal one is logged the same way, and rethrown once pending is cleared.
        val fatal = runtime(seed = null, server = Server())
        assertFailsWith<OutOfMemoryError> { fatal.startTask(loadSeed = false) { throw OutOfMemoryError("clock") } }
        assertFalse(fatal.crlite().pending)
        assertEquals(2, recording.messages.count { it.first == LogLevel.ERROR && "the clock threw" in it.second })
    }
}
