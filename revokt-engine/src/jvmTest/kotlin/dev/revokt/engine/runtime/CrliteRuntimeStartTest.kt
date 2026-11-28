// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.LogLevel
import dev.revokt.RevoktPolicy
import dev.revokt.SeedSource
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.seed.SeedFixture
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.stored
import okio.ByteString.Companion.toByteString
import java.io.IOException
import java.io.InterruptedIOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The start task's recovery chain over the content-addressed store (spec §5.1 "one loader task", §6.5 crash recovery,
 * #287 slice 4): `live` → `previous` → seed → nothing, deciding on each candidate's `<ts>` first and loading in full only
 * the winner, and the sole-seed `ENFORCE` check that reads one small file on the calling thread.
 */
internal class CrliteRuntimeStartTest : SeedFixture() {
    private fun source(seed: Seed): SeedSource {
        val bytes = seed.bytes()
        return Counted { bytes }.source
    }

    private fun runtime(
        seed: SeedSource?,
        engine: TestEngine = TestEngine(),
        fetchingSource: Boolean = false,
        policy: RevoktPolicy = RevoktPolicy.DEFAULT,
    ): CrliteRuntime =
        CrliteRuntime(
            seed = seed,
            channel = CrliteChannel.COMPAT,
            crlite = true,
            fetchingSource = fetchingSource,
            engine = engine,
            verifier = verifier,
            policy = policy,
            pinnedRootSpkis = pinned,
            storage = storage,
            logger = logger,
        )

    private fun CrliteRuntime.crlite(): DatasetGeneration = assertNotNull(snapshot.snapshot.datasets[Dataset.CRLITE])

    private val now = ts + 2 * hour

    private val minute = 60_000L

    /** A delta no other generation names, so its blob rots alone ([rotExtra]). */
    private val extra =
        Rec(
            "d2",
            true,
            delta.effectiveTimestamp + 1,
            "d2.filter.delta",
            UpdateFixtures.v4(listOf(UpdateFixtures.log(2) to (1L to 2L))),
            parent = full.id,
        )

    /** A stored seed generation at [at] that names [extra]: Load's steps 1 and 2 pass, and step 3 fails once rotted. */
    private fun withExtra(at: Long): String = installed(load(Seed(records = listOf(full, delta, extra), ts = at))).name

    private fun rotExtra() = storage.inner.write(store.blobKey(extra.body.toByteString().sha256()), byteArrayOf(1))

    /** The `<ts>` of the seed's generation, `"<ts>/<last placed record id>"`. */
    private fun seedId(at: Long = ts) = "$at/${delta.id}"

    private fun counted(): List<String> = recording.messages.map { it.second }.filter { "the start task counted" in it }

    private fun watermark(): Long? = updater(now).watermarkMillis

    private fun start(
        runtime: CrliteRuntime,
        soleSeed: Boolean = false,
    ) {
        val load = runtime.startSeed(soleSeed, now)
        runtime.startTask(load) { now }
    }

    @Test
    fun `a trustworthy live not older than the seed is loaded, and the seed is never decoded`() {
        val name = installedAt(ts)
        reset(keepStore = true)
        val before = contents()
        val engine = TestEngine()
        val runtime = runtime(source(Seed(ts = ts - hour)), engine)
        start(runtime)
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared)
        assertEquals(name, runtime.crlite().generationFile)
        assertEquals(before, contents(), "nothing written")
        assertFalse(runtime.storeReadUnresolved)
    }

    @Test
    fun `a stored seed generation reloads fromSeed with its seedFormat`() {
        installedAt(ts)
        reset(keepStore = true)
        val runtime = runtime(null)
        start(runtime)
        assertTrue(runtime.crlite().fromSeed)
        assertEquals(1, runtime.crlite().seedFormat)
        assertTrue(runtime.crlite().staleGateOpen, "with no fetching source the gate is open")
    }

    @Test
    fun `a live that does not load falls to previous, which is served when newer than the seed`() {
        val previous = installedAt(ts)
        // The live one names a blob the previous does not, which is then rotted: it fails Load's step 3.
        val live = withExtra(ts + hour)
        rotExtra()
        reset(keepStore = true)
        val pointer = store.pointer()
        val engine = TestEngine()
        val runtime = runtime(source(Seed(ts = ts - hour)), engine)
        start(runtime)
        assertEquals(previous, runtime.crlite().generationFile)
        assertEquals("$ts/${delta.id}", runtime.crlite().generationId)
        // Served once, and kept: no second seed pass re-adopts it, so current is not rewritten at start.
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared)
        assertEquals(pointer, store.pointer())
        assertTrue(live in store.generationNames(), "the unloadable live is never deleted")
        assertFalse(runtime.storeReadUnresolved)
    }

    @Test
    fun `a trusted live that passes steps 1 and 2 but fails step 3, with no previous, falls to the seed`() {
        val live = withExtra(ts + hour)
        rotExtra()
        reset(keepStore = true)
        recording.messages.clear()
        val runtime = runtime(source(Seed(ts = ts - hour)))
        start(runtime)
        // Rule (a) skipped the seed on Load's steps 1 and 2; the chain's full load failed, so the seed installs.
        assertTrue(runtime.crlite().fromSeed)
        assertEquals(ts - hour, runtime.crlite().sourceTimestampMillis)
        assertTrue(live in store.generationNames(), "the unloadable live is never deleted")
        assertFalse(runtime.storeReadUnresolved)
        // As coded: the watermark is lowered to the seed's ts (the residual in #336's Risk section).
        assertEquals(ts - hour, watermark())
        assertEquals(listOf("the start task counted 1 store failures"), counted(), "the rotted live, once")
    }

    @Test
    fun `a previous older than the seed is never decoded, and the seed installs over a live that fails step 3`() {
        val previous = installedAt(ts - hour)
        val live = withExtra(ts + hour)
        assertEquals(Pointer(live, previous), (store.pointer() as StoreRead.Found).value)
        rotExtra()
        reset(keepStore = true)
        val engine = TestEngine()
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertEquals(listOf(seedId()), engine.prepared, "only the seed is decoded")
        assertEquals(1, runtime.snapshot.snapshot.generationEpoch)
        assertTrue(runtime.crlite().fromSeed)
        assertTrue(store.generationNames().containsAll(listOf(live, previous)))
    }

    @Test
    fun `an intact live the engine refuses once falls to the seed, its watermark lowered and the live kept`() {
        val live = installedAt(ts + hour)
        assertEquals(ts + hour, watermark())
        reset(keepStore = true)
        var refused = false
        val engine = TestEngine()
        engine.onPrepare = {
            if (!refused) {
                refused = true
                error("refused")
            }
        }
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertTrue(runtime.crlite().fromSeed)
        // As coded and as Firefox imports a dump: the live passed over, the seed's install sets the watermark to its ts.
        assertEquals(ts, watermark())
        val seed = assertNotNull(runtime.crlite().generationFile)
        assertEquals(Pointer(seed, live), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `nine newer stored generations the engine refuses are each tried once, then the seed installs`() {
        val names = (1..9).map { installedAt(ts + it * hour) }
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val engine = TestEngine()
        engine.onPrepare = { check(it.generationId == seedId()) { "refused" } }
        recording.messages.clear()
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertEquals(10, engine.prepared.size)
        assertEquals(seedId(), engine.prepared.last())
        assertTrue(runtime.crlite().fromSeed)
        assertFalse(runtime.storeReadUnresolved)
        assertTrue(store.generationNames().containsAll(names))
        assertEquals(listOf("the start task counted 9 store failures"), counted())
    }

    @Test
    fun `S9 - after the previous fallback a newer unpointed generation that loads is still adopted`() {
        val previous = installedAt(ts + hour)
        // Newer than the previous, named by no pointer once current names live and previous, and it loads.
        val newer = installedAt(ts + 90 * minute)
        val live = withExtra(ts + 2 * hour)
        store.point(Pointer(live, previous))
        rotExtra()
        reset(keepStore = true)
        val engine = TestEngine()
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertEquals(newer, runtime.crlite().generationFile, "rule (b) adopts the newest that loads")
        // The chain serves the previous first (live -> previous), then the seed's second pass adopts the newer one.
        assertEquals(listOf(seedId(ts + hour), seedId(ts + 90 * minute)), engine.prepared)
        assertEquals(1, runtime.startStoreFailures, "the rotted live")
    }

    @Test
    fun `a previous at exactly the seed's ts is kept as served after the live fails, decoded once`() {
        val previous = installedAt(ts)
        val live = withExtra(ts + hour)
        assertEquals(Pointer(live, previous), (store.pointer() as StoreRead.Found).value)
        rotExtra()
        reset(keepStore = true)
        val pointer = store.pointer()
        val engine = TestEngine()
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertEquals(previous, runtime.crlite().generationFile)
        // Not older than the seed, so kept, as rule (a) keeps it: the seed does not install over it.
        assertEquals(1, engine.prepared.size)
        assertEquals(1, runtime.snapshot.snapshot.generationEpoch)
        assertEquals(pointer, store.pointer())
    }

    @Test
    fun `S10 - a malformed pointer and an adopted generation the engine refuses are two store failures`() {
        val adoptee = installedAt(ts + hour)
        storage.inner.write(pointerKey, "{".encodeToByteArray())
        reset(keepStore = true)
        val engine = TestEngine()
        engine.onPrepare = { check(it.generationId == seedId()) { "refused" } }
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertTrue(runtime.crlite().fromSeed)
        // The adopt healed the pointer before the second pass: its fault counts from the first pass.
        assertEquals(2, runtime.startStoreFailures)
        assertTrue(adoptee in store.generationNames())
    }

    @Test
    fun `S12 - a rotted blob the seed also ships is one store failure, not one more for its rewrite`() {
        val live = installedAt(ts + hour)
        // The live's delta, which the seed ships too: the chain fails the live at step 3, the seed's install rewrites it.
        storage.inner.write(store.blobKey(delta.body.toByteString().sha256()), byteArrayOf(1))
        reset(keepStore = true)
        val runtime = runtime(source(Seed()))
        start(runtime)
        assertTrue(runtime.crlite().fromSeed)
        assertContentEquals(delta.body, storage.inner.read(store.blobKey(delta.body.toByteString().sha256())))
        assertEquals(1, runtime.startStoreFailures)
        assertTrue(live in store.generationNames())
    }

    @Test
    fun `a pointed previous failing steps 1 and 2 beside a live that fails is counted once, by the seed read`() {
        val previous = installedAt(ts + hour)
        val live = withExtra(ts + 2 * hour)
        assertEquals(Pointer(live, previous), (store.pointer() as StoreRead.Found).value)
        val key = store.generationKey(previous)
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).let { it.copyOf(it.size - 1) })
        rotExtra()
        reset(keepStore = true)
        val runtime = runtime(source(Seed()))
        start(runtime)
        assertTrue(runtime.crlite().fromSeed)
        // The seed's read counts the previous; the chain then fails both, and counts only the live.
        assertEquals(2, runtime.startStoreFailures)
    }

    @Test
    fun `a fault every pass reads again is counted once across the start's passes`() {
        installedAt(ts + hour)
        // A generation file that fails Load's step 1: each pass's adopt scan reads it again.
        val damaged = installedAt(ts + 2 * hour)
        val key = store.generationKey(damaged)
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).let { it.copyOf(it.size - 1) })
        storage.inner.write(pointerKey, "{".encodeToByteArray())
        reset(keepStore = true)
        val engine = TestEngine()
        engine.onPrepare = { check(it.generationId == seedId()) { "refused" } }
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertTrue(runtime.crlite().fromSeed)
        // The malformed pointer, the damaged file, and the adopted generation the engine refused: once each.
        assertEquals(3, runtime.startStoreFailures)
    }

    @Test
    fun `a stored seed's STALE gate with a fetching source opens only once an attempt follows its install`() {
        installedAt(ts)
        val installed = assertNotNull(updater(now).seedInstalledAtMillis)
        reset(keepStore = true)
        val closed = runtime(null, fetchingSource = true)
        start(closed)
        assertFalse(closed.crlite().staleGateOpen, "no attempt since the seed's install")
        store.writeUpdater(updater(now).copy(datasetLastAttemptAtMillis = installed), now)
        reset(keepStore = true)
        val open = runtime(null, fetchingSource = true)
        start(open)
        assertTrue(open.crlite().staleGateOpen, "an attempt at the install's own time")
    }

    @Test
    fun `the sole-seed check beside a pointer whose live does not read decodes the seed, and a bad one throws`() {
        val name = installedAt(ts)
        storage.inner.delete(store.generationKey(name))
        reset(keepStore = true)
        val runtime = runtime(source(Seed().apply { signature = "not base64url!" }))
        assertFailsWith<IllegalStateException> { runtime.startSeed(soleSeed = true, now) }
    }

    @Test
    fun `a seed that does not verify beside a readable store leaves the store served`() {
        val name = installedAt(ts - hour)
        reset(keepStore = true)
        val runtime = runtime(source(Seed().apply { signature = "not base64url!" }))
        start(runtime)
        assertEquals(name, runtime.crlite().generationFile)
        assertEquals(ts - hour, runtime.crlite().sourceTimestampMillis)
    }

    @Test
    fun `when live and previous both fail to load, the seed installs and nothing is deleted`() {
        val previous = installedAt(ts - hour)
        val live = installedAt(ts)
        for (n in listOf(previous, live)) storage.inner.write(store.generationKey(n), "{}".encodeToByteArray())
        reset(keepStore = true)
        val before = storage.inner.names()
        val runtime = runtime(source(Seed(ts = ts - 2 * hour)))
        start(runtime)
        assertTrue(runtime.crlite().fromSeed)
        assertEquals(ts - 2 * hour, runtime.crlite().sourceTimestampMillis)
        assertTrue(storage.inner.names().containsAll(before), "no seed load deletes")
    }

    @Test
    fun `a stored live older than the seed is not decoded at start, and the seed installs over it`() {
        val older = installedAt(ts - hour)
        reset(keepStore = true)
        val engine = TestEngine()
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared, "only the seed is decoded")
        assertEquals(Pointer(runtime.crlite().generationFile!!, older), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `with no seed the chain is the pointer's live, then its previous, then nothing`() {
        val previous = installedAt(ts - hour)
        val live = installedAt(ts)
        reset(keepStore = true)
        storage.inner.write(store.generationKey(live), "{}".encodeToByteArray())
        val runtime = runtime(null)
        start(runtime)
        assertEquals(previous, runtime.crlite().generationFile)
        reset(keepStore = true)
        storage.inner.write(store.generationKey(previous), "{}".encodeToByteArray())
        val none = runtime(null)
        start(none)
        assertEquals(null, none.crlite().generationId)
        assertFalse(none.crlite().pending)
        assertFalse(none.storeReadUnresolved)
    }

    @Test
    fun `beside no trustworthy pointer a newer stored generation is adopted, then loaded`() {
        val newer = installedAt(ts + hour)
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val engine = TestEngine()
        val runtime = runtime(source(Seed()), engine)
        start(runtime)
        assertEquals(newer, runtime.crlite().generationFile)
        assertEquals(listOf("${ts + hour}/${delta.id}"), engine.prepared)
        assertEquals(Pointer(newer, null), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `a current with a flipped hex digit at start warns nothing of an unreadable store, and the start heals it`() {
        val own = installedAt(ts)
        flipLiveHex(own)
        reset(keepStore = true)
        recording.messages.clear()
        val runtime = runtime(source(Seed()))
        start(runtime)
        assertEquals(own, runtime.crlite().generationFile)
        assertEquals(Pointer(own, null), (store.pointer() as StoreRead.Found).value, "healed")
        assertFalse(runtime.storeReadUnresolved)
        // spec §5.1: a damaged pointer is a counted store failure only; STORE_UNREADABLE means the in-memory fallback.
        assertEquals(emptyList(), recording.messages.filter { "STORE_UNREADABLE" in it.second || "SEED_" in it.second })
    }

    @Test
    fun `a restart serving a stored seed generation past rejectStaleAfter reports SEED_PAST_REJECT_THRESHOLD`() {
        val stored = installedAt(ts)
        val installedAt = updater(now).seedInstalledAtMillis
        val past = ts + 31 * 24 * hour
        for (seed in listOf(null, source(Seed()))) {
            reset(keepStore = true)
            recording.messages.clear()
            val engine = TestEngine()
            val runtime = runtime(seed, engine, policy = RevoktPolicy.STRICT)
            runtime.startTask(runtime.startSeed(soleSeed = false, nowMillis = past)) { past }
            // The stored seed generation is served, not the seed re-installed: a restart is a first start (spec §4).
            assertEquals(listOf(seedId()), engine.prepared)
            assertEquals(stored, runtime.crlite().generationFile)
            assertEquals(installedAt, updater(now).seedInstalledAtMillis, "the seed did not install again")
            assertTrue(runtime.crlite().fromSeed)
            val fired = runtime.diagnostics(past).single { it.code == DiagnosticCode.SEED_PAST_REJECT_THRESHOLD }
            assertEquals(Dataset.CRLITE, fired.dataset)
            assertTrue(
                recording.messages.any { (level, m) -> level == LogLevel.WARN && "SEED_PAST_REJECT_THRESHOLD" in m },
                "logged, since the start task may end after start() returned: ${recording.messages}",
            )
            assertEquals(
                emptyList(),
                runtime.diagnostics(ts + hour).filter { it.code == DiagnosticCode.SEED_PAST_REJECT_THRESHOLD },
                "measured from the stored generation's signed ts",
            )
        }
    }

    @Test
    fun `a restart reports SEED_PAST_REJECT_THRESHOLD from a stored seed generation the chain reaches as previous`() {
        val previous = installedAt(ts)
        withExtra(ts + hour)
        rotExtra()
        reset(keepStore = true)
        val past = ts + 31 * 24 * hour
        val runtime = runtime(null, policy = RevoktPolicy.STRICT)
        runtime.startTask(false) { past }
        assertEquals(previous, runtime.crlite().generationFile)
        assertEquals(1, runtime.diagnostics(past).count { it.code == DiagnosticCode.SEED_PAST_REJECT_THRESHOLD })
    }

    @Test
    fun `a restart reports SEED_PAST_REJECT_THRESHOLD from an adopted stored seed generation, at its own ts`() {
        val newer = installedAt(ts + hour)
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val past = ts + 31 * 24 * hour
        val runtime = runtime(source(Seed()), policy = RevoktPolicy.STRICT)
        runtime.startTask(runtime.startSeed(soleSeed = false, nowMillis = past)) { past }
        assertEquals(newer, runtime.crlite().generationFile, "adopted under rule (b)")
        val code = DiagnosticCode.SEED_PAST_REJECT_THRESHOLD
        assertEquals(1, runtime.diagnostics(past).count { it.code == code })
        // 30 d and 30 min after the seed's ts, but under 30 d after the adopted generation's.
        assertEquals(0, runtime.diagnostics(ts + 30 * 24 * hour + 30 * minute).count { it.code == code })
    }

    @Test
    fun `a sole-seed start whose live fails step 3 beside a seed that does not verify logs SEED_UNREADABLE`() {
        val live = withExtra(ts + hour)
        rotExtra()
        reset(keepStore = true)
        recording.messages.clear()
        val engine = TestEngine()
        val runtime = runtime(source(Seed().apply { signature = "not base64url!" }), engine)
        // Load's steps 1 and 2 pass on the calling thread, so start() does not throw (B5) ...
        assertTrue(runtime.startSeed(soleSeed = true, nowMillis = now), "the start task still has work")
        runtime.startTask(true) { now }
        // ... and the start task ends with nothing served, which is said loudly, once.
        assertEquals(null, runtime.crlite().generationId)
        assertFalse(runtime.crlite().pending)
        assertEquals(emptyList(), engine.prepared)
        val errors = recording.messages.filter { it.first == LogLevel.ERROR }.map { it.second }
        assertEquals(1, errors.count { "SEED_UNREADABLE" in it && "NO_DATA" in it }, "$errors")
        assertTrue(live in store.generationNames(), "nothing deleted")
        // Outside the sole-seed configuration the same start logs no ERROR.
        reset(keepStore = true)
        recording.messages.clear()
        val other = runtime(source(Seed().apply { signature = "not base64url!" }))
        start(other)
        assertEquals(null, other.crlite().generationId)
        assertEquals(emptyList(), recording.messages.filter { it.first == LogLevel.ERROR })
    }

    @Test
    fun `a sole-seed start whose store read throws on the loader logs SEED_UNREADABLE, unless it is interrupted`() {
        installedAt(ts)
        for (interrupted in listOf(false, true)) {
            reset(keepStore = true)
            recording.messages.clear()
            var reads = 0
            // The calling thread's check reads the pointer; the loader's reads throw.
            storage.failRead = { name ->
                if (name != pointerKey || reads++ == 0) {
                    null
                } else if (interrupted) {
                    Thread.currentThread().interrupt()
                    InterruptedIOException("close() stops the loader")
                } else {
                    IOException("the pointer read")
                }
            }
            val runtime = runtime(source(Seed(ts = ts - hour)))
            try {
                assertTrue(runtime.startSeed(soleSeed = true, nowMillis = now))
                runtime.startTask(true) { now }
            } finally {
                Thread.interrupted()
            }
            assertTrue(runtime.storeReadUnresolved)
            assertEquals(null, runtime.crlite().generationId)
            val errors = recording.messages.filter { it.first == LogLevel.ERROR && "SEED_UNREADABLE" in it.second }
            assertEquals(if (interrupted) 0 else 1, errors.size, "interrupted=$interrupted: ${recording.messages}")
        }
    }

    @Test
    fun `a sole-seed start that serves its stored live logs no SEED_UNREADABLE`() {
        installedAt(ts)
        reset(keepStore = true)
        recording.messages.clear()
        val runtime = runtime(source(Seed(ts = ts - hour)))
        assertTrue(runtime.startSeed(soleSeed = true, nowMillis = now))
        runtime.startTask(true) { now }
        assertEquals(seedId(), runtime.crlite().generationId)
        assertEquals(emptyList(), recording.messages.filter { it.first == LogLevel.ERROR })
    }

    @Test
    fun `the sole-seed check finds a stored live on the calling thread, so the seed is not decoded there`() {
        installedAt(ts)
        reset(keepStore = true)
        val engine = TestEngine()
        val runtime = runtime(source(Seed(ts = ts - hour)), engine)
        assertTrue(runtime.startSeed(soleSeed = true, nowMillis = now), "the start task still has work")
        assertEquals(emptyList(), engine.prepared, "nothing decoded on the calling thread")
        runtime.startTask(true) { now }
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared)
    }

    @Test
    fun `the sole-seed check with no stored live decodes the seed on the calling thread`() {
        val engine = TestEngine()
        val runtime = runtime(source(Seed()), engine)
        assertFalse(runtime.startSeed(soleSeed = true, nowMillis = now))
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared)
        runtime.startTask(false) { now }
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared, "the start task loads nothing more")
    }
}
