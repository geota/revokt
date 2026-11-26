// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
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
import kotlin.test.Test
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
    ): CrliteRuntime =
        CrliteRuntime(
            seed = seed,
            channel = CrliteChannel.COMPAT,
            crlite = true,
            fetchingSource = fetchingSource,
            engine = engine,
            verifier = verifier,
            policy = RevoktPolicy.DEFAULT,
            pinnedRootSpkis = pinned,
            storage = storage,
            logger = logger,
        )

    private fun CrliteRuntime.crlite(): DatasetGeneration = assertNotNull(snapshot.snapshot.datasets[Dataset.CRLITE])

    private val now = ts + 2 * hour

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
