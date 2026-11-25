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
    ): CrliteRuntime =
        CrliteRuntime(
            seed = seed,
            channel = CrliteChannel.COMPAT,
            crlite = true,
            fetchingSource = false,
            engine = engine,
            verifier = verifier,
            policy = RevoktPolicy.DEFAULT,
            pinnedRootSpkis = pinned,
            storage = storage,
            logger = logger,
        )

    private fun CrliteRuntime.crlite(): DatasetGeneration = assertNotNull(snapshot.snapshot.datasets[Dataset.CRLITE])

    private val now = ts + 2 * hour

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
        val d2 =
            Rec(
                "d2",
                true,
                delta.effectiveTimestamp + 1,
                "d2.filter.delta",
                UpdateFixtures.v4(
                    listOf(UpdateFixtures.log(2) to (1L to 2L)),
                ),
                parent = full.id,
            )
        val live = installed(load(Seed(records = listOf(full, delta, d2), ts = ts + hour))).name
        storage.inner.write(store.blobKey(d2.body.toByteString().sha256()), byteArrayOf(1))
        reset(keepStore = true)
        val engine = TestEngine()
        val runtime = runtime(source(Seed(ts = ts - hour)), engine)
        start(runtime)
        assertEquals(previous, runtime.crlite().generationFile)
        assertEquals("$ts/${delta.id}", runtime.crlite().generationId)
        assertTrue(live in store.generationNames(), "the unloadable live is never deleted")
        assertFalse(runtime.storeReadUnresolved)
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
