// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.RevoktInternalApi
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.GenerationLoad
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.load
import dev.revokt.engine.update.stored
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The seed load over the content-addressed store (spec §6.5 seed-load rule, #138, #287): every store read that is not
 * `Found` fails closed, each fault is counted once where it is found, and no seed load deletes anything. Rule (b)'s
 * adopt scan is [SeedAdoptTest]'s; the seed-vs-stored rules [SeedLoaderTest]'s.
 */
internal class SeedLoaderStoreTest : SeedFixture() {
    @Test
    fun `updater_json that throws on read fails closed, nothing written`() {
        storage.failRead = { if (it == updaterKey) IOException("disk") else null }
        val before = contents()
        val failed = failed(load(Seed()), "disk")
        assertEquals(1, failed.storeFailures)
        assertEquals(before, contents())
        assertNull(live().generationId)
    }

    @Test
    fun `a malformed updater_json reads as absent, counted, and the install writes a fresh one`() {
        storage.inner.write(updaterKey, "{not json".encodeToByteArray())
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
        assertEquals(UpdaterRecord(watermarkMillis = ts, seedInstalledAtMillis = ts + hour), updater())
    }

    @Test
    fun `an updater_json with one malformed source entry keeps the rest, the watermark included, and counts it`() {
        storage.inner.write(
            updaterKey,
            """{"watermarkMillis":${ts + day},"sources":{"bad":{"consecutiveFailures":"x"},"ok":{"consecutiveFailures":1}}}"""
                .encodeToByteArray(),
        )
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
        val record = updater()
        // The watermark was read (ts + day); with nothing loaded the seed's install sets it to its <ts> (§7.1).
        assertEquals(ts, record.watermarkMillis)
        assertEquals(setOf("ok"), record.sources.keys)
    }

    @Test
    fun `a pointer, or a pointed generation file, that throws on read fails closed, nothing written`() {
        val older = installedAt(ts - hour)
        reset(keepStore = true)
        for (key in listOf(pointerKey, store.generationKey(older))) {
            storage.failRead = { if (it == key) IOException("read") else null }
            val before = contents()
            failed(load(Seed()), "read")
            assertEquals(before, contents())
        }
    }

    @Test
    fun `a malformed pointer with only older generations installs, heals the pointer, and deletes nothing`() {
        val older = installedAt(ts - hour)
        storage.inner.write(pointerKey, "{".encodeToByteArray())
        reset(keepStore = true)
        val before = contents().keys
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
        assertEquals(Pointer(load.name, null), (store.pointer() as StoreRead.Found).value)
        assertTrue(contents().keys.containsAll(before))
        assertIs<StoreRead.Found<*>>(store.stored(older))
    }

    @Test
    fun `beside a malformed pointer the seed's own stored generation is reused as it stands, healing the pointer`() {
        val own = installedAt(ts)
        storage.inner.write(pointerKey, "{".encodeToByteArray())
        reset(keepStore = true)
        val kept = files(own)
        val load = installed(load(Seed()))
        assertEquals(own, load.name, "the same bytes, the same name")
        assertEquals(kept, files(own), "nothing rewritten")
        assertEquals(Pointer(own, null), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `a current with a flipped hex digit is counted once, and the seed's install heals it`() {
        val own = installedAt(ts)
        flipLiveHex(own)
        assertIs<StoreRead.Found<*>>(store.pointer(), "the pointer still parses")
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures, "the live the pointer names, which is no stored file")
        assertEquals(Pointer(own, null), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `beside a malformed pointer the seed's own rotted blob is rewritten from the seed, counted`() {
        val own = installedAt(ts)
        val blob = "$root/blobs/" + stored(own).blobNames.last()
        storage.inner.write(blob, byteArrayOf(1, 2, 3))
        storage.inner.write(pointerKey, "{".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(2, load.storeFailures, "the malformed pointer and the rotted blob")
        assertEquals(own, load.name)
        assertIs<GenerationLoad.Loaded>(store.load(own))
    }

    @Test
    fun `a rotted blob of a newer generation the scan rejected is counted once, with that generation`() {
        val newer = installedAt(ts + hour)
        // The newer seed shares the delta's blob with this one: rotting it fails the candidate at step 3.
        val shared = stored(newer).blobNames.last()
        storage.inner.write("$root/blobs/$shared", byteArrayOf(1))
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures, "the rejected candidate, not again for its rewritten blob")
        assertIs<StoreRead.Found<*>>(store.readGeneration(newer), "never deleted")
    }

    @Test
    fun `a trustworthy pointer whose live is the seed's own damaged file heals it, counted once`() {
        val own = installedAt(ts)
        val key = store.generationKey(own)
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).let { it.copyOf(it.size - 1) })
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
        assertEquals(own, load.name)
        assertIs<StoreRead.Found<*>>(store.readGeneration(own), "rewritten with the bytes its name promises")
    }

    @Test
    fun `the seed's own file as the pointed previous, damaged, is counted once, and the seed installs over it`() {
        val older = installedAt(ts - hour)
        val own = installedAt(ts)
        store.point(Pointer(older, own))
        val key = store.generationKey(own)
        storage.inner.write(key, "{}".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
        assertEquals(Pointer(own, older), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `a live the start's chain could not load is passed over and never counted again, by the scan or the install`() {
        val previous = installedAt(ts - hour)
        val d2 = Rec("d2", true, delta.effectiveTimestamp + 1, "d2.filter.delta", d2Body, parent = full.id)
        val live = installed(load(Seed(records = listOf(full, delta, d2), ts = ts + hour))).name
        // live passes Load's steps 1 and 2 and fails step 3: the chain counted it when it failed to load it.
        storage.inner.write(store.blobKey(okio.ByteString.of(*d2Body).sha256()), byteArrayOf(1))
        reset(keepStore = true)
        val bytes = Seed().bytes()
        val load = installed(loader(Counted { bytes }.source).load(ts + hour, unloadable = setOf(live)))
        // The chain counts it: CrliteRuntimeStartTest's rotted-live case logs exactly one for the whole start.
        assertEquals(0, load.storeFailures, "the seed load leaves the chain's failure to the chain")
        assertEquals(
            Pointer(load.name, previous),
            (store.pointer() as StoreRead.Found).value,
            "the unloadable live is no previous",
        )
        assertTrue(previous in store.generationNames() && live in store.generationNames())
    }

    private val d2Body =
        dev.revokt.engine.update.UpdateFixtures.v4(
            listOf(
                dev.revokt.engine.update.UpdateFixtures
                    .log(2) to (1L to 2L),
            ),
        )

    @Test
    fun `both pointed files unreadable are two faults, and the seed installs`() {
        val first = installedAt(ts - 2 * hour)
        val second = installedAt(ts - hour)
        assertEquals(Pointer(second, first), (store.pointer() as StoreRead.Found).value)
        for (n in listOf(first, second)) storage.inner.write(store.generationKey(n), "{}".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(2, load.storeFailures)
        assertTrue(
            store.generationKey(first) in storage.inner.names() && store.generationKey(second) in storage.inner.names(),
        )
    }

    @Test
    fun `at a fresh start beside a valid pointer to the seed's own generation, the seed is skipped`() {
        installedAt(ts)
        reset(keepStore = true)
        val before = contents()
        assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(before, contents())
    }

    @Test
    fun `under a trustworthy pointer to an older live generation the seed installs and prunes nothing`() {
        val older = installedAt(ts - 2 * hour)
        val previous = installedAt(ts - hour)
        store.point(Pointer(previous, older))
        val stray = "$root/blobs/" + "c".repeat(64)
        storage.inner.write(stray, byteArrayOf(1))
        reset(keepStore = true)
        installed(load(Seed()))
        assertTrue(stray in storage.inner.names(), "a seed load never prunes")
        assertIs<StoreRead.Found<*>>(store.readGeneration(older))
    }

    @Test
    fun `a write that fails while writing a blob is STORE_FAILED, and nothing is deleted`() {
        var writes = 0
        storage.failWrite = { if ("/blobs/" in it && writes++ == 1) IOException("full") else null }
        val failed = failed(load(Seed()), "full")
        assertEquals(1, failed.storeFailures)
        assertEquals(1, storage.inner.names().count { "/blobs/" in it }, "the blob written first stays")
        assertIs<StoreRead.Absent>(store.updater(ts))
        assertIs<StoreRead.Absent>(store.pointer())
    }

    @Test
    fun `an out-of-memory error from the store is caught, unreadable and counted`() {
        storage.failWrite = { if ("/generations/" in it) OutOfMemoryError("store") else null }
        val unreadable = assertIs<SeedLoad.Unreadable>(load(Seed()))
        assertEquals(1, unreadable.storeFailures)
        assertTrue(store.generationNames().isEmpty())
    }

    @Test
    fun `a blob that does not read back while the index is rebuilt fails at STORE`() {
        // The blob reads absent before it is written, then throws when the index is rebuilt from it.
        storage.failRead = { if ("/blobs/" in it && storage.inner.read(it) != null) IOException("blob") else null }
        failed(load(Seed()), "blob")
        assertTrue(store.generationNames().isEmpty())
    }

    @Test
    fun `a failed pointer flip after activate keeps the seed live, its file, and the old updater_json`() {
        store.writeUpdater(UpdaterRecord(watermarkMillis = 7), ts)
        val updater = storage.inner.read(updaterKey)?.toList()
        storage.failWrite = { if (it == pointerKey) IOException("flip") else null }
        val engine = TestEngine()
        failed(load(Seed(), engine = engine), "flip", activated = true)
        assertEquals("$ts/${delta.id}", engine.live)
        val name = store.generationNames().single()
        assertEquals(updater, storage.inner.read(updaterKey)?.toList())
        // The seed is live in the engine though no pointer names it: a second load finds its file and every blob, and
        // the flip heals the pointer.
        storage.failWrite = { null }
        val kept = files(name)
        assertEquals(name, installed(load(Seed(), engine = engine)).name)
        assertEquals(Pointer(name, null), (store.pointer() as StoreRead.Found).value)
        assertEquals(kept, files(name))
    }

    @Test
    fun `a failed updater_json write after the flip is STORE_FAILED with the seed live and pointed`() {
        storage.failWrite = { if (it == updaterKey) IOException("updater") else null }
        failed(load(Seed()), "updater", activated = true)
        assertEquals(live().generationFile, liveName())
        assertIs<StoreRead.Absent>(store.updater(ts))
    }
}
