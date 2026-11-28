// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.Dataset
import dev.revokt.Freshness
import dev.revokt.RevoktInternalApi
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.GenerationFile
import dev.revokt.engine.store.GenerationFileJson
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.FilterRecord
import dev.revokt.engine.update.GenerationLoad
import dev.revokt.engine.update.UpdateFixtures
import dev.revokt.engine.update.UpdateFixtures.log
import dev.revokt.engine.update.load
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The seed-load rule's rule (b) over generation files (spec §6.5, the maintainer's Q2 answer): with no trustworthy
 * pointer, the adopt scan adopts the newest stored generation newer than the seed, and not older than the one the
 * engine serves, that re-verifies, and the seed installs otherwise. Split from [SeedLoaderStoreTest].
 */
internal class SeedAdoptTest : SeedFixture() {
    /** [name]'s generation file with [signature], under [leaf], at [ts]: another file, under another name. */
    private fun variant(
        name: String,
        signature: ByteString = stored(name).file.signature,
        leaf: ByteString = stored(name).file.signerLeafSha256,
        ts: Long = stored(name).timestampMillis,
    ): String {
        val f = stored(name).file
        val file = GenerationFile(f.dataset, f.channel, f.freshness, f.seedFormat, signature, leaf, f.records, ts)
        return store.putGeneration(GenerationFileJson.write(file))
    }

    private fun serve(at: Long) {
        snapshot.publish(
            GenerationSnapshot(
                1,
                mapOf(
                    Dataset.CRLITE to
                        DatasetGeneration("$at/x", Freshness.RECORD_LAST_MODIFIED, false, at, null, false, true),
                ),
                null,
            ),
        )
    }

    @Test
    fun `with no trustworthy pointer a newer generation that re-verifies is adopted, nothing else written`() {
        val newer = installedAt(ts + hour)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val before = contents()
        val adopted = assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(newer to ts + hour, adopted.name to adopted.timestampMillis)
        assertEquals(1, adopted.storeFailures, "the malformed pointer, counted where it is found")
        assertEquals(Pointer(newer, null), (store.pointer() as StoreRead.Found).value)
        val written = setOf(pointerKey, updaterKey)
        assertEquals(before - written, contents() - written, "only the pointer and updater.json are written")
        // With no pointer at all (a first sync that crashed before its flip), the same.
        storage.inner.delete(pointerKey)
        assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(Pointer(newer, null), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `a pointer whose live does not read is no trustworthy pointer, and the scan adopts`() {
        val newer = installedAt(ts + hour)
        store.point(Pointer("e".repeat(64), null))
        reset(keepStore = true)
        val adopted = assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(newer, adopted.name)
        assertEquals(1, adopted.storeFailures, "the absent live, once")
    }

    @Test
    fun `with no trustworthy pointer and nothing to adopt, a newer generation live in the engine is kept`() {
        serve(ts + hour)
        val skipped = assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(ts to ts + hour, skipped.seedTimestampMillis to skipped.storedTimestampMillis)
        assertTrue(store.generationNames().isEmpty())
    }

    @Test
    fun `adopt writes updater_json from the record read, its watermark raised to the adopted timestamp`() {
        val newer = installedAt(ts + hour)
        storage.inner.delete(pointerKey)
        store.writeUpdater(UpdaterRecord(watermarkMillis = ts - day, seedInstalledAtMillis = 5), ts)
        reset(keepStore = true)
        assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(UpdaterRecord(watermarkMillis = ts + hour, seedInstalledAtMillis = 5), updater())
        // Never lowered: a stored watermark above the adopted <ts> stays.
        store.writeUpdater(UpdaterRecord(watermarkMillis = ts + day), ts)
        storage.inner.delete(pointerKey)
        assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(ts + day, updater().watermarkMillis)
        assertEquals(Pointer(newer, null), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `adopt writes updater_json before the flip, so a failed flip is an honest failure and adopts again`() {
        val newer = installedAt(ts + hour)
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        storage.failWrite = { if (it == pointerKey) IOException("flip") else null }
        failed(load(Seed()), "flip")
        assertEquals(ts + hour, updater().watermarkMillis)
        storage.failWrite = { null }
        assertEquals(newer, assertIs<SeedLoad.Adopted>(load(Seed())).name)
    }

    @Test
    fun `adopt never rolls back below the generation the engine serves, and takes one not older`() {
        val newer = installedAt(ts + hour)
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        serve(ts + 2 * hour)
        assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(StoreRead.Absent, store.pointer())
        serve(ts + hour)
        assertEquals(newer, assertIs<SeedLoad.Adopted>(load(Seed())).name)
    }

    @Test
    fun `a newer generation whose signature no longer verifies under the seed's leaf is not adopted, counted, kept`() {
        val newer = installedAt(ts + hour)
        val forged = variant(newer, signature = ByteArray(96) { 1 }.toByteString())
        storage.inner.delete(store.generationKey(newer))
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
        assertIs<StoreRead.Found<*>>(store.readGeneration(forged), "kept")
    }

    @Test
    fun `a newer generation signed by another leaf is adopted on its stored hashes alone`() {
        val newer = installedAt(ts + hour)
        val other =
            variant(newer, signature = ByteArray(96) { 1 }.toByteString(), leaf = ByteArray(32) { 2 }.toByteString())
        storage.inner.delete(store.generationKey(newer))
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        assertEquals(other, assertIs<SeedLoad.Adopted>(load(Seed())).name)
    }

    @Test
    fun `a damaged newer file, or one whose blob is gone, is not adopted, counted once, and kept`() {
        val newer = installedAt(ts + hour)
        val key = store.generationKey(newer)
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).let { it.copyOf(it.size - 1) })
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        assertEquals(1, installed(load(Seed())).storeFailures, "a file that fails step 1")
        assertTrue(key in storage.inner.names())
        // A newer generation that reads but whose blob is missing fails step 3.
        reset()
        val n2 = installedAt(ts + hour)
        val blob = stored(n2).blobNames.first()
        storage.inner.delete(pointerKey)
        storage.inner.delete("$root/blobs/$blob")
        reset(keepStore = true)
        assertEquals(1, installed(load(Seed())).storeFailures, "a candidate that fails step 3")
        assertIs<StoreRead.Found<*>>(store.readGeneration(n2))
    }

    @Test
    fun `a pointed previous newer than the seed with a rotted blob of its own is counted once, by the scan`() {
        val older = installedAt(ts - hour)
        val d2 =
            Rec(
                "d2",
                true,
                delta.effectiveTimestamp + 1,
                "d2.filter.delta",
                UpdateFixtures.v4(listOf(log(2) to (1L to 2L))),
                parent = full.id,
            )
        val newer = installed(load(Seed(records = listOf(full, delta, d2), ts = ts + hour))).name
        store.point(Pointer(older, newer))
        // The live does not read, so the pointer is no trustworthy one (rule (b)); the newer previous's own blob rots.
        val key = store.generationKey(older)
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).let { it.copyOf(it.size - 1) })
        storage.inner.write(store.blobKey(d2.body.toByteString().sha256()), byteArrayOf(1))
        reset(keepStore = true)
        // The scan rejects the newer previous and counts it; the seed's install does not count it again as a previous
        // candidate (#335 review): one for the live, one for the previous.
        val load = installed(load(Seed()))
        assertEquals(2, load.storeFailures)
        assertEquals(Pointer(load.name, null), (store.pointer() as StoreRead.Found).value)
        assertTrue(store.generationKey(newer) in storage.inner.names(), "kept")
    }

    @Test
    fun `a newer generation whose filter does not decode past its coverage is not adopted, counted once, and kept`() {
        // A v4 trailing byte, which §6.3 rejects, behind a coverage that reads; the blob matches its signed hash, and
        // another leaf signed the file, so only the scan's whole decode can refuse it before the flip.
        val body = UpdateFixtures.v4(listOf(log(1) to (1L to 2L))) + byteArrayOf(0)
        val records = listOf(FilterRecord("own", "compat", false, 1, "own.filter"))
        store.putBlob(body)
        val json = UpdateFixtures.recordsJson(records, mapOf("own.filter" to body))
        val newer = store.putGeneration(GenerationFileJson.write(UpdateFixtures.file(json, ts + hour)))
        assertIs<GenerationLoad.Loaded>(store.load(newer), "the start chain's Load reads its coverage alone")
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures, "the rejected candidate, once")
        assertEquals(Pointer(load.name, null), (store.pointer() as StoreRead.Found).value)
        assertIs<StoreRead.Found<*>>(store.readGeneration(newer), "kept")
    }

    @Test
    fun `a newer generation whose blob holds another filter's valid bytes is not adopted`() {
        val newer = installedAt(ts + hour)
        val (a, b) = stored(newer).blobNames.toList()
        storage.inner.write("$root/blobs/$b", checkNotNull(storage.inner.read("$root/blobs/$a")))
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        assertEquals(1, installed(load(Seed())).storeFailures, "the rejected candidate, once")
        assertIs<StoreRead.Found<*>>(store.readGeneration(newer))
    }

    @Test
    fun `the newest candidate wins, ties broken by name, and an older valid file is not counted`() {
        val older = installedAt(ts - hour)
        val newer = installedAt(ts + hour)
        val newest = installedAt(ts + 2 * hour)
        val twin =
            variant(newest, signature = ByteArray(96) { 1 }.toByteString(), leaf = ByteArray(32) { 3 }.toByteString())
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val adopted = assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(minOf(newest, twin), adopted.name, "two files of one <ts>: the first by name")
        assertEquals(0, adopted.storeFailures)
        assertTrue(older != newer)
    }

    @Test
    fun `beside a trustworthy pointer nothing is scanned, so no damaged file is counted`() {
        installedAt(ts + hour)
        storage.inner.write(store.generationKey("f".repeat(64)), "{}".encodeToByteArray())
        reset(keepStore = true)
        val skipped = assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(0, skipped.storeFailures)
    }
}
