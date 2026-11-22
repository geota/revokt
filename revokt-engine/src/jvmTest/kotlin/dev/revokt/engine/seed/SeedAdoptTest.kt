// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The seed-load rule's rule (b) (lead, 2026-11-16 and 2026-11-19, on #138): with no trusted pointer, the seed adopts
 * the newest complete generation newer than it, and not older than the one the engine serves, whose stored files
 * re-verify, and installs otherwise. Split from [SeedLoaderStoreTest].
 */
internal class SeedAdoptTest : SeedFixture() {
    @Test
    fun `with no trusted pointer a newer complete generation that re-verifies is adopted, nothing else written`() {
        val newer = installedAt(ts + hour)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val before = contents()
        val adopted = assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(newer to ts + hour, adopted.directory to adopted.timestampMillis)
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
    fun `with no trusted pointer and nothing to adopt, a newer generation live in the engine is kept`() {
        snapshot.publish(
            dev.revokt.engine.generation.GenerationSnapshot(
                1,
                mapOf(
                    dev.revokt.Dataset.CRLITE to
                        dev.revokt.engine.generation.DatasetGeneration(
                            "${ts + hour}/x",
                            dev.revokt.Freshness.RECORD_LAST_MODIFIED,
                            false,
                            ts + hour,
                            null,
                            false,
                            true,
                        ),
                ),
                null,
            ),
        )
        val before = contents()
        assertEquals(ts + hour, assertIs<SeedLoad.Skipped>(load(Seed())).storedTimestampMillis)
        assertEquals(before, contents())
    }

    @Test
    fun `adopt writes updater_json from the record read, its watermark raised to the adopted timestamp`() {
        val newer = installedAt(ts + hour)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        storage.inner.write(updaterKey, "{not json".encodeToByteArray())
        reset(keepStore = true)
        assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(ts + hour, updater().watermarkMillis, "a malformed updater.json is replaced")
        storage.inner.delete(updaterKey)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(ts + hour, updater().watermarkMillis, "an absent one is written")
        store.writeUpdater(UpdaterRecord(watermarkMillis = ts + day, seedInstalledAtMillis = 5), ts)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        assertIs<SeedLoad.Adopted>(load(Seed()))
        assertEquals(
            UpdaterRecord(watermarkMillis = ts + day, seedInstalledAtMillis = 5),
            updater(),
            "the rest is kept",
        )
        assertTrue(store.meta(newer) != null)
    }

    @Test
    fun `the seed's own rotted directory is never rewritten while the engine serves it`() {
        val own = installedAt(ts)
        storage.inner.write("$root/$own/${delta.filename}", ByteArray(3))
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        val before = contents()
        failed(load(Seed()), "does not re-hash")
        assertEquals(before, contents(), "the served directory is byte-identical")
    }

    @Test
    fun `adopt writes updater_json before the flip, so a failed flip is an honest failure and adopts again`() {
        val newer = installedAt(ts + hour)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        store.writeUpdater(UpdaterRecord(watermarkMillis = 1), ts)
        reset(keepStore = true)
        storage.failWrite = { if (it == pointerKey) IOException("flip") else null }
        failed(load(Seed()), "flip")
        assertEquals(ts + hour, updater().watermarkMillis, "the watermark is raised; adopt never reads it")
        assertIs<StoreRead.Malformed>(store.pointer())
        storage.failWrite = { null }
        assertEquals(newer, assertIs<SeedLoad.Adopted>(load(Seed())).directory)
    }

    @Test
    fun `adopt never rolls back below the generation the engine serves`() {
        // The engine serves ts + 2 h, whose delta has rotted on disk; ts + 1 h re-verifies, and the pointer is malformed.
        installedAt(ts + hour)
        val serving = installedAt(ts + 2 * hour)
        storage.inner.write("$root/$serving/${delta.filename}", ByteArray(3))
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        val before = contents()
        val skipped = assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(ts + 2 * hour, skipped.storedTimestampMillis)
        assertEquals(2, skipped.storeFailures, "the malformed pointer and the rejected directory")
        assertEquals(before, contents())
    }

    @Test
    fun `adopt takes a generation not older than the one the engine serves`() {
        installedAt(ts + hour)
        val serving = snapshot.snapshot
        val newer = installedAt(ts + 2 * hour)
        snapshot.publish(serving)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        assertEquals(newer, assertIs<SeedLoad.Adopted>(load(Seed())).directory)
    }

    @Test
    fun `a newer generation whose records json no longer verifies under the seed's leaf is not adopted`() {
        val newer = installedAt(ts + hour)
        val recordsKey = "$root/$newer/records.json"
        val records = checkNotNull(storage.inner.read(recordsKey)).decodeToString()
        storage.inner.write(recordsKey, records.replace("octet-stream", "octet-streax").encodeToByteArray())
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures, "the rejected directory")
        assertTrue(store.meta(newer) != null)
    }

    @Test
    fun `a newer generation whose meta json timestamps disagree with its records is not adopted`() {
        val newer = installedAt(ts + hour)
        val meta = checkNotNull(store.meta(newer))
        val signed = checkNotNull(meta.signed).copy(changesetTimestampMillis = ts + 2 * hour)
        storage.inner.write(
            "$root/$newer/meta.json",
            dev.revokt.engine.store.MetaJson
                .write(meta.copy(signed = signed)),
        )
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        assertEquals(1, installed(load(Seed())).storeFailures, "the rejected directory")
    }

    @Test
    fun `a newer generation whose index names fewer files than its records place is not adopted`() {
        val newer = installedAt(ts + hour)
        val fullOnly =
            (
                dev.revokt.engine.update.buildIndex(
                    listOf(dev.revokt.engine.update.UpdateFixtures.fullRecord),
                    dev.revokt.CrliteChannel.COMPAT,
                ) { full.body } as dev.revokt.engine.update.IndexBuild.Built
            ).index
        storage.inner.write("$root/$newer/index.bin", fullOnly)
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        assertEquals(1, installed(load(Seed())).storeFailures, "the rejected directory")
    }

    @Test
    fun `a newer generation of another leaf whose records and changeset timestamps both moved is not adopted`() {
        val newer = installedAt(ts + hour)
        val recordsKey = "$root/$newer/records.json"
        val records = checkNotNull(storage.inner.read(recordsKey)).decodeToString()
        val moved = records.replace("\"last_modified\":\"${ts + hour}\"}", "\"last_modified\":\"${ts + 2 * hour}\"}")
        check(moved != records)
        storage.inner.write(recordsKey, moved.encodeToByteArray())
        val meta = checkNotNull(store.meta(newer))
        val other =
            checkNotNull(meta.signed).copy(
                changesetTimestampMillis = ts + 2 * hour,
                signerLeafSha256 = okio.ByteString.of(*ByteArray(32) { 7 }),
            )
        storage.inner.write(
            "$root/$newer/meta.json",
            dev.revokt.engine.store.MetaJson
                .write(meta.copy(signed = other)),
        )
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        assertEquals(1, installed(load(Seed())).storeFailures, "the rejected directory")
    }

    @Test
    fun `a newer generation signed by another leaf is adopted on its stored hashes alone`() {
        val newer = installedAt(ts + hour)
        val meta = checkNotNull(store.meta(newer))
        val other = checkNotNull(meta.signed).copy(signerLeafSha256 = okio.ByteString.of(*ByteArray(32) { 7 }))
        storage.inner.write(
            "$root/$newer/meta.json",
            dev.revokt.engine.store.MetaJson
                .write(meta.copy(signed = other)),
        )
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        assertEquals(newer, assertIs<SeedLoad.Adopted>(load(Seed())).directory)
    }

    @Test
    fun `a trusted pointer whose live is the engine's and the seed's directory with an unreadable meta counts once`() {
        val own = installedAt(ts)
        storage.inner.write("$root/$own/meta.json", "{}".encodeToByteArray())
        val before = contents()
        val failed = failed(load(Seed()), "is the engine's live generation")
        assertEquals(1, failed.storeFailures, "the unreadable pointed meta.json, counted once")
        assertEquals(before, contents())
    }

    @Test
    fun `a trusted older pointed live generation is kept when the engine serves one newer than the seed`() {
        val older = installedAt(ts - hour)
        installedAt(ts + hour)
        store.point(Pointer(older, null))
        val before = contents()
        assertEquals(ts + hour, assertIs<SeedLoad.Skipped>(load(Seed())).storedTimestampMillis)
        assertEquals(before, contents())
    }

    @Test
    fun `a newer complete generation that does not re-verify is not adopted, and is kept while the seed installs`() {
        val newer = installedAt(ts + hour)
        storage.inner.write("$root/$newer/${delta.filename}", ByteArray(3))
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val kept = files(newer)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures, "the rejected directory, counted once")
        assertEquals(Pointer(load.directory, null), (store.pointer() as StoreRead.Found).value)
        assertEquals(kept, files(newer), "never pruned in a rule (b) load")
    }

    @Test
    fun `a sync's directory of the seed's own generation, beside a malformed pointer, installs as it stands`() {
        val own = installedAt(ts)
        val meta = checkNotNull(store.meta(own))
        storage.inner.write(
            "$root/$own/meta.json",
            dev.revokt.engine.store.MetaJson
                .write(meta.copy(freshness = dev.revokt.Freshness.RECORD_LAST_MODIFIED)),
        )
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val kept = files(own)
        val load = installed(load(Seed()))
        assertEquals(own, load.directory)
        assertEquals(Pointer(own, null), (store.pointer() as StoreRead.Found).value)
        assertEquals(kept, files(own))
        assertTrue(live().fromSeed)
    }
}
