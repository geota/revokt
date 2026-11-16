// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
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
 * The seed loader over a damaged, half-written or unreadable store (#138, and the data-loss lessons of #200, #207 and
 * #209): every store read it makes has a throwing arm and a malformed arm, and each fails closed. Nothing is written
 * from a record that was not read, no live or pointed generation is replaced or deleted, and a lower-trust install
 * never displaces a higher one ([SeedLoaderTest]'s seed-vs-stored rules).
 */
internal class SeedLoaderStoreTest : SeedFixture() {
    private val root = "crlite/compat"
    private val updaterKey = "$root/updater.json"
    private val pointerKey = "$root/current"

    /** Every key and its bytes, to show a failure left the store byte-identical. */
    private fun contents(): Map<String, List<Byte>> =
        storage.inner.names().associateWith { checkNotNull(storage.inner.read(it)).toList() }

    private fun failed(
        load: SeedLoad,
        detail: String,
        activated: Boolean = false,
    ): SeedLoad.Failed {
        val failed = assertIs<SeedLoad.Failed>(load, "$load")
        assertEquals(SyncOutcome.STORE_FAILED, failed.outcome)
        assertEquals(activated, failed.activated)
        assertTrue(detail in failed.detail, "'${failed.detail}' does not say '$detail'")
        return failed
    }

    /** A store holding the seed at [at] installed, live and pointed. */
    private fun installedAt(at: Long): String = installed(load(Seed(ts = at))).directory

    @Test
    fun `updater_json that throws on read fails closed, nothing written`() {
        storage.failRead = { if (it == updaterKey) IOException("disk") else null }
        val before = contents()
        val failed = failed(load(Seed()), "disk")
        assertEquals(SyncStage.STORE, failed.stage)
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
        assertEquals(ts + day, record.watermarkMillis)
        assertEquals(setOf("ok"), record.sources.keys)
    }

    @Test
    fun `a pointer that throws fails closed, nothing written`() {
        installedAt(ts - hour)
        storage.failRead = { if (it == pointerKey) IOException("pointer") else null }
        val before = contents()
        failed(load(Seed()), "pointer")
        assertEquals(before, contents())
    }

    /** Every key of [directory] and its bytes. */
    private fun files(directory: String): Map<String, List<Byte>> = contents().filterKeys { "/$directory/" in it }

    @Test
    fun `a malformed pointer with only older generations installs, heals the pointer, and deletes nothing`() {
        val first = installedAt(ts - 2 * hour)
        val second = installedAt(ts - hour)
        val kept = files(first) + files(second)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures, "counted once, by the install")
        assertEquals(Pointer(load.directory, null), (store.pointer() as StoreRead.Found).value)
        assertEquals(kept, files(first) + files(second), "no complete directory is reopened, rewritten or pruned")
    }

    @Test
    fun `a malformed pointer beside a stored generation not older than the seed skips it, nothing written`() {
        installedAt(ts)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val before = contents()
        val skipped = assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(ts, skipped.storedTimestampMillis)
        // Counted once, by the install that reads the pointer; a skip installs nothing (#138).
        assertEquals(0, skipped.storeFailures)
        assertEquals(before, contents(), "the seed's own complete directory is never reopened")
        installedAt(ts + hour)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        assertIs<SeedLoad.Skipped>(load(Seed()))
    }

    @Test
    fun `a pointed live meta_json that throws fails closed, and malformed the seed installs with nothing pruned`() {
        val old = installedAt(ts - hour)
        val metaKey = "$root/$old/meta.json"
        storage.failRead = { if (it == metaKey) IOException("meta") else null }
        val before = contents()
        failed(load(Seed()), "meta")
        assertEquals(before, contents())
        storage.failRead = { null }
        storage.inner.write(metaKey, "{}".encodeToByteArray())
        reset(keepStore = true)
        val kept = files(old)
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures, "counted once, by the install")
        assertEquals(load.directory, liveDirectory())
        assertEquals(kept, files(old), "the unreadable pointed directory stays until a prune over a valid pointer")
    }

    @Test
    fun `a pointed previous meta_json that is malformed is kept, the seed installs and nothing is pruned`() {
        val first = installedAt(ts - 2 * hour)
        val second = installedAt(ts - hour)
        assertEquals(Pointer(second, first), (store.pointer() as StoreRead.Found).value)
        storage.inner.write("$root/$first/meta.json", "[]".encodeToByteArray())
        val kept = files(first) + files(second)
        val load = installed(load(Seed()))
        assertEquals(load.directory, liveDirectory())
        assertEquals(kept, files(first) + files(second))
    }

    @Test
    fun `a write that fails while staging a delta is STORE_FAILED and the staged directory is deleted`() {
        storage.failWrite = { if ("/gen-" in it && it.endsWith(".delta")) IOException("full") else null }
        val failed = failed(load(Seed()), "full")
        assertEquals(1, failed.storeFailures)
        assertTrue(storage.names().none { "/gen-" in it }, "${storage.names()}")
        assertIs<StoreRead.Absent>(store.updater(ts))
    }

    @Test
    fun `an out-of-memory error from the store is caught, unreadable and counted`() {
        storage.failWrite = { if ("/gen-" in it) OutOfMemoryError("store") else null }
        val unreadable = assertIs<SeedLoad.Unreadable>(load(Seed()))
        assertEquals(1, unreadable.storeFailures)
        assertTrue(storage.names().none { "/gen-" in it })
    }

    @Test
    fun `a blob that does not read back while the index is rebuilt fails at STORE and deletes the staged directory`() {
        // The blob reads absent before it is written, then throws when the index is rebuilt from it.
        storage.failRead = { if ("/blobs/" in it && storage.inner.read(it) != null) IOException("blob") else null }
        failed(load(Seed()), "blob")
        assertTrue(storage.names().none { "/gen-" in it })
    }

    @Test
    fun `a failed pointer flip after activate keeps the seed live, its directory, and the old updater_json`() {
        store.writeUpdater(UpdaterRecord(watermarkMillis = 7), ts)
        val updater = storage.inner.read(updaterKey)?.toList()
        storage.failWrite = { if (it == pointerKey) IOException("flip") else null }
        val engine = TestEngine()
        val failed = failed(load(Seed(), engine = engine), "flip", activated = true)
        assertEquals(SyncStage.STORE, failed.stage)
        assertEquals("$ts/${delta.id}", engine.live)
        assertTrue(store.meta(GenerationNames.directory(ts, "$ts/${delta.id}")) != null)
        assertEquals(updater, storage.inner.read(updaterKey)?.toList())
        // The seed is live in the engine though the store does not point to it: a second load never displaces it.
        storage.failWrite = { null }
        val before = contents()
        assertIs<SeedLoad.Skipped>(load(Seed()))
        assertEquals(before, contents())
    }

    @Test
    fun `a failed updater_json write after the flip is STORE_FAILED with the seed live and pointed`() {
        storage.failWrite = { if (it == updaterKey) IOException("updater") else null }
        failed(load(Seed()), "updater", activated = true)
        assertEquals(GenerationNames.directory(ts, "$ts/${delta.id}"), liveDirectory())
        assertIs<StoreRead.Absent>(store.updater(ts))
    }

    /** The seed's directory as the pointer's `previous`, under an older live generation: pointed, not live. */
    private fun seedAsPrevious(): String {
        val older = installedAt(ts - hour)
        val seed = installedAt(ts)
        store.point(Pointer(older, seed))
        reset(keepStore = true)
        return seed
    }

    @Test
    fun `a seed whose directory is the pointer's previous re-installs it as it stands, never rewritten`() {
        val seed = seedAsPrevious()
        val files =
            storage.inner
                .names()
                .filter { "/$seed/" in it }
                .associateWith { storage.inner.read(it)?.toList() }
        val load = installed(load(Seed()))
        assertEquals(seed, load.directory)
        assertEquals(
            files,
            storage.inner
                .names()
                .filter { "/$seed/" in it }
                .associateWith { storage.inner.read(it)?.toList() },
        )
    }

    @Test
    fun `a pointed previous directory whose delta does not re-hash fails closed and is never deleted`() {
        val seed = seedAsPrevious()
        val deltaKey = "$root/$seed/${delta.filename}"
        storage.inner.write(deltaKey, ByteArray(3))
        val before = contents()
        failed(load(Seed()), "holds another generation")
        assertEquals(before, contents())
    }

    @Test
    fun `a complete orphan directory of the seed's name is completed afresh`() {
        val directory = installedAt(ts)
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        storage.inner.write("$root/$directory/stale-file", ByteArray(1))
        val load = installed(load(Seed()))
        assertEquals(directory, load.directory)
        assertNull(storage.inner.read("$root/$directory/stale-file"))
    }

    @Test
    fun `a prune that fails is a store failure, never the load's`() {
        val old = installedAt(ts - 2 * hour)
        installedAt(ts - hour)
        storage.failDelete = { if (it.startsWith("$root/$old/")) IOException("delete") else null }
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
    }

    @Test
    fun `a pointer that does not read back after the install skips the prune and counts it`() {
        installedAt(ts - hour)
        var flipped = false
        storage.failWrite = {
            if (it == pointerKey) flipped = true
            null
        }
        storage.hidden = { it == pointerKey && flipped }
        val load = installed(load(Seed()))
        assertEquals(1, load.storeFailures)
        assertTrue(storage.names().any { "/gen-" in it && it.endsWith(StoreLayout.META) })
    }
}
