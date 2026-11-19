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
    fun `a malformed pointer beside the seed's own complete directory installs it as it stands, healing the pointer`() {
        val own = installedAt(ts)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val kept = files(own)
        val engine = TestEngine()
        val load = installed(load(Seed(), engine = engine))
        assertEquals(own, load.directory)
        assertEquals(1, load.storeFailures, "the malformed pointer, counted once")
        assertEquals("$ts/${delta.id}", engine.live)
        assertEquals(Pointer(own, null), (store.pointer() as StoreRead.Found).value)
        assertEquals(kept, files(own), "installed as it stands, never reopened or rewritten")
    }

    @Test
    fun `beside a malformed pointer the seed's own directory with a rotted delta is completed again from the seed`() {
        val own = installedAt(ts)
        val deltaKey = "$root/$own/${delta.filename}"
        storage.inner.write(deltaKey, ByteArray(3))
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(own, load.directory)
        assertEquals(2, load.storeFailures, "the malformed pointer and the rejected directory, each once")
        assertEquals(delta.body.toList(), storage.inner.read(deltaKey)?.toList(), "the rotted delta is re-staged")
        assertEquals(Pointer(own, null), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `a failed load over the seed's own rotted directory leaves it incomplete, never deleted`() {
        val own = installedAt(ts)
        val deltaKey = "$root/$own/${delta.filename}"
        storage.inner.write(deltaKey, ByteArray(3))
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val kept = files(own).keys - "$root/$own/meta.json"
        // A seed whose delta body fails its signed hash (P8): unreadable after the directory was reopened.
        val index = Seed().index()
        val bad =
            Seed().apply {
                bodies = mapOf(delta.filename to delta.body.copyOf().also { it[0] = (it[0] + 1).toByte() })
                this.index = index
            }
        assertIs<SeedLoad.Unreadable>(load(bad))
        assertEquals(kept, files(own).keys, "every file stays but meta.json, for the next load")
        // A store write that fails while the delta is re-staged (P2): the same.
        storage.failWrite = { if (it == deltaKey) IOException("full") else null }
        failed(load(Seed()), "full")
        assertEquals(kept, files(own).keys)
        // The next valid seed completes it.
        storage.failWrite = { null }
        assertEquals(own, installed(load(Seed())).directory)
        assertEquals(delta.body.toList(), storage.inner.read(deltaKey)?.toList())
    }

    @Test
    fun `a rotted blob of the seed's own rejected directory is counted once, with the directory`() {
        val own = installedAt(ts)
        val blob = storage.inner.names().single { "/blobs/" in it }
        storage.inner.write(blob, ByteArray(5))
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(own, load.directory)
        assertEquals(2, load.storeFailures, "the malformed pointer and the rejected directory; its blob not again")
    }

    @Test
    fun `beside a malformed pointer the seed's own directory holding another generation fails and keeps it`() {
        val own = installedAt(ts)
        val meta = checkNotNull(store.meta(own))
        storage.inner.write(
            "$root/$own/meta.json",
            dev.revokt.engine.store.MetaJson
                .write(meta.copy(collection = "security-state/other")),
        )
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val before = contents()
        failed(load(Seed()), "holds another generation")
        assertEquals(before, contents())
    }

    @Test
    fun `a malformed pointer beside the seed's own directory with a malformed meta_json rewrites it from the seed`() {
        val own = installedAt(ts)
        storage.inner.write("$root/$own/meta.json", "{}".encodeToByteArray())
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(own, load.directory)
        assertTrue(store.meta(own) != null)
        assertEquals(Pointer(own, null), (store.pointer() as StoreRead.Found).value)
    }

    @Test
    fun `a trusted pointer whose live is the seed's own directory with an unreadable meta_json heals it`() {
        val own = installedAt(ts)
        storage.inner.write("$root/$own/meta.json", "{}".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(own, load.directory)
        assertEquals(1, load.storeFailures, "the unreadable pointed meta.json, counted once")
        assertTrue(store.meta(own) != null)
        assertEquals(own, liveDirectory())
    }

    @Test
    fun `the seed's own directory as pointed previous with an unreadable meta_json fails, counted once`() {
        val older = installedAt(ts - hour)
        val own = installedAt(ts)
        store.point(Pointer(older, own))
        storage.inner.write("$root/$own/meta.json", "{}".encodeToByteArray())
        reset(keepStore = true)
        val before = contents()
        val failed = failed(load(Seed()), "is live or pointed to, and its meta.json is not readable")
        assertEquals(1, failed.storeFailures)
        assertEquals(before, contents())
    }

    @Test
    fun `both pointed meta_json unreadable are two faults, and the seed installs`() {
        val first = installedAt(ts - 2 * hour)
        val second = installedAt(ts - hour)
        storage.inner.write("$root/$first/meta.json", "{}".encodeToByteArray())
        storage.inner.write("$root/$second/meta.json", "{}".encodeToByteArray())
        reset(keepStore = true)
        val load = installed(load(Seed()))
        assertEquals(2, load.storeFailures)
        assertEquals(Pointer(load.directory, null), (store.pointer() as StoreRead.Found).value)
        assertTrue(files(first).isNotEmpty() && files(second).isNotEmpty(), "not pruned")
    }

    @Test
    fun `at a fresh start beside a valid pointer to the seed's own generation, the seed is skipped`() {
        installedAt(ts)
        reset(keepStore = true)
        val before = contents()
        assertIs<SeedLoad.Skipped>(load(Seed()), "the start task loads the pointed generation")
        assertEquals(before, contents())
    }

    @Test
    fun `a running loader's live directory with a damaged meta_json is never rewritten beside a malformed pointer`() {
        val own = installedAt(ts)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        storage.inner.write("$root/$own/meta.json", "{".encodeToByteArray())
        val before = contents()
        // The snapshot still serves the seed's generation: the running loader's live directory.
        failed(load(Seed()), "is the engine's live generation")
        assertEquals(before, contents())
        assertEquals("$ts/${delta.id}", live().generationId)
    }

    @Test
    fun `a running loader's damaged live directory is left as it is when a newer generation is adopted instead`() {
        val own = installedAt(ts)
        val serving = snapshot.snapshot
        val newer = installedAt(ts + hour)
        snapshot.publish(serving)
        storage.inner.write(pointerKey, "garbage".encodeToByteArray())
        storage.inner.write("$root/$own/meta.json", "{".encodeToByteArray())
        val kept = files(own)
        assertEquals(newer, assertIs<SeedLoad.Adopted>(load(Seed())).directory)
        assertEquals(kept, files(own))
    }

    @Test
    fun `under a trusted pointer to an older live generation the seed installs and never prunes a newer one`() {
        // A sync completed gen-(ts + 1 h) and crashed before its flip; the pointer still names an older one.
        val older = installedAt(ts - hour)
        val newer = installedAt(ts + hour)
        store.point(Pointer(older, null))
        reset(keepStore = true)
        val kept = files(newer)
        val load = installed(load(Seed()))
        assertEquals(Pointer(load.directory, older), (store.pointer() as StoreRead.Found).value)
        assertEquals(kept, files(newer), "the newer complete directory is not pruned")
        // And a pointed previous newer than live, with the seed between them.
        reset(keepStore = true)
        store.point(Pointer(older, newer))
        val again = installed(load(Seed()))
        assertEquals(kept, files(newer))
        assertTrue(store.meta(again.directory) != null)
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
        assertEquals(1, load.storeFailures, "the malformed previous meta.json, counted once")
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
        // The seed is live in the engine though no pointer names it: a second load installs its directory as it stands,
        // and the flip heals the pointer (rule (b)).
        storage.failWrite = { null }
        val directory = GenerationNames.directory(ts, "$ts/${delta.id}")
        val kept = files(directory)
        assertEquals(directory, installed(load(Seed(), engine = engine)).directory)
        assertEquals(Pointer(directory, null), (store.pointer() as StoreRead.Found).value)
        assertEquals(kept, files(directory))
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
    fun `under a trusted pointer a complete orphan of the seed's name is completed afresh`() {
        val older = installedAt(ts - hour)
        val directory = installedAt(ts)
        store.point(Pointer(older, null))
        reset(keepStore = true)
        storage.inner.write("$root/$directory/stale-file", ByteArray(1))
        val load = installed(load(Seed()))
        assertEquals(directory, load.directory)
        assertNull(storage.inner.read("$root/$directory/stale-file"))
    }

    @Test
    fun `with no pointer the seed's own complete directory is installed as it stands`() {
        val directory = installedAt(ts)
        storage.inner.delete(pointerKey)
        reset(keepStore = true)
        val kept = files(directory)
        val load = installed(load(Seed()))
        assertEquals(directory, load.directory)
        assertEquals(kept, files(directory))
        assertEquals(Pointer(directory, null), (store.pointer() as StoreRead.Found).value)
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
