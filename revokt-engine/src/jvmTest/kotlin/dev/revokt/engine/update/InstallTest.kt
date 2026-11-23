// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.SyncFailure
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.MetaJson
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.UpdateFixtures.deltaRecord
import dev.revokt.engine.update.UpdateFixtures.fullRecord
import dev.revokt.engine.update.UpdateFixtures.log
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The §6.5 install order (#130): nothing is live before every check passes; a failure leaves the previous generation. */
internal class InstallTest : InstallFixture() {
    @Test
    fun `a generation installs in the 6_5 order and is published, pointed to and recorded`() {
        val p = pending()
        storage.writes.clear()
        val r = assertIs<InstallResult.Installed>(install(p))
        val dir = p.meta.directory
        assertEquals(dir, r.directory)
        assertEquals("g1", r.generationId)
        assertEquals(1, r.generationEpoch)
        assertEquals(0, r.storeFailures)
        // The delta was staged before the install (UpdateFixtures.pending, as the sync stages each body it fetches).
        assertEquals(
            listOf(
                "$dir/index.bin",
                "$dir/records.json",
                "$dir/meta.json",
                "current",
                "updater.json",
            ),
            storage.writes,
        )
        assertEquals("g1", engine.live)
        assertEquals(StoreRead.Found(Pointer(dir, null)), store.pointer())
        assertEquals(1L, (store.updater(now) as StoreRead.Found).value.record.watermarkMillis)
        val s = snapshot.snapshot
        assertEquals(1, s.generationEpoch)
        assertEquals(engine.inner.coverageEndMillis, s.coverageEndMillis)
        assertNotNull(s.coverageEndMillis)
        assertEquals(
            DatasetGeneration(
                "g1",
                Freshness.RECORD_LAST_MODIFIED,
                fromSeed = false,
                sourceTimestampMillis = 1_792_587_631_204,
                seedFormat = null,
                pending = false,
                staleGateOpen = false,
            ),
            s.datasets.getValue(Dataset.CRLITE),
        )
    }

    @Test
    fun `an engine that cannot tell its coverage end publishes none`() {
        val engine = TestEngine().apply { coverageEnd = { null } }
        install(pending(), engine = engine)
        assertNull(snapshot.snapshot.coverageEndMillis)
    }

    @Test
    fun `33- and 64-character names are the derived names in index bin, GenerationFiles, the directory, meta json`() {
        val long33 = "20261021-123-compat.filter.deltax"
        val long64 = "20261017-1-compat-full-filter-with-a-very-long-name-0123456.filt"
        val window = listOf(log(1) to (1_000L to 2_000L))
        val bodies = mapOf(long64 to UpdateFixtures.v4(window), long33 to UpdateFixtures.v4(window))
        val records =
            listOf(FilterRecord("f", "compat", false, 1, long64), FilterRecord("d", "compat", true, 2, long33))
        val p = UpdateFixtures.pending(store, records, bodies, generationId = "g-long", format = FilterFormat.V4)
        val r = assertIs<InstallResult.Installed>(install(p))
        val full = GenerationNames.derive(long64)
        val delta = GenerationNames.derive(long33)
        val stored = assertNotNull(store.readGeneration(r.directory))
        assertEquals(listOf(full, delta), C2spIndex.read(stored.files.bytes("index.bin")).filenames)
        assertEquals(setOf("index.bin", full, delta), stored.files.names)
        assertEquals(setOf(full), stored.meta.blobs.keys)
        assertTrue(storage.names().contains("crlite/compat/${r.directory}/$delta"))
        val all = storage.names().joinToString() + store.readMeta(r.directory)
        assertTrue(long64 !in all && long33 !in all, all)
    }

    @Test
    fun `the epoch advances once per install, after activate and before the pointer flip`() {
        val atActivate = mutableListOf<Long>()
        val atFlip = mutableListOf<Long>()
        engine.onActivate = { atActivate += snapshot.snapshot.generationEpoch }
        storage.onWrite = { if (it.endsWith("/current")) atFlip += snapshot.snapshot.generationEpoch }
        assertIs<InstallResult.Installed>(install(pending("g1")))
        assertIs<InstallResult.Installed>(install(pending("g2", timestamp = 1_792_587_631_205)))
        assertEquals(listOf(0L, 1L), atActivate)
        assertEquals(listOf(1L, 2L), atFlip)
        assertEquals(2, snapshot.snapshot.generationEpoch)
    }

    @Test
    fun `the install never queries the prepared generation, so a constant-answer engine installs`() {
        // The self-check moved to the cross-engine suite (EngineProbesTest): prepare is followed by activate directly.
        engine.preparedAnswer = { error("the install queried the prepared generation") }
        val r = assertIs<InstallResult.Installed>(install(pending()))
        assertEquals("g1", r.generationId)
        assertEquals("g1", engine.live)
    }

    @Test
    fun `a prepare or activate that throws is ENGINE_FAILED and leaves everything as it was`() {
        assertIs<InstallResult.Installed>(install(pending("g1")))
        val published = snapshot.snapshot
        val pointer = store.pointer()
        val cases =
            listOf(
                true to IllegalArgumentException("corrupt"),
                true to OutOfMemoryError("prepare"),
                false to IllegalStateException("closed"),
                false to OutOfMemoryError("activate"),
            )
        for ((inPrepare, thrown) in cases) {
            val e = TestEngine(inner = engine.inner)
            val fail = { throw thrown }
            if (inPrepare) e.onPrepare = { fail() } else e.onActivate = fail
            val p = pending("g2", timestamp = 1_792_587_631_205)
            val f = failed(install(p, e))
            assertEquals(SyncFailure.ENGINE_FAILED, f.failure, "$thrown")
            assertEquals(thrown::class, assertNotNull(f.cause)::class)
            assertEquals(1, f.storeFailures)
            assertEquals(false, f.activated)
            assertUntouched(p.meta.directory, live = "g1", published = published)
            assertEquals(pointer, store.pointer())
            if (!inPrepare) assertEquals(listOf("g2"), e.closed)
        }
    }

    @Test
    fun `an InterruptedException from prepare or activate fails the install and keeps the interrupt`() {
        assertIs<InstallResult.Installed>(install(pending("g1")))
        val published = snapshot.snapshot
        for (stage in listOf("prepare", "activate")) {
            val e = TestEngine(inner = engine.inner)
            val interrupt = { throw InterruptedException(stage) }
            if (stage == "prepare") e.onPrepare = { interrupt() } else e.onActivate = interrupt
            val p = pending("g2", timestamp = 1_792_587_631_205)
            try {
                val f = failed(install(p, e))
                assertEquals(SyncFailure.ENGINE_FAILED, f.failure, stage)
                assertIs<InterruptedException>(f.cause)
                assertTrue(Thread.currentThread().isInterrupted, "the interrupt flag is restored at $stage")
            } finally {
                Thread.interrupted()
            }
            assertUntouched(p.meta.directory, live = "g1", published = published)
        }
    }

    @Test
    fun `a format the engine does not list is FORMAT_UNSUPPORTED and never offered to prepare`() {
        val v4only = TestEngine(formats = setOf(FilterFormat.V4))
        val p = pending()
        storage.writes.clear()
        val f = failed(install(p, v4only))
        assertEquals(SyncFailure.FORMAT_UNSUPPORTED, f.failure)
        assertEquals(0, f.storeFailures)
        assertEquals(emptyList(), v4only.prepared)
        assertEquals(emptyList(), storage.writes)
        assertUntouched(p.meta.directory)
    }

    @Test
    fun `an index over 1 MiB fails before the directory is written, and one of exactly 1 MiB installs`() {
        val p = pending()
        val over =
            PendingGeneration(p.meta, p.index + ByteArray(C2spIndex.MAX_BYTES + 1 - p.index.size), p.deltas, p.records)
        storage.writes.clear()
        val f = failed(install(over))
        assertEquals(SyncFailure.INDEX_INCONSISTENT, f.failure)
        assertEquals(0, f.storeFailures)
        assertEquals(emptyList(), storage.writes)
        assertEquals(emptyList(), engine.prepared)
        // C2SP's reader allows trailing bytes, so zero padding makes a valid index of exactly the cap. The failures
        // deleted the staged delta, so it is staged again.
        val again = pending()
        val atCap =
            PendingGeneration(
                again.meta,
                again.index + ByteArray(C2spIndex.MAX_BYTES - again.index.size),
                again.deltas,
                again.records,
            )
        assertIs<InstallResult.Installed>(install(atCap))
    }

    @Test
    fun `a store write that throws is STORE_FAILED, deletes what it wrote, and offers nothing to the engine`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/records.json")) IllegalStateException("disk full") else null }
        val f = failed(install(p))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals(1, f.storeFailures)
        assertEquals(emptyList(), engine.prepared)
        assertUntouched(p.meta.directory)
        storage.fail = { if (it.endsWith("/meta.json")) OutOfMemoryError("store") else null }
        val oom = failed(install(pending()))
        assertEquals(SyncFailure.INTERNAL_ERROR, oom.failure)
        assertEquals(1, oom.storeFailures)
        assertUntouched(p.meta.directory)
    }

    @Test
    fun `a pointer flip or updater write that throws after the publish is STORE_FAILED with the generation live`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        val f = failed(install(p))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals(true, f.activated)
        assertEquals(1, f.storeFailures)
        assertEquals("g1", engine.live)
        assertEquals(1, snapshot.snapshot.generationEpoch)
        assertNotNull(store.readGeneration(p.meta.directory))
        assertEquals(StoreRead.Absent, store.pointer())
        storage.fail = { if (it.endsWith("/updater.json")) IllegalStateException("updater") else null }
        val g2 = pending("g2", timestamp = 1_792_587_631_205)
        val u = failed(install(g2))
        assertEquals(true, u.activated)
        // g1, which the engine served although no pointer named it, is the fallback (#249).
        assertEquals(StoreRead.Found(Pointer(g2.meta.directory, p.meta.directory)), store.pointer())
    }

    @Test
    fun `a retry over its own complete directory skips the write and installs`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        assertEquals(true, failed(install(p)).activated)
        storage.fail = { null }
        storage.writes.clear()
        val r = assertIs<InstallResult.Installed>(install(pending()))
        assertEquals(listOf("current", "updater.json"), storage.writes)
        assertEquals(2, r.generationEpoch)
        assertEquals(StoreRead.Found(Pointer(p.meta.directory, null)), store.pointer())
        assertEquals("g1", engine.live)
    }

    @Test
    fun `a failed retry deletes an orphan complete directory and keeps a pointed one`() {
        val orphan = pending()
        store.completeGeneration(orphan.meta, orphan.index, orphan.deltas, orphan.records)
        engine.onActivate = { error("activate") }
        // The orphan holds this generation, so it is prepared as it stands, and as the directory the install was given
        // it is deleted on the failure (§6.5).
        assertEquals(SyncFailure.ENGINE_FAILED, failed(install(pending())).failure)
        assertEquals(emptyList(), keysOf(orphan.meta.directory))
        // Pointed to, but not live in this snapshot: a failure leaves it for recovery.
        engine.onActivate = {}
        val dir = assertIs<InstallResult.Installed>(install(pending())).directory
        engine.onActivate = { error("activate") }
        val fresh = SnapshotRef(empty)
        val f = install(pending(), engine, store, fresh, publication, null, logger)
        assertEquals(SyncFailure.ENGINE_FAILED, failed(f).failure)
        assertNotNull(store.readGeneration(dir))
        assertSame(empty, fresh.snapshot)
    }

    @Test
    fun `a failed install of the pointer's previous generation keeps it, held as the pointer names it`() {
        // The r205b probe: g1, then g2, so the pointer is (g2, g1); then a rollback-inside-the-window install of g1
        // with a fresh snapshot, whose activate fails. g1 is held through the pointer's previous, so it stays.
        val g1 = assertIs<InstallResult.Installed>(install(pending("g1"))).directory
        val g2 = assertIs<InstallResult.Installed>(install(pending("g2", timestamp = 2_000_000_000_000))).directory
        assertEquals(StoreRead.Found(Pointer(g2, g1)), store.pointer())
        engine.onActivate = { error("activate") }
        val f = failed(install(pending("g1"), engine, store, SnapshotRef(empty), publication, null, logger))
        assertEquals(SyncFailure.ENGINE_FAILED, f.failure)
        assertNotNull(store.readGeneration(g1))
        assertEquals(StoreRead.Found(Pointer(g2, g1)), store.pointer())
    }

    @Test
    fun `an orphan holding another meta json or index bin is completed afresh, and a held one fails and stays`() {
        // Referenced by nothing: completed again with this generation's files, as main replaced it whole (#205 review).
        val p = pending()
        val other = p.meta.copy(collection = "security-state/other")
        store.completeGeneration(other, p.index, p.deltas, p.records)
        assertIs<InstallResult.Installed>(
            install(pending(), engine, store, SnapshotRef(empty), publication, null, logger),
        )
        assertEquals(p.meta, store.meta(p.meta.directory))
        storage.inner.delete("crlite/compat/current")
        store.deleteGeneration(p.meta.directory)
        val padded = p.index + ByteArray(4)
        store.writeGeneration(p.meta, padded, bytesOf(p), p.records)
        assertIs<InstallResult.Installed>(
            install(pending(), engine, store, SnapshotRef(empty), publication, null, logger),
        )
        assertTrue(p.index.contentEquals(store.file(p.meta.directory, StoreLayout.INDEX)))
        // Pointed to: another meta json fails and stays.
        storage.inner.write("crlite/compat/${p.meta.directory}/meta.json", MetaJson.write(other))
        val f = failed(install(pending(), engine, store, SnapshotRef(empty), publication, null, logger))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertTrue("holds another generation" in f.cause?.message.orEmpty())
        assertEquals(other, store.meta(p.meta.directory))
    }

    @Test
    fun `a retry over its own directory re-signed under the same ts installs, keeping the stored meta json`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        assertEquals(true, failed(install(p)).activated)
        storage.fail = { null }
        // The maintainer's decision on #200: the same <ts> and signed records under another signature or leaf.
        val signed = checkNotNull(p.meta.signed)
        val resigned =
            signed.copy(
                signerLeafSha256 = ByteArray(32) { 1 }.toByteString(),
                signature = ByteArray(64) { 2 }.toByteString(),
            )
        val retry = PendingGeneration(p.meta.copy(signed = resigned), p.index, p.deltas, p.records)
        storage.writes.clear()
        val r = assertIs<InstallResult.Installed>(install(retry))
        assertEquals(listOf("current", "updater.json"), storage.writes)
        assertEquals(StoreRead.Found(Pointer(p.meta.directory, null)), store.pointer())
        assertEquals(p.meta, store.meta(r.directory))
    }

    @Test
    fun `a directory that differs in anything but the signed members still holds another generation`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        assertEquals(true, failed(install(p)).activated)
        storage.fail = { null }
        val resigned = checkNotNull(p.meta.signed).copy(signature = ByteArray(96) { 3 }.toByteString())
        val others =
            listOf(
                "collection" to
                    PendingGeneration(p.meta.copy(collection = "x/y", signed = resigned), p.index, p.deltas, p.records),
                "freshness" to
                    PendingGeneration(
                        p.meta.copy(freshness = Freshness.SEED_SIGNED_TIME, signed = resigned),
                        p.index,
                        p.deltas,
                        p.records,
                    ),
                "index.bin" to
                    PendingGeneration(p.meta.copy(signed = resigned), p.index + ByteArray(4), p.deltas, p.records),
                "records.json" to
                    PendingGeneration(
                        p.meta.copy(signed = resigned),
                        p.index,
                        p.deltas,
                        "{\"data\":[1]}".encodeToByteArray(),
                    ),
            )
        for ((what, other) in others) {
            val f = failed(install(other))
            assertEquals(SyncFailure.STORE_FAILED, f.failure, what)
            assertTrue("holds another generation" in f.cause?.message.orEmpty(), what)
            assertEquals(p.meta, store.meta(p.meta.directory), what)
        }
    }

    @Test
    fun `a malformed or incomplete directory is replaced whole`() {
        val p = pending()
        val dir = p.meta.directory
        for (meta in listOf("{".encodeToByteArray(), null)) {
            storage.inner.write("crlite/compat/$dir/index.bin", byteArrayOf(1))
            storage.inner.write("crlite/compat/$dir/stray", byteArrayOf(2))
            if (meta != null) storage.inner.write("crlite/compat/$dir/meta.json", meta)
            // A fresh snapshot each round, so the directory is not the live one.
            val r = install(pending(), TestEngine(), store, SnapshotRef(empty), publication, null, logger)
            assertIs<InstallResult.Installed>(r, "meta=$meta")
            assertEquals(false, storage.names().contains("crlite/compat/$dir/stray"))
            assertEquals(p.meta, store.meta(dir))
            storage.inner.delete("crlite/compat/current")
            store.deleteGeneration(dir)
        }
    }

    @Test
    fun `a retry that fails before activate keeps the live directory the failed flip left unpointed`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        assertEquals(true, failed(install(p)).activated)
        storage.fail = { null }
        engine.onPrepare = { throw IllegalArgumentException("corrupt") }
        val f = failed(install(pending()))
        assertEquals(SyncFailure.ENGINE_FAILED, f.failure)
        assertNotNull(store.readGeneration(p.meta.directory))
        assertEquals("g1", engine.live)
    }

    @Test
    fun `an orphan holding this generation is completed afresh with its meta json, a pointed one reused as is`() {
        val p = pending()
        val signed = checkNotNull(p.meta.signed)
        val stale = p.meta.copy(signed = signed.copy(signature = ByteArray(96) { 3 }.toByteString()))
        store.completeGeneration(stale, p.index, p.deltas, p.records)
        storage.writes.clear()
        // An orphan (neither live nor pointed): its files re-hash and stay, and it carries this install's signature.
        assertIs<InstallResult.Installed>(install(pending()))
        val dir = p.meta.directory
        assertEquals(
            listOf("$dir/index.bin", "$dir/records.json", "$dir/meta.json", "current", "updater.json"),
            storage.writes,
        )
        assertEquals(p.meta, store.meta(dir))
        // Pointed to (not live in a fresh snapshot): reused as it stands.
        storage.writes.clear()
        val r = install(pending(), engine, store, SnapshotRef(empty), publication, null, logger)
        assertIs<InstallResult.Installed>(r)
        assertEquals(listOf("current"), storage.writes)
    }

    @Test
    fun `#201 - a stored delta that does not re-hash fails a held directory, and an orphan is deleted for a restage`() {
        // An orphan holding this generation's meta json, index bin and records json, with a corrupted delta: the
        // install fails and deletes it, so the next one stages afresh and installs, never a STORE_FAILED loop.
        val p = pending()
        val dir = p.meta.directory
        val delta = p.deltas.keys.single()
        store.writeGeneration(p.meta, p.index, mapOf(delta to byteArrayOf(4, 0)), p.records)
        val orphan = failed(install(pending()))
        assertEquals(SyncFailure.STORE_FAILED, orphan.failure)
        assertEquals(emptyList(), keysOf(dir))
        assertEquals(emptyList(), engine.prepared)
        val fresh = TestEngine()
        assertIs<InstallResult.Installed>(
            install(pending(), fresh, store, SnapshotRef(empty), publication, null, logger),
        )
        storage.inner.delete("crlite/compat/current")
        // The live directory a failed flip left unpointed, its delta then corrupted: the retried flip fails and keeps it.
        store.deleteGeneration(dir)
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        assertEquals(true, failed(install(pending())).activated)
        storage.fail = { null }
        storage.inner.write("crlite/compat/$dir/$delta", bytesOf(p).getValue(delta).copyOf().also { it[0] = 9 })
        val held = failed(install(pending()))
        assertEquals(SyncFailure.STORE_FAILED, held.failure)
        assertTrue("holds another generation" in held.cause?.message.orEmpty())
        assertNotNull(store.meta(dir))
        assertEquals(StoreRead.Absent, store.pointer())
    }

    @Test
    fun `a staged delta that is missing or does not re-hash is STORE_FAILED and the directory is deleted`() {
        val p = pending()
        val dir = p.meta.directory
        val delta = p.deltas.keys.single()
        storage.inner.write("crlite/compat/$dir/$delta", byteArrayOf(1))
        val f = failed(install(p))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals(1, f.storeFailures)
        assertUntouched(dir)
        // Missing: nothing staged at all.
        val g = failed(install(p))
        assertEquals(SyncFailure.STORE_FAILED, g.failure)
        assertUntouched(dir)
    }

    @Test
    fun `a pointed directory whose meta json is malformed is kept, as a newer binary's generation`() {
        val p = pending()
        assertIs<InstallResult.Installed>(install(p))
        val key = "crlite/compat/${p.meta.directory}/meta.json"
        storage.inner.write(key, "{\"metaVersion\":2}".encodeToByteArray())
        val f = install(pending(), TestEngine(), store, SnapshotRef(empty), publication, null, logger)
        assertEquals(SyncFailure.STORE_FAILED, failed(f).failure)
        assertEquals("{\"metaVersion\":2}", storage.inner.read(key)?.decodeToString())
        assertNotNull(storage.inner.read("crlite/compat/${p.meta.directory}/index.bin"))
    }

    @Test
    fun `the live generation's directory is never replaced, even with a malformed meta json`() {
        val p = pending()
        assertIs<InstallResult.Installed>(install(p))
        val published = snapshot.snapshot
        val key = "crlite/compat/${p.meta.directory}/meta.json"
        storage.inner.write(key, "{".encodeToByteArray())
        val f = failed(install(pending()))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals("{", storage.inner.read(key)?.decodeToString())
        assertSame(published, snapshot.snapshot)
        assertEquals("g1", engine.live)
    }

    @Test
    fun `previous is the old live generation`() {
        fun dir(r: InstallResult) = assertIs<InstallResult.Installed>(r).directory
        val g1 = dir(install(pending("g1")))
        val g2 = dir(install(pending("g2", timestamp = 2_000_000_000_000)))
        assertEquals(StoreRead.Found(Pointer(g2, g1)), store.pointer())
        val g3 = dir(install(pending("g3", timestamp = 2_000_000_000_001)))
        assertEquals(StoreRead.Found(Pointer(g3, g2)), store.pointer())
    }

    @Test
    fun `a pointed generation that does not read back is no previous, counted (#246)`() {
        val g1 = assertIs<InstallResult.Installed>(install(pending("g1"))).directory
        // meta.json reads, records.json is gone: the loader could not load g1, so it is no fallback.
        storage.inner.delete("crlite/compat/$g1/records.json")
        assertIs<StoreRead.Found<*>>(store.readMeta(g1))
        val r = assertIs<InstallResult.Installed>(install(pending("g2", timestamp = 2_000_000_000_000)))
        assertEquals(1, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.directory, null)), store.pointer())
    }

    @Test
    fun `a malformed pointer or a pointed directory without meta json counts a store failure`() {
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val r = assertIs<InstallResult.Installed>(install(pending("g1")))
        assertEquals(1, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.directory, null)), store.pointer())
        val missing = GenerationNames.directory(1, "gone")
        storage.inner.write(
            "crlite/compat/current",
            "{\"live\":\"$missing\",\"previous\":\"${r.directory}\"}".encodeToByteArray(),
        )
        val r2 = assertIs<InstallResult.Installed>(install(pending("g2", timestamp = 2_000_000_000_000)))
        assertEquals(1, r2.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r2.directory, r.directory)), store.pointer())
    }

    @Test
    fun `a filter that does not decode fails in the engine's prepare, ENGINE_FAILED, and nothing installs`() {
        // The engine's prepare is the install's one decode: the loader no longer decodes the filters itself.
        val p = pending()
        val garbage = byteArrayOf(4, 0, 0)
        for (name in p.deltas.keys) store.stageFile(p.meta.directory, name, garbage)
        val hashes = p.deltas.mapValues { garbage.toByteString().sha256() }
        val f = failed(install(PendingGeneration(p.meta, p.index, hashes, p.records)))
        assertEquals(SyncFailure.ENGINE_FAILED, f.failure)
        assertIs<IllegalArgumentException>(f.cause)
        assertEquals(1, f.storeFailures)
        assertEquals(listOf("g1"), engine.prepared)
        assertEquals(emptyList(), engine.closed)
        assertUntouched(p.meta.directory)
    }

    @Test
    fun `a seed install publishes fromSeed, its seedFormat and the STALE gate`() {
        val seed = Publication(true, 1, true, now)
        assertIs<InstallResult.Installed>(
            install(pending("seed", freshness = Freshness.SEED_SIGNED_TIME), publication = seed, updater = null),
        )
        val d = snapshot.snapshot.datasets.getValue(Dataset.CRLITE)
        assertEquals(true, d.fromSeed)
        assertEquals(1, d.seedFormat)
        assertEquals(true, d.staleGateOpen)
        assertEquals(Freshness.SEED_SIGNED_TIME, d.freshness)
        assertEquals(StoreRead.Absent, store.updater(now))
        for (bad in listOf({ Publication(true, null, false, now) }, { Publication(false, 1, false, now) })) {
            kotlin.test.assertFailsWith<IllegalArgumentException> { bad() }
        }
    }

    @Test
    fun `an engine whose coverageEndMillis throws publishes null`() {
        engine.coverageEnd = { error("cannot tell") }
        assertIs<InstallResult.Installed>(install(pending()))
        assertNull(snapshot.snapshot.coverageEndMillis)
    }

    @Test
    fun `GenerationMeta built from buildIndex names exactly the placed fulls`() {
        val p = pending()
        val meta: GenerationMeta = p.meta
        assertEquals(setOf(fullRecord.filename), meta.blobs.keys)
        assertEquals(setOf(deltaRecord.filename), p.deltas.keys)
    }
}
