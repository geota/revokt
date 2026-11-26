// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.LogLevel
import dev.revokt.SyncFailure
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.json.CanonicalJson
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.UpdateFixtures.deltaRecord
import dev.revokt.engine.update.UpdateFixtures.fullRecord
import dev.revokt.engine.update.UpdateFixtures.log
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The §6.5 install order over the content-addressed store (#130, #287): nothing is live before every check passes, a
 * failure leaves the previous generation, and an install deletes nothing.
 */
internal class InstallTest : InstallFixture() {
    private val generationId = "$TS/${deltaRecord.id}"

    @Test
    fun `a generation installs in the 6_5 order and is published, pointed to and recorded`() {
        val p = pending()
        storage.writes.clear()
        val r = installed(install(p))
        val name = nameOf(p)
        assertEquals(name, r.name)
        assertEquals(generationId, r.generationId)
        assertEquals(1, r.generationEpoch)
        assertEquals(0, r.storeFailures)
        assertEquals(false, r.healed)
        assertEquals(false, r.prunable, "an absent pointer before the install: no prune")
        // The blobs were written before the install (UpdateFixtures.pending, as the sync writes each body it fetches).
        assertEquals(listOf("generations/$name", "current", "updater.json"), storage.writes)
        assertEquals(generationId, engine.live)
        assertEquals(StoreRead.Found(Pointer(name, null)), store.pointer())
        assertEquals(1L, (store.updater(now) as StoreRead.Found).value.record.watermarkMillis)
        val s = snapshot.snapshot
        assertEquals(1, s.generationEpoch)
        assertEquals(engine.inner.coverageEndMillis, s.coverageEndMillis)
        assertNotNull(s.coverageEndMillis)
        assertEquals(
            DatasetGeneration(
                generationId,
                Freshness.RECORD_LAST_MODIFIED,
                fromSeed = false,
                sourceTimestampMillis = TS,
                seedFormat = null,
                pending = false,
                staleGateOpen = false,
                generationFile = name,
            ),
            s.datasets.getValue(Dataset.CRLITE),
        )
        assertEquals(emptyList(), storage.deletes)
    }

    @Test
    fun `the generation file holds the verified records and signature, and no index, meta json or directory`() {
        val p = pending()
        val r = installed(install(p))
        val keys = storage.names().map { it.removePrefix("crlite/compat/") }.toSet()
        val blobs = listOf(fullRecord, deltaRecord).map { "blobs/" + sha(it) }
        assertEquals(setOf("generations/${r.name}", "current", "updater.json") + blobs, keys)
        val file = (store.readGeneration(r.name) as StoreRead.Found).value
        assertContentEquals(p.file.payload, file.payload)
        assertEquals(TS, file.lastModified)
        assertEquals(ByteArray(96) { 9 }.toByteString(), file.signature)
    }

    @Test
    fun `33- and 64-character names are the derived names in index bin and GenerationFiles, never a key`() {
        val long33 = "20261021-123-compat.filter.deltax"
        val long64 = "20261017-1-compat-full-filter-with-a-very-long-name-0123456.filt"
        val window = listOf(log(1) to (1_000L to 2_000L))
        val bodies = mapOf(long64 to UpdateFixtures.v4(window), long33 to UpdateFixtures.v4(window))
        val records =
            listOf(FilterRecord("f", "compat", false, 1, long64), FilterRecord("d", "compat", true, 2, long33))
        val p = UpdateFixtures.pending(store, records, bodies, format = FilterFormat.V4)
        val r = installed(install(p))
        val full = GenerationNames.derive(long64)
        val delta = GenerationNames.derive(long33)
        val loaded = assertIs<GenerationLoad.Loaded>(store.load(r.name)).value
        assertEquals(listOf(full, delta), C2spIndex.read(loaded.files.bytes("index.bin")).filenames)
        assertEquals(setOf("index.bin", full, delta), loaded.files.names)
        val keys = storage.names().joinToString()
        assertTrue(long64 !in keys && long33 !in keys && full !in keys && delta !in keys, keys)
    }

    @Test
    fun `the epoch advances once per install, after activate and before the pointer flip`() {
        val atActivate = mutableListOf<Long>()
        val atFlip = mutableListOf<Long>()
        engine.onActivate = { atActivate += snapshot.snapshot.generationEpoch }
        storage.onWrite = { if (it.endsWith("/current")) atFlip += snapshot.snapshot.generationEpoch }
        installed(install(pending()))
        installed(install(pending(TS + 1)))
        assertEquals(listOf(0L, 1L), atActivate)
        assertEquals(listOf(1L, 2L), atFlip)
        assertEquals(2, snapshot.snapshot.generationEpoch)
    }

    @Test
    fun `the install never queries the prepared generation, so a constant-answer engine installs`() {
        engine.preparedAnswer = { error("the install queried the prepared generation") }
        val r = installed(install(pending()))
        assertEquals(generationId, r.generationId)
        assertEquals(generationId, engine.live)
    }

    @Test
    fun `an engine that cannot tell its coverage end, or whose getter throws, publishes none`() {
        installed(install(pending(), engine = TestEngine().apply { coverageEnd = { null } }))
        assertNull(snapshot.snapshot.coverageEndMillis)
        installed(install(pending(TS + 1), engine = TestEngine().apply { coverageEnd = { error("cannot tell") } }))
        assertNull(snapshot.snapshot.coverageEndMillis)
    }

    @Test
    fun `a prepare or activate that throws is ENGINE_FAILED, deletes nothing and leaves everything as it was`() {
        installed(install(pending()))
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
            val p = pending(TS + 1)
            val f = failed(install(p, e))
            assertEquals(SyncFailure.ENGINE_FAILED, f.failure, "$thrown")
            assertEquals(thrown::class, assertNotNull(f.cause)::class)
            assertEquals(1, f.storeFailures)
            assertEquals(false, f.activated)
            assertUntouched(live = generationId, published = published)
            assertEquals(pointer, store.pointer())
            // The failed generation's file stays, named by no pointer, for the retry to reuse.
            assertIs<StoreRead.Found<*>>(store.readGeneration(nameOf(p)))
            if (!inPrepare) assertEquals(listOf("${TS + 1}/${deltaRecord.id}"), e.closed)
        }
    }

    @Test
    fun `an InterruptedException from prepare or activate fails the install and keeps the interrupt`() {
        installed(install(pending()))
        val published = snapshot.snapshot
        for (stage in listOf("prepare", "activate")) {
            val e = TestEngine(inner = engine.inner)
            val interrupt = { throw InterruptedException(stage) }
            if (stage == "prepare") e.onPrepare = { interrupt() } else e.onActivate = interrupt
            try {
                val f = failed(install(pending(TS + 1), e))
                assertEquals(SyncFailure.ENGINE_FAILED, f.failure, stage)
                assertIs<InterruptedException>(f.cause)
                assertTrue(Thread.currentThread().isInterrupted, "the interrupt flag is restored at $stage")
            } finally {
                Thread.interrupted()
            }
            assertUntouched(live = generationId, published = published)
        }
    }

    @Test
    fun `a format the engine does not list is FORMAT_UNSUPPORTED, never offered to prepare, nothing written`() {
        val v4only = TestEngine(formats = setOf(FilterFormat.V4))
        val p = pending()
        storage.writes.clear()
        val f = failed(install(p, v4only))
        assertEquals(SyncFailure.FORMAT_UNSUPPORTED, f.failure)
        assertEquals(0, f.storeFailures)
        assertEquals(emptyList(), v4only.prepared)
        assertEquals(emptyList(), storage.writes)
        assertUntouched()
    }

    @Test
    fun `an index over 1 MiB fails before the generation file is written, and one of exactly 1 MiB installs`() {
        val p = pending()
        val over =
            PendingGeneration(p.file, p.placed, p.index + ByteArray(C2spIndex.MAX_BYTES + 1 - p.index.size), p.format)
        storage.writes.clear()
        val f = failed(install(over))
        assertEquals(SyncFailure.INDEX_INCONSISTENT, f.failure)
        assertEquals(0, f.storeFailures)
        assertEquals(emptyList(), storage.writes)
        assertEquals(emptyList(), engine.prepared)
        // C2SP's reader allows trailing bytes, so zero padding makes a valid index of exactly the cap.
        val atCap =
            PendingGeneration(p.file, p.placed, p.index + ByteArray(C2spIndex.MAX_BYTES - p.index.size), p.format)
        installed(install(atCap))
    }

    @Test
    fun `a generation file over maxJsonBytes plus 64 KiB is STORE_FAILED before it is written, with a warning`() {
        val small = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT, maxJsonBytes = 1)
        val records = listOf(fullRecord, deltaRecord)
        val json =
            UpdateFixtures.recordsJson(records).map {
                // A member the schema does not read, to grow the file past the cap.
                val text = CanonicalJson.write(it).decodeToString().dropLast(1) + ",\"pad\":\"${"x".repeat(40_000)}\"}"
                Json.parse(text.encodeToByteArray()) as JsonObject
            }
        val p = UpdateFixtures.pending(small, records, json = json)
        storage.writes.clear()
        val f = failed(install(p, engine, small))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals(1, f.storeFailures)
        assertEquals(emptyList(), storage.writes)
        assertEquals(emptyList(), engine.prepared)
        val warning = logger.messages.single { it.first == LogLevel.WARN }.second
        assertTrue("maxJsonBytes" in warning, warning)
        // The default cap holds it.
        installed(install(p))
    }

    private fun install(
        p: PendingGeneration,
        engine: TestEngine,
        layout: StoreLayout,
    ): InstallResult = install(p, engine, layout, snapshot, publication, null, logger)

    @Test
    fun `a store write that throws is STORE_FAILED, deletes nothing, and offers nothing to the engine`() {
        val p = pending()
        storage.fail = { if ("/generations/" in it) IllegalStateException("disk full") else null }
        val f = failed(install(p))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals(1, f.storeFailures)
        assertEquals(emptyList(), engine.prepared)
        assertUntouched()
        storage.fail = { if ("/generations/" in it) OutOfMemoryError("store") else null }
        val oom = failed(install(pending()))
        assertEquals(SyncFailure.INTERNAL_ERROR, oom.failure)
        assertEquals(1, oom.storeFailures)
        assertUntouched()
    }

    @Test
    fun `a generation that does not load back is STORE_FAILED, never offered to the engine, nothing deleted`() {
        val p = pending()
        // A blob gone between the body write and the install: the load-back re-hashes every blob.
        storage.inner.delete(
            store.blobKey(
                UpdateFixtures.bodies
                    .getValue(deltaRecord.filename)
                    .toByteString()
                    .sha256(),
            ),
        )
        val f = failed(install(p))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals(1, f.storeFailures)
        assertEquals(emptyList(), engine.prepared)
        assertUntouched()
        // A rotted blob: the same.
        val rotted = pending(TS + 1)
        val key =
            store.blobKey(
                UpdateFixtures.bodies
                    .getValue(fullRecord.filename)
                    .toByteString()
                    .sha256(),
            )
        storage.inner.write(key, byteArrayOf(1, 2, 3))
        assertEquals(SyncFailure.STORE_FAILED, failed(install(rotted)).failure)
        assertUntouched()
    }

    @Test
    fun `a stored generation file that does not re-hash is written again, and the install proceeds`() {
        val p = pending()
        val name = nameOf(p)
        storage.inner.write(store.generationKey(name), "{}".encodeToByteArray())
        storage.writes.clear()
        installed(install(p))
        assertEquals("generations/$name", storage.writes.first())
        assertIs<StoreRead.Found<*>>(store.readGeneration(name))
    }

    @Test
    fun `a pointer flip or updater write that throws after the publish is STORE_FAILED with the generation live`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        val f = failed(install(p))
        assertEquals(SyncFailure.STORE_FAILED, f.failure)
        assertEquals(true, f.activated)
        assertEquals(1, f.storeFailures)
        assertEquals(generationId, engine.live)
        assertEquals(1, snapshot.snapshot.generationEpoch)
        assertEquals(StoreRead.Absent, store.pointer())
        storage.fail = { if (it.endsWith("/updater.json")) IllegalStateException("updater") else null }
        val g2 = pending(TS + 1)
        assertEquals(true, failed(install(g2)).activated)
        // g1, which the engine served although no pointer named it, is the fallback (#249).
        assertEquals(StoreRead.Found(Pointer(nameOf(g2), nameOf(p))), store.pointer())
        assertEquals(emptyList(), storage.deletes)
    }

    @Test
    fun `a retry after a flip that failed finds its generation file and blobs stored, so it only flips`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        assertEquals(true, failed(install(p)).activated)
        storage.fail = { null }
        storage.writes.clear()
        val r = installed(install(pending()))
        assertEquals(listOf("current", "updater.json"), storage.writes)
        assertEquals(2, r.generationEpoch)
        assertEquals(StoreRead.Found(Pointer(r.name, null)), store.pointer(), "the served generation is the new live")
    }

    @Test
    fun `a collection re-signed under the same ts is another file under another name, and installs`() {
        val a = installed(install(pending()))
        val b = installed(install(pending(signature = ByteArray(96) { 8 })))
        assertTrue(a.name != b.name)
        assertEquals(a.generationId, b.generationId)
        assertEquals(StoreRead.Found(Pointer(b.name, a.name)), store.pointer())
    }

    @Test
    fun `previous is the old live generation`() {
        val g1 = installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        assertEquals(StoreRead.Found(Pointer(g2.name, g1.name)), store.pointer())
        assertEquals(true, g2.prunable)
        assertEquals(0, g2.storeFailures)
    }

    @Test
    fun `a pointed previous that does not read counts a store failure even beside a qualifying live (#249)`() {
        val g1 = installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        storage.inner.delete(store.generationKey(g1.name))
        val r = installed(install(pending(TS + 2)))
        assertEquals(1, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.name, g2.name)), store.pointer())
        assertEquals(false, r.prunable, "a pointed generation that did not read: prune deletes nothing (B2)")
    }

    @Test
    fun `a served generation the pointer also names is read once, so its fault counts once (#249)`() {
        val g1 = installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        // g2 is both served and the pointer's live; its file is gone, so the fallback is the pointer's previous.
        storage.inner.delete(store.generationKey(g2.name))
        val r = installed(install(pending(TS + 2)))
        assertEquals(1, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.name, g1.name)), store.pointer())
    }

    @Test
    fun `a pointed generation whose blob is damaged passes steps 1 and 2 but is no previous, counted`() {
        // g1 has its own full, so the next install does not rewrite g1's blob.
        val other = UpdateFixtures.v4(listOf(log(1) to (1_000L to 2_000L)))
        val records = listOf(FilterRecord("f1", "compat", false, 1, "full-1.filter"))
        val g1 =
            installed(
                install(
                    UpdateFixtures.pending(store, records, mapOf("full-1.filter" to other), format = FilterFormat.V4),
                ),
            )
        val g2 = installed(install(pending(TS + 1)))
        storage.inner.write(store.blobKey(other.toByteString().sha256()), byteArrayOf(9))
        // g2, served and live, loses its file (counted once); g1, the pointer's previous, has a rotted blob (counted).
        storage.inner.delete(store.generationKey(g2.name))
        val r = installed(install(pending(TS + 2)))
        assertEquals(2, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.name, null)), store.pointer())
        assertEquals(false, r.prunable, "g2 failed steps 1 and 2")
        assertIs<StoreRead.Found<*>>(store.stored(g1.name), "g1 itself still reads: only its blob is bad")
    }

    @Test
    fun `a flip that failed after activation keeps the generation the engine served as the next previous (#249)`() {
        val g1 = installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        val p3 = pending(TS + 2)
        assertEquals(true, failed(install(p3)).activated)
        assertEquals(StoreRead.Found(Pointer(g2.name, g1.name)), store.pointer())
        storage.fail = { null }
        val g4 = installed(install(pending(TS + 3)))
        assertEquals(StoreRead.Found(Pointer(g4.name, nameOf(p3))), store.pointer())
    }

    @Test
    fun `beside a malformed pointer the flip heals it, counted once, with only the served generation as previous`() {
        val g1 = installed(install(pending()))
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val r = installed(install(pending(TS + 1)))
        assertEquals(true, r.healed)
        assertEquals(false, r.prunable)
        assertEquals(1, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.name, g1.name)), store.pointer())
        // A fresh loader (nothing served) beside a malformed pointer has no previous.
        storage.inner.write("crlite/compat/current", "{\"live\":1}".encodeToByteArray())
        val fresh =
            installed(install(pending(TS + 2), TestEngine(), store, SnapshotRef(empty), publication, null, logger))
        assertEquals(StoreRead.Found(Pointer(fresh.name, null)), store.pointer())
        assertEquals(true, fresh.healed)
    }

    @Test
    fun `a pointer whose previous member name is damaged is malformed, so nothing it named is lost (#246)`() {
        val g1 = installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        val text = "{\"live\":\"${g2.name}\",\"previouz\":\"${g1.name}\"}"
        storage.inner.write("crlite/compat/current", text.encodeToByteArray())
        assertEquals(StoreRead.Malformed, store.pointer())
        val r = installed(install(pending(TS + 2)))
        assertEquals(true, r.healed)
        assertEquals(false, r.prunable)
        assertIs<StoreRead.Found<*>>(store.readGeneration(g1.name))
    }

    @Test
    fun `a caller that counted the pointer's faults has them not counted again`() {
        installed(install(pending()))
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val counted = Publication(false, null, false, now, pointerCounted = true)
        assertEquals(0, installed(install(pending(TS + 1), publication = counted)).storeFailures)
    }

    @Test
    fun `a filter that does not decode fails in the engine's prepare, ENGINE_FAILED, and nothing installs`() {
        // The engine's prepare is the install's one decode; the index here is the one built from the good bytes.
        val p = pending()
        val garbage = byteArrayOf(4, 0, 0)
        val bodies = UpdateFixtures.bodies + (deltaRecord.filename to garbage)
        val records = UpdateFixtures.recordsJson(listOf(fullRecord, deltaRecord), bodies)
        store.putBlob(garbage)
        val bad = PendingGeneration(UpdateFixtures.file(records, TS), p.placed, p.index, p.format)
        val f = failed(install(bad))
        assertEquals(SyncFailure.ENGINE_FAILED, f.failure)
        assertIs<IllegalArgumentException>(f.cause)
        assertEquals(1, f.storeFailures)
        assertEquals(listOf(generationId), engine.prepared)
        assertEquals(emptyList(), engine.closed)
        assertUntouched()
    }

    @Test
    fun `deleting a served generation's keys cannot break serving, as the engine never reads the store`() {
        // Design note section 9: prune may delete what the engine serves once it is neither live nor previous. A
        // disk-backed GenerationFiles (§4 allows one later) would have to make prune protect the served generation; this
        // test fails if the engine ever reads the store again.
        installed(install(pending()))
        val q =
            dev.revokt.CrliteQuery
                .Builder()
                .issuerSpkiHash(ByteArray(32) { 3 })
                .serial(byteArrayOf(1, 2, 3))
                .build()
        val before = engine.query(q)
        storage.inner.names().forEach(storage.inner::delete)
        assertEquals(before, engine.query(q))
        assertEquals(generationId, engine.live)
    }

    @Test
    fun `a seed install publishes fromSeed, its seedFormat and the STALE gate`() {
        val seed = Publication(true, 1, true, now)
        installed(install(pending(freshness = Freshness.SEED_SIGNED_TIME), publication = seed, updater = null))
        val d = snapshot.snapshot.datasets.getValue(Dataset.CRLITE)
        assertEquals(true, d.fromSeed)
        assertEquals(1, d.seedFormat)
        assertEquals(true, d.staleGateOpen)
        assertEquals(Freshness.SEED_SIGNED_TIME, d.freshness)
        assertEquals(StoreRead.Absent, store.updater(now))
        for (bad in listOf({ Publication(true, null, false, now) }, { Publication(false, 1, false, now) })) {
            assertFailsWith<IllegalArgumentException> { bad() }
        }
    }

    private fun sha(r: FilterRecord): String =
        UpdateFixtures.bodies
            .getValue(r.filename)
            .toByteString()
            .sha256()
            .hex()
}
