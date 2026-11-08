// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.RevoktStorage
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.UpdateFixtures.deltaRecord
import dev.revokt.engine.update.UpdateFixtures.fullRecord
import dev.revokt.engine.update.UpdateFixtures.log
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The §6.5 install order (#130): nothing is live before every check passes; a failure leaves the previous generation. */
class InstallTest {
    /** A storage whose writes a test can fail or observe, key by key. */
    private class Faulty(
        val inner: RevoktStorage = RevoktStorage.inMemory(),
    ) : RevoktStorage by inner {
        var fail: (String) -> Throwable? = { null }
        var onWrite: (String) -> Unit = {}
        val writes = mutableListOf<String>()

        override fun write(
            name: String,
            bytes: ByteArray,
        ) {
            fail(name)?.let { throw it }
            onWrite(name)
            writes += name.removePrefix("crlite/compat/")
            inner.write(name, bytes)
        }
    }

    private val storage = Faulty()
    private val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
    private val engine = TestEngine()
    private val logger = UpdateFixtures.Recording()
    private val empty =
        GenerationSnapshot(
            0,
            mapOf(Dataset.CRLITE to DatasetGeneration(null, null, null, false, null, null, true, false, false)),
            null,
        )
    private val snapshot = SnapshotRef(empty)
    private val now = 1_792_600_000_000
    private val publication = Publication(false, null, false, now, 600_000)

    private fun install(
        pending: PendingGeneration,
        engine: TestEngine = this.engine,
        publication: Publication = this.publication,
        updater: UpdaterRecord? = UpdaterRecord(watermarkMillis = 1),
    ): InstallResult = install(pending, engine, store, snapshot, publication, updater, logger)

    private fun pending(
        id: String = "g1",
        trustClass: TrustClass = TrustClass.SIGNED,
        timestamp: Long = 1_792_587_631_204,
    ) = UpdateFixtures.pending(store, trustClass = trustClass, generationId = id, sourceTimestampMillis = timestamp)

    private fun failed(result: InstallResult): InstallResult.Failed = assertIs<InstallResult.Failed>(result)

    private fun keysOf(directory: String): List<String> = storage.names().filter { it.contains("/$directory/") }

    /** The engine, the snapshot and the pointer are as they were, and [directory] is gone. */
    private fun assertUntouched(
        directory: String,
        live: String? = null,
        published: GenerationSnapshot = empty,
    ) {
        assertEquals(live, engine.live)
        assertSame(published, snapshot.snapshot)
        assertEquals(emptyList(), keysOf(directory))
        if (live == null) assertEquals(StoreRead.Absent, store.pointer())
    }

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
        assertEquals(
            listOf(
                "$dir/index.bin",
                "$dir/${deltaRecord.filename}",
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
                TrustClass.SIGNED,
                Freshness.RECORD_LAST_MODIFIED,
                fromSeed = false,
                sourceTimestampMillis = 1_792_587_631_204,
                seedFormat = null,
                pending = false,
                staleGateOpen = false,
                clockBehind = false,
            ),
            s.datasets.getValue(Dataset.CRLITE),
        )
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
    fun `a constant-answer engine fails the self-check, and the live engine generation and the snapshot stay`() {
        assertIs<InstallResult.Installed>(install(pending("g1")))
        val published = snapshot.snapshot
        val pointer = store.pointer()
        for (constant in listOf(CrliteQueryResult.NOT_REVOKED, CrliteQueryResult.REVOKED)) {
            engine.preparedAnswer = { constant }
            val p = pending("g2", timestamp = 1_792_587_631_205)
            val f = failed(install(p))
            assertEquals(SyncOutcome.FAILED, f.outcome)
            assertEquals(SyncStage.SELF_CHECK, f.stage)
            assertEquals(DiagnosticCode.ENGINE_SELF_CHECK_FAILED, f.code)
            assertEquals(1, f.storeFailures)
            assertEquals(false, f.activated)
            assertUntouched(p.meta.directory, live = "g1", published = published)
            assertEquals(pointer, store.pointer())
            assertEquals("g2", engine.closed.last())
        }
    }

    @Test
    fun `a probe that throws fails the self-check as an engine error`() {
        engine.preparedAnswer = { error("broken") }
        val f = failed(install(pending()))
        assertEquals(SyncStage.SELF_CHECK, f.stage)
        assertEquals(DiagnosticCode.ENGINE_SELF_CHECK_FAILED, f.code)
    }

    @Test
    fun `a prepare or activate that throws fails at its stage and leaves everything as it was`() {
        assertIs<InstallResult.Installed>(install(pending("g1")))
        val published = snapshot.snapshot
        val cases =
            listOf(
                SyncStage.PREPARE to IllegalArgumentException("corrupt"),
                SyncStage.PREPARE to OutOfMemoryError("prepare"),
                SyncStage.ACTIVATE to IllegalStateException("closed"),
                SyncStage.ACTIVATE to OutOfMemoryError("activate"),
            )
        for ((stage, thrown) in cases) {
            val e = TestEngine(inner = engine.inner)
            val fail = { throw thrown }
            if (stage == SyncStage.PREPARE) e.onPrepare = { fail() } else e.onActivate = fail
            val p = pending("g2", timestamp = 1_792_587_631_205)
            val f = failed(install(p, e))
            assertEquals(SyncOutcome.FAILED, f.outcome, "$thrown")
            assertEquals(stage, f.stage, "$thrown")
            assertEquals(null, f.code)
            assertEquals(thrown::class, assertNotNull(f.cause)::class)
            assertEquals(1, f.storeFailures)
            assertUntouched(p.meta.directory, live = "g1", published = published)
            if (stage == SyncStage.ACTIVATE) assertEquals(listOf("g2"), e.closed)
        }
    }

    @Test
    fun `a format the engine does not list is FORMAT_UNSUPPORTED at PREPARE and never offered to prepare`() {
        val v4only = TestEngine(formats = setOf(FilterFormat.V4))
        val p = pending()
        storage.writes.clear()
        val f = failed(install(p, v4only))
        assertEquals(SyncOutcome.FAILED, f.outcome)
        assertEquals(SyncStage.PREPARE, f.stage)
        assertEquals(DiagnosticCode.FORMAT_UNSUPPORTED, f.code)
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
        assertEquals(SyncOutcome.FAILED, f.outcome)
        assertEquals(SyncStage.INDEX, f.stage)
        assertEquals(DiagnosticCode.INDEX_INCONSISTENT, f.code)
        assertEquals(0, f.storeFailures)
        assertEquals(emptyList(), storage.writes)
        assertEquals(emptyList(), engine.prepared)
        val system = pending(trustClass = TrustClass.SYSTEM)
        val read = PendingGeneration(system.meta, over.index, system.deltas, null)
        assertEquals(DiagnosticCode.STORE_UNREADABLE, failed(install(read)).code)
        // C2SP's reader allows trailing bytes, so zero padding makes a valid index of exactly the cap.
        val atCap =
            PendingGeneration(p.meta, p.index + ByteArray(C2spIndex.MAX_BYTES - p.index.size), p.deltas, p.records)
        assertIs<InstallResult.Installed>(install(atCap))
    }

    @Test
    fun `a store write that throws is STORE_FAILED, deletes what it wrote, and offers nothing to the engine`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/records.json")) IllegalStateException("disk full") else null }
        val f = failed(install(p))
        assertEquals(SyncOutcome.STORE_FAILED, f.outcome)
        assertEquals(SyncStage.STORE, f.stage)
        assertEquals(1, f.storeFailures)
        assertEquals(emptyList(), engine.prepared)
        assertUntouched(p.meta.directory)
        storage.fail = { if (it.endsWith("/meta.json")) OutOfMemoryError("store") else null }
        val oom = failed(install(p))
        assertEquals(SyncOutcome.FAILED, oom.outcome)
        assertEquals(SyncStage.STORE, oom.stage)
        assertEquals(1, oom.storeFailures)
        assertUntouched(p.meta.directory)
    }

    @Test
    fun `a pointer flip or updater write that throws after the publish is STORE_FAILED with the generation live`() {
        val p = pending()
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        val f = failed(install(p))
        assertEquals(SyncOutcome.STORE_FAILED, f.outcome)
        assertEquals(SyncStage.STORE, f.stage)
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
        assertEquals(StoreRead.Found(Pointer(g2.meta.directory, null)), store.pointer())
    }

    @Test
    fun `an install over a complete directory fails and leaves it in place`() {
        val p = pending()
        assertIs<InstallResult.Installed>(install(p))
        val published = snapshot.snapshot
        val f = failed(install(pending()))
        assertEquals(SyncOutcome.STORE_FAILED, f.outcome)
        assertEquals(SyncStage.STORE, f.stage)
        assertNotNull(store.readGeneration(p.meta.directory))
        assertSame(published, snapshot.snapshot)
        assertEquals(StoreRead.Found(Pointer(p.meta.directory, null)), store.pointer())
    }

    @Test
    fun `previous is the old live or previous generation of the same or a higher trust class`() {
        fun dir(r: InstallResult) = assertIs<InstallResult.Installed>(r).directory
        val g1 = dir(install(pending("g1")))
        val g2 = dir(install(pending("g2", timestamp = 2_000_000_000_000)))
        assertEquals(StoreRead.Found(Pointer(g2, g1)), store.pointer())
        val g3 = dir(install(pending("g3", TrustClass.MIRROR, 2_000_000_000_001)))
        assertEquals(StoreRead.Found(Pointer(g3, g2)), store.pointer())
        // The live MIRROR generation ranks below SIGNED, so the SIGNED previous stays previous.
        val g4 = dir(install(pending("g4", timestamp = 2_000_000_000_002)))
        assertEquals(StoreRead.Found(Pointer(g4, g2)), store.pointer())
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
    fun `a SYSTEM generation whose index is not selection-equivalent to its filters is STORE_UNREADABLE`() {
        val p = pending(trustClass = TrustClass.SYSTEM)
        val wrong =
            C2spIndex.write(
                C2spIndex.index(
                    C2spIndex.read(p.index).filenames.map { it to mapOf(log(1) to Window(1u, 2u)) },
                ),
            )
        val f = failed(install(PendingGeneration(p.meta, wrong, p.deltas, null)))
        assertEquals(SyncStage.INDEX, f.stage)
        assertEquals(DiagnosticCode.STORE_UNREADABLE, f.code)
        assertEquals(emptyList(), engine.prepared)
        assertUntouched(p.meta.directory)
        assertIs<InstallResult.Installed>(install(p))
    }

    @Test
    fun `a filter the loader cannot decode fails at PREPARE before the engine sees it`() {
        val p = pending(trustClass = TrustClass.SYSTEM)
        val garbage = p.deltas.mapValues { byteArrayOf(4, 0, 0) }
        val f = failed(install(PendingGeneration(p.meta, p.index, garbage, null)))
        assertEquals(SyncOutcome.FAILED, f.outcome)
        assertEquals(SyncStage.PREPARE, f.stage)
        assertEquals(1, f.storeFailures)
        assertEquals(emptyList(), engine.prepared)
        assertUntouched(p.meta.directory)
    }

    @Test
    fun `clockBehind is recomputed at the publish against now and clockSkew`() {
        val ts = now + 600_000
        assertIs<InstallResult.Installed>(install(pending("g1", timestamp = ts)))
        assertEquals(
            false,
            snapshot.snapshot.datasets
                .getValue(Dataset.CRLITE)
                .clockBehind,
        )
        assertIs<InstallResult.Installed>(install(pending("g2", timestamp = ts + 1)))
        assertEquals(
            true,
            snapshot.snapshot.datasets
                .getValue(Dataset.CRLITE)
                .clockBehind,
        )
    }

    @Test
    fun `a seed install publishes fromSeed, its seedFormat and the STALE gate`() {
        val seed = Publication(true, 1, true, now, 0)
        assertIs<InstallResult.Installed>(
            install(pending("seed", TrustClass.BUNDLED), publication = seed, updater = null),
        )
        val d = snapshot.snapshot.datasets.getValue(Dataset.CRLITE)
        assertEquals(true, d.fromSeed)
        assertEquals(1, d.seedFormat)
        assertEquals(true, d.staleGateOpen)
        assertEquals(Freshness.SEED_SIGNED_TIME, d.freshness)
        assertEquals(StoreRead.Absent, store.updater(now))
        for (bad in listOf({
            Publication(true, null, false, now, 0)
        }, { Publication(false, 1, false, now, 0) }, { Publication(false, null, false, now, -1) })) {
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
