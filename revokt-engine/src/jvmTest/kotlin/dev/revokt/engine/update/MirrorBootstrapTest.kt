// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.RevoktLimits
import dev.revokt.RevoktStorage
import dev.revokt.Rule
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.evaluate.dataStates
import dev.revokt.engine.fetch.C2spMirrorClient
import dev.revokt.engine.fetch.C2spMirrorSource
import dev.revokt.engine.fetch.ImfFixdate
import dev.revokt.engine.fetch.ScriptedFetcher
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.Preset
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.UpdateFixtures.log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * §7.3 "Bootstrap only" for the C2SP mirror loader (#194, #207's reviews): the sync runs only when the dataset has no
 * generation above `MIRROR`, live or stored, and fails closed whenever the store cannot tell; when it does not run it
 * returns null, fetches nothing and writes nothing (the maintainer's decision, Q1). The mirror rows of §9 (c) are named
 * `fixture (c)`, as in [MirrorSyncTest].
 */
internal class MirrorBootstrapTest : MirrorSyncFixture() {
    @Test
    fun `fixture (c) - a live SIGNED generation, a seed or a stored one, stops the mirror, which does not run`() {
        val mirror = Mirror(listOf("a.filter" to filter(1)))
        for (fromSeed in listOf(false, true)) {
            snapshot.publish(
                GenerationSnapshot(
                    1,
                    mapOf(
                        Dataset.CRLITE to
                            empty.copy(
                                generationId = "1/x",
                                trustClass = TrustClass.SIGNED,
                                sourceTimestampMillis = 1,
                                fromSeed = fromSeed,
                            ),
                    ),
                    null,
                ),
            )
            // Not UNCHANGED: no result at all, which the loader never publishes (the maintainer's decision, Q1).
            assertNull(attempt(mirror))
            assertTrue(mirror.fetcher.requests.isEmpty())
            assertTrue(storage.names().isEmpty(), "updater.json is not written either")
        }
        // A stored SIGNED generation the pointer names, though the snapshot holds none, stops it too.
        snapshot.publish(GenerationSnapshot(2, mapOf(Dataset.CRLITE to empty), null))
        val signed = UpdateFixtures.pending(store)
        store.writeGeneration(signed.meta, signed.index, staged(signed), signed.records)
        store.point(Pointer(signed.meta.directory, null))
        assertNull(attempt(mirror))
        assertTrue(mirror.fetcher.requests.isEmpty())
    }

    @Test
    fun `a store read that throws during the bootstrap check is STORE_FAILED and leaves updater json byte-identical`() {
        for (failing in listOf("/meta.json", "/current")) {
            storage.names().forEach(storage::delete)
            realUpdater()
            val live = stored(TrustClass.MIRROR, "m-live")
            store.point(Pointer(live, null))
            stored(TrustClass.MIRROR, "m-other")
            storage.failRead = { it.endsWith(failing) }
            assertStopped(Mirror(listOf("a.filter" to filter(1))), null) { run ->
                checkNotNull(run).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed())
                assertEquals(1, run.storeFailures, failing)
            }
            storage.failRead = { false }
            assertEquals(1_700_000_000_000, updater().watermarkMillis, failing)
        }
    }

    @Test
    fun `an updater json read that throws writes nothing over it`() {
        realUpdater()
        storage.failRead = { it.endsWith("/updater.json") }
        assertStopped(Mirror(listOf("a.filter" to filter(1))), null) { run ->
            checkNotNull(run).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed())
        }
    }

    @Test
    fun `fixture (c) - a malformed pointer stops the mirror, and the stored SIGNED generation survives`() {
        realUpdater()
        val signed = stored(TrustClass.SIGNED, "1792587631204/s")
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        assertStopped(Mirror(listOf("a.filter" to filter(1))), signed)
        // With no generation stored at all, a malformed pointer still fails closed.
        storage.names().filter { "/gen-" in it }.forEach(storage::delete)
        assertStopped(Mirror(listOf("a.filter" to filter(1))), null)
    }

    @Test
    fun `fixture (c) - a pointed directory whose meta json is missing or malformed stops the mirror`() {
        val mirror = Mirror(listOf("a.filter" to filter(1)))
        // Two MIRROR generations, so no SIGNED one elsewhere in the store stops the mirror instead.
        val live = stored(TrustClass.MIRROR, "m-live")
        val previous = stored(TrustClass.MIRROR, "m-previous")
        store.point(Pointer(live, previous))
        for (pointed in listOf(live, previous)) {
            val key = store.fileKey(pointed, StoreLayout.META)
            val meta = checkNotNull(storage.read(key))
            for (broken in listOf(null, "{".encodeToByteArray())) {
                if (broken == null) storage.delete(key) else storage.inner.write(key, broken)
                assertStopped(mirror, null)
            }
            storage.inner.write(key, meta)
        }
    }

    @Test
    fun `fixture (c) - a SIGNED previous behind a MIRROR or SYSTEM live stops the mirror`() {
        for (lower in listOf(TrustClass.MIRROR, TrustClass.SYSTEM)) {
            storage.names().forEach(storage::delete)
            val live = stored(lower, "low-$lower")
            val signed = stored(TrustClass.SIGNED, "1792587631204/s")
            store.point(Pointer(live, signed))
            assertStopped(Mirror(listOf("a.filter" to filter(1))), signed)
        }
    }

    @Test
    fun `fixture (c) - a stored SIGNED generation the pointer does not name stops the mirror and survives`() {
        val mirror = Mirror(listOf("a.filter" to filter(1)))
        val signed = stored(TrustClass.SIGNED, "1792587631204/s")
        assertStopped(mirror, signed)
        // Beside a pointed MIRROR generation too, and a directory whose meta json is malformed counts as one.
        storage.delete(store.fileKey(signed, StoreLayout.META))
        val live = stored(TrustClass.MIRROR, "m-live")
        store.point(Pointer(live, null))
        val other = stored(TrustClass.SIGNED, "1792587631205/t")
        assertStopped(mirror, other)
        storage.inner.write(store.fileKey(other, StoreLayout.META), "{".encodeToByteArray())
        assertStopped(mirror, null)
        // An interrupted install (no meta json) says nothing, so the mirror then runs.
        storage.delete(store.fileKey(other, StoreLayout.META))
        sync(mirror).assert(SyncOutcome.INSTALLED)
    }

    @Test
    fun `fixture (c) - a live SYSTEM generation does not stop the mirror, which ranks above it`() {
        snapshot.publish(
            GenerationSnapshot(
                1,
                mapOf(
                    Dataset.CRLITE to
                        empty.copy(generationId = "sys", trustClass = TrustClass.SYSTEM, sourceTimestampMillis = 1),
                ),
                null,
            ),
        )
        sync(Mirror(listOf("a.filter" to filter(1)))).assert(SyncOutcome.INSTALLED)
        assertEquals(TrustClass.MIRROR, live().trustClass)
    }
}
