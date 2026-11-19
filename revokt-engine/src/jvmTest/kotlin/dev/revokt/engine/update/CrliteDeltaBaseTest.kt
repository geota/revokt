// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.RevoktLimits
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.engine.fetch.json
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.log
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.engine.verify.ContentSignatureFailure
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The `_since` merge's base and the #236 malformed-pointer cases: what the sync merges a delta changeset over, or
 * fetches in full instead, when the pointer or the live generation's `meta.json` does not read (spec §6.5, §7.1).
 */
internal class CrliteDeltaBaseTest : CrliteDeltaFixture() {
    @Test
    fun `#236 - with no cursor the whole collection is verified alone, never merged over the stored records`() {
        val server = installedFirst()
        // A malformed updater.json loses the cursor; the pointed generation's records.json still reads.
        storage.inner.write("crlite/compat/updater.json", "{".encodeToByteArray())
        // The next collection drops the first delta: merged over the stored records, it would keep it and fail.
        next(server, listOf(full, delta2), listOf(tombstone))
        val now = ts2 + hour
        val run = sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertEquals(server.changesetUrl, server.fetcher.requests[1].url)
        assertEquals("$ts2/${delta2.id}", live().generationId)
    }

    @Test
    fun `#236 - a malformed pointer and a fresh loader re-serve the same ts, which installs and heals the pointer`() {
        val server = installedFirst()
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        // A fresh loader over the same store: nothing is live in its snapshot.
        freshLoader()
        server.fetcher.requests.clear()
        val run = sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertTrue(run.storeFailures >= 1, "the malformed pointer is a store failure")
        assertEquals(emptyList(), server.attachmentRequests())
        assertEquals(directory1, liveDirectory())
        assertNotNull(store.meta(directory1))
    }

    @Test
    fun `#236 - a running loader re-serving the same ts beside a malformed pointer installs, with no previous`() {
        // The retried-flip path: the target is the engine's live directory, so it is never its own previous.
        val server = installedFirst()
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        server.fetcher.requests.clear()
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Found(Pointer(directory1, null)), store.pointer())
        assertEquals(emptyList(), server.attachmentRequests())
        sync(server, now = ts + 9 * hour).assert(SyncOutcome.UNCHANGED)
    }

    @Test
    fun `#236 - beside a malformed pointer a complete directory with an altered delta fails, and is never deleted`() {
        val server = installedFirst()
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val key = "crlite/compat/$directory1/${delta.filename}"
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).also { it[0] = (it[0] + 1).toByte() })
        freshLoader()
        server.fetcher.requests.clear()

        fun files() =
            storage.inner.names().filter { "/$directory1/" in it }.associateWith {
                checkNotNull(storage.inner.read(it)).toList()
            }
        val before = files()
        repeat(2) { i ->
            sync(server, now = ts + (2 + 7 * i) * hour).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed())
            assertEquals(before, files(), "sync $i left the directory byte-identical")
        }
        assertEquals(emptyList(), server.attachmentRequests())
    }

    @Test
    fun `#236 - a running loader whose live meta json is malformed heals a new ts with no previous, counted`() {
        val server = installedFirst()
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        storage.inner.write("crlite/compat/$directory1/meta.json", "{".encodeToByteArray())
        next(server, listOf(full, delta, delta2))
        val run = sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        // One for the malformed pointer, one for the unreadable fallback candidate.
        assertEquals(2, run.storeFailures)
        val directory2 = GenerationNames.directory(ts2, "$ts2/${delta2.id}")
        assertEquals(StoreRead.Found(Pointer(directory2, null)), store.pointer())
    }

    @Test
    fun `a malformed live meta json beside a pointer that reads is fetched in full, never merged over`() {
        val server = installedFirst()
        // The pointer and records.json read; only the live generation's meta.json does not, so it is no delta base.
        storage.inner.write("crlite/compat/$directory1/meta.json", "{".encodeToByteArray())
        assertEquals(StoreRead.Found(Pointer(directory1, null)), store.pointer())
        assertNotNull(store.file(directory1, StoreLayout.RECORDS))
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        val changesets =
            server.fetcher.requests
                .map { it.url }
                .filter { it.startsWith(server.changesetUrl) }
        assertEquals(listOf(server.changesetUrl), changesets, "a full fetch, with no _since")
        assertEquals(
            StoreRead.Found(Pointer(GenerationNames.directory(ts2, "$ts2/${delta2.id}"), null)),
            store.pointer(),
        )
    }

    @Test
    fun `#236 - beside a malformed pointer a new ts installs, a running loader keeping its live one as previous`() {
        val server = installedFirst()
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        val directory2 = GenerationNames.directory(ts2, "$ts2/${delta2.id}")
        assertEquals(StoreRead.Found(Pointer(directory2, directory1)), store.pointer())
        assertNotNull(store.readGeneration(directory1))
    }

    @Test
    fun `#236 - beside a malformed pointer a fresh loader installs a new ts, the healed pointer with no previous`() {
        val server = installedFirst()
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        freshLoader()
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        val directory2 = GenerationNames.directory(ts2, "$ts2/${delta2.id}")
        assertEquals(StoreRead.Found(Pointer(directory2, null)), store.pointer())
    }

    @Test
    fun `#236 - beside a malformed pointer a directory whose meta json is malformed is held, and a new ts heals`() {
        val server = installedFirst()
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        storage.inner.write("crlite/compat/$directory1/meta.json", "{\"metaVersion\":2}".encodeToByteArray())
        freshLoader()
        server.fetcher.requests.clear()
        val before =
            storage.inner
                .names()
                .filter {
                    "/$directory1/" in it
                }.associateWith { checkNotNull(storage.inner.read(it)).toList() }
        repeat(2) { i ->
            sync(server, now = ts + (2 + 7 * i) * hour).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed())
            val after =
                storage.inner
                    .names()
                    .filter {
                        "/$directory1/" in it
                    }.associateWith { checkNotNull(storage.inner.read(it)).toList() }
            assertEquals(before, after, "sync $i left the directory byte-identical")
        }
        assertEquals(emptyList(), server.attachmentRequests())
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + 16 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(GenerationNames.directory(ts2, "$ts2/${delta2.id}"), liveDirectory())
    }

    @Test
    fun `a pointed records json of another shape is a store failure, and the sync fetches in full`() {
        for (shape in listOf("[]", "{}", """{"data":{}}""", """{"data":[1]}""")) {
            val server = installedFirst()
            storage.inner.write("crlite/compat/$directory1/records.json", shape.encodeToByteArray())
            next(server, listOf(full, delta, delta2))
            val run = sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
            assertEquals(1, run.storeFailures, shape)
            assertEquals(server.changesetUrl, server.fetcher.requests[1].url, shape)
            // Back to the first generation for the next shape: a fresh store is what installedFirst expects.
            storage.inner.names().forEach { storage.inner.delete(it) }
            freshLoader()
        }
    }

    @Test
    fun `a pointed records json that does not read is a store failure, and the sync fetches in full`() {
        val server = installedFirst()
        storage.inner.write("crlite/compat/$directory1/records.json", "{".encodeToByteArray())
        next(server, listOf(full, delta, delta2))
        val run = sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertEquals(server.changesetUrl, server.fetcher.requests[1].url)
        assertFalse("If-None-Match" in server.fetcher.requests[1].headers)
    }
}
