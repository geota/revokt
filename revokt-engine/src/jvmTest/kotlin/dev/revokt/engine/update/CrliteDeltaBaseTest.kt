// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
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
 * The `_since` merge's base and the malformed-pointer cases over the content-addressed store: what the sync merges a
 * delta changeset over (the served generation's file, spec §6.5), or fetches in full instead, and that nothing is
 * deleted beside a pointer or a served generation that does not read (#236, #287).
 */
internal class CrliteDeltaBaseTest : CrliteDeltaFixture() {
    private fun malformPointer() = storage.inner.write("crlite/compat/current", "{".encodeToByteArray())

    /** Damages the generation file [name] in place: still a key, no longer the bytes its name promises. */
    private fun damage(name: String?) {
        val key = store.generationKey(assertNotNull(name))
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).let { it.copyOf(it.size - 1) })
    }

    @Test
    fun `#236 - with no cursor the whole collection is verified alone, never merged over the stored records`() {
        val server = installedFirst()
        // A malformed updater.json loses the cursor; the served generation's file still reads.
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
    fun `#236 - a malformed pointer and a fresh loader re-serve the same ts, which installs the same file and heals`() {
        val server = installedFirst()
        malformPointer()
        freshLoader()
        server.fetcher.requests.clear()
        val run = sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures, "the malformed pointer")
        assertEquals(emptyList(), server.attachmentRequests(), "every blob is reused")
        assertEquals(
            StoreRead.Found(Pointer(assertNotNull(name1), null)),
            store.pointer(),
            "the same bytes, the same name",
        )
    }

    @Test
    fun `#236 - a running loader re-serving the same ts beside a malformed pointer installs, with no previous`() {
        val server = installedFirst()
        malformPointer()
        server.fetcher.requests.clear()
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Found(Pointer(assertNotNull(name1), null)), store.pointer())
        assertEquals(emptyList(), server.attachmentRequests())
        sync(server, now = ts + 9 * hour).assert(SyncOutcome.UNCHANGED)
    }

    @Test
    fun `#236 - beside a malformed pointer a rotted blob is fetched again and rewritten, and nothing is deleted`() {
        val server = installedFirst()
        malformPointer()
        val key = store.blobKey(delta.body.toByteString().sha256())
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).also { it[0] = (it[0] + 1).toByte() })
        freshLoader()
        server.fetcher.requests.clear()
        val before = storage.inner.names()
        val run = sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(2, run.storeFailures, "the malformed pointer and the rotted blob")
        assertEquals(listOf(attachments + delta.location), server.attachmentRequests())
        assertContentEquals(delta.body, storage.inner.read(key))
        assertTrue(storage.inner.names().containsAll(before))
    }

    @Test
    fun `#236 - a running loader with a damaged served file heals a new ts beside a malformed pointer`() {
        val server = installedFirst()
        malformPointer()
        damage(name1)
        next(server, listOf(full, delta, delta2))
        val run = sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        // One for the malformed pointer, one for the served file: no delta base (counted here, as the pointer does not
        // name it), so no previous either, which reads it once more without counting it again.
        assertEquals(3, run.storeFailures)
        assertEquals(StoreRead.Found(Pointer(stored(liveName()).name, null)), store.pointer())
        assertTrue(store.generationKey(assertNotNull(name1)) in storage.inner.names(), "the damaged file is kept")
    }

    @Test
    fun `a damaged served file beside a pointer that reads is fetched in full, counted once, and nothing is pruned`() {
        val server = installedFirst()
        damage(name1)
        next(server, listOf(full, delta, delta2))
        val run = sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        val changesets =
            server.fetcher.requests
                .map { it.url }
                .filter { it.startsWith(server.changesetUrl) }
        assertEquals(listOf(server.changesetUrl), changesets, "a full fetch, with no _since")
        assertFalse("If-None-Match" in server.fetcher.requests[1].headers)
        assertEquals(StoreRead.Found(Pointer(stored(liveName()).name, null)), store.pointer())
        // The pointer named a generation that did not read before the install: prune deleted nothing (B2).
        assertTrue(store.generationKey(assertNotNull(name1)) in storage.inner.names())
    }

    @Test
    fun `#236 - beside a malformed pointer a new ts installs, a running loader keeping its live one as previous`() {
        val server = installedFirst()
        malformPointer()
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Found(Pointer(stored(liveName()).name, assertNotNull(name1))), store.pointer())
    }

    @Test
    fun `#236 - beside a malformed pointer a fresh loader installs a new ts, the healed pointer with no previous`() {
        val server = installedFirst()
        malformPointer()
        freshLoader()
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Found(Pointer(stored(liveName()).name, null)), store.pointer())
    }

    @Test
    fun `#256 - a heal flip deletes nothing, and the next install over the healed pointer prunes`() {
        val server = installedFirst()
        // Another binary's generation file under its own name, and a stray blob: both unnamed.
        val stray = store.blobKey(okio.ByteString.of(1, 2, 3).sha256())
        storage.inner.write(stray, byteArrayOf(1, 2, 3))
        malformPointer()
        freshLoader()
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertTrue(stray in storage.inner.names(), "no prune after a heal")
        server.ts = ts2 + 1_000
        sync(server, now = server.ts + hour).assert(SyncOutcome.INSTALLED)
        assertFalse(stray in storage.inner.names(), "the next install over a pointer that reads prunes")
        assertEquals(StoreRead.Absent, store.readGeneration(assertNotNull(name1)))
    }
}
