// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.runtime.StartChain
import dev.revokt.engine.runtime.serveChain
import dev.revokt.engine.seed.SeedFixture
import dev.revokt.engine.seed.SeedLoad
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.log
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The crash table of the content-addressed store (design note section 8, spec §6.5 "Crash recovery"), one test per row:
 * a process stop at a chosen write or delete, after which nothing more lands, then a fresh loader over the same store.
 * `StoreModelTest` stops at every operation; these pin each row's outcome down. Lost write durability (a rename the
 * parent directory's fsync did not cover) is `JvmStorage`'s, out of reach of an in-memory store.
 */
internal class StoreCrashTest : SeedFixture() {
    /** Thrown by every write and delete once the process has stopped. */
    private class Stopped : Error("the process stopped")

    private var stopped = false

    /** Stops the process at the first write or delete [at] names: it and everything after it are lost. */
    private fun stopAt(at: (String) -> Boolean) {
        stopped = false
        val hit = { name: String ->
            if (stopped || at(name)) {
                stopped = true
                Stopped()
            } else {
                null
            }
        }
        storage.failWrite = hit
        storage.failDelete = hit
    }

    /** A fresh loader over the same store, as at the next `start()`: nothing served, no faults. */
    private fun restart() {
        storage.failWrite = { null }
        storage.failDelete = { null }
        stopped = false
        snapshot.publish(
            GenerationSnapshot(
                snapshot.snapshot.generationEpoch,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false)),
                null,
            ),
        )
    }

    private val ts2 = ts + 1_000

    /** Two new deltas, so a publication at [ts2] writes two blobs. */
    private val d2 =
        Rec("d2", true, ts + 500, "d2.filter.delta", UpdateFixtures.v4(listOf(log(2) to (1L to 2L))), parent = full.id)
    private val d3 =
        Rec("d3", true, ts + 600, "d3.filter.delta", UpdateFixtures.v4(listOf(log(3) to (1L to 2L))), parent = full.id)

    private fun second(server: Server) {
        server.ts = ts2
        server.records = listOf(full, delta, d2, d3).map { it.json() }
        server.bodies = listOf(full, delta, d2, d3).associate { it.location to it.body }
        server.fetcher.requests.clear()
    }

    private fun blobKey(r: Rec): String = store.blobKey(r.body.toByteString().sha256())

    @Test
    fun `row 1 - a stop after some blob writes leaves the old live, and the retry fetches only the rest`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = liveName()
        second(server)
        stopAt { it == blobKey(d3) }
        sync(server, now = ts2 + hour)
        assertTrue(blobKey(d2) in storage.inner.names() && blobKey(d3) !in storage.inner.names())
        restart()
        assertEquals(first, liveName(), "the old live, untouched")
        assertIs<GenerationLoad.Loaded>(store.load(checkNotNull(first)))
        server.fetcher.requests.clear()
        sync(server, now = ts2 + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + d3.location), server.attachmentRequests(), "nothing fetched twice")
    }

    @Test
    fun `row 2 - a REWRITTEN blob holds the bytes its name promises again, and the old live loads`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = checkNotNull(liveName())
        storage.inner.write(blobKey(delta), byteArrayOf(1, 2, 3))
        assertIs<GenerationLoad.Failed>(store.load(first))
        second(server)
        val run = sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertContentEquals(delta.body, storage.inner.read(blobKey(delta)))
        restart()
        assertIs<GenerationLoad.Loaded>(store.load(first), "the old live, whose blob was repaired")
    }

    @Test
    fun `row 3 - a stop after the generation file leaves it whole and unnamed, and the retry only flips`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = liveName()
        second(server)
        stopAt { it.endsWith("/current") }
        sync(server, now = ts2 + hour)
        restart()
        assertEquals(first, liveName())
        val orphan = (store.generationNames() - checkNotNull(first)).single()
        assertIs<StoreRead.Found<*>>(store.stored(orphan), "whole")
        // The same changeset rebuilds the same bytes and the same name: nothing is fetched or written but the flip.
        server.fetcher.requests.clear()
        val writes = ArrayList<String>()
        storage.failWrite = {
            writes += it.removePrefix("crlite/compat/")
            null
        }
        sync(server, now = ts2 + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(emptyList(), server.attachmentRequests())
        assertEquals(listOf("current", "updater.json"), writes)
        assertEquals(
            StoreRead.Found(Pointer(orphan, first)),
            store.pointer(),
            "the old live is its previous",
        )
    }

    @Test
    fun `row 3 - a newer changeset leaves the interrupted file to the next prune, never an orphan loop (#205)`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        second(server)
        stopAt { it.endsWith("/current") }
        sync(server, now = ts2 + hour)
        restart()
        val orphan = (store.generationNames() - checkNotNull(liveName())).single()
        // A newer publication installs over the pointer that reads, and its prune deletes the orphan, now older.
        server.ts = ts2 + 1_000
        sync(server, now = ts2 + 2 * hour).assert(SyncOutcome.INSTALLED)
        server.ts = ts2 + 2_000
        sync(server, now = ts2 + 3 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Absent, store.readGeneration(orphan))
    }

    @Test
    fun `row 4 - a stop after the flip leaves the new generation pointed, and UNCHANGED repairs updater_json`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        second(server)
        stopAt { it.endsWith("/updater.json") }
        sync(server, now = ts2 + hour)
        stopped = false
        storage.failWrite = { null }
        storage.failDelete = { null }
        val name = checkNotNull(liveName())
        assertEquals("$ts2/d3", stored(name).generationId, "every key it needs was durable before the flip")
        assertEquals(ts, updater(ts2 + hour).watermarkMillis, "the watermark stayed")
        // The running loader serves it; the cursor is stale, so the whole collection is fetched, UNCHANGED, and
        // updater.json is written as the install of ts2 would have written it (spec §6.5).
        val now = ts2 + 2 * hour
        sync(server, now = now).assert(SyncOutcome.UNCHANGED)
        assertEquals(now, updater(now).datasetLastAttemptAtMillis)
        assertEquals(ts2, sourceRecord(now).lastVerifiedLastModified, "the cursor")
        assertEquals(now, sourceRecord(now).lastVerifiedAtMillis)
        assertEquals(ts2, updater(now).watermarkMillis, "the watermark")
        // Caught up, the next sync sends the cursor: a 304.
        server.fetcher.requests.clear()
        sync(server, now = now + hour).assert(SyncOutcome.UNCHANGED)
        assertTrue(server.fetcher.requests.any { "_since" in it.url || "If-None-Match" in it.headers })
        // The floor is max(watermark, the live <ts>): the stale watermark reopens no rollback.
        server.ts = ts2 - 1
        sync(server, now = ts2 + 3 * hour).assert(SyncFailure.ROLLBACK_REFUSED)
    }

    @Test
    fun `row 4 - after a restart the chain serves the new pointed generation, and UNCHANGED catches updater_json up`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        second(server)
        stopAt { it.endsWith("/updater.json") }
        sync(server, now = ts2 + hour)
        restart()
        val name = checkNotNull(liveName())
        val engine = UpdateFixtures.TestEngine()
        assertEquals(StartChain.LIVE, serveChain(store, { ts2 + 2 * hour }, HashSet(), engine, snapshot, true, logger))
        assertEquals(name, live().generationFile)
        assertEquals(ts, updater(ts2 + 2 * hour).watermarkMillis, "stale until the next sync")
        val now = ts2 + 3 * hour
        sync(server, now = now).assert(SyncOutcome.UNCHANGED)
        assertEquals(ts2, sourceRecord(now).lastVerifiedLastModified, "the cursor")
        assertEquals(now, sourceRecord(now).lastVerifiedAtMillis)
        assertEquals(ts2, updater(now).watermarkMillis, "the watermark")
        server.ts = ts2 - 1
        sync(server, now = now + hour).assert(SyncFailure.ROLLBACK_REFUSED)
    }

    /** [server] serving [records] at [at]. */
    private fun serve(
        server: Server,
        at: Long,
        vararg records: Rec,
    ) {
        server.ts = at
        server.records = records.map { it.json() }
        server.bodies = (listOf(full, delta, d2, d3)).associate { it.location to it.body }
        server.fetcher.requests.clear()
    }

    @Test
    fun `row 5 - a stop among prune's deletes leaves the new generation, and the next prune deletes the rest`() {
        val server = Server()
        serve(server, ts, full, delta, d2)
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = checkNotNull(liveName())
        serve(server, ts + 500, full, delta)
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        serve(server, ts2, full, delta, d3)
        // Prune deletes the first generation file, then d2's blob, which only it named: stop after the first delete.
        var deletes = 0
        storage.failDelete = { if (deletes++ >= 1) Stopped() else null }
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Absent, store.readGeneration(first))
        assertTrue(blobKey(d2) in storage.inner.names(), "the blob delete was lost to the stop")
        restart()
        assertIs<GenerationLoad.Loaded>(store.load(checkNotNull(liveName())), "nothing named was in the delete set")
        serve(server, ts2 + 1_000, full, delta, d3)
        sync(server, now = ts2 + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertFalse(blobKey(d2) in storage.inner.names(), "the next prune finished the job")
    }

    @Test
    fun `row 5 - a lost generation-file delete beside a landed blob delete is never adopted, and counts once`() {
        val server = Server()
        serve(server, ts, full, delta, d2)
        sync(server).assert(SyncOutcome.INSTALLED)
        val old = checkNotNull(liveName())
        val oldBytes = checkNotNull(storage.inner.read(store.generationKey(old)))
        serve(server, ts + 500, full, delta)
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        serve(server, ts + 600, full, delta)
        sync(server, now = ts + 3 * hour).assert(SyncOutcome.INSTALLED)
        assertFalse(blobKey(d2) in storage.inner.names())
        // The file's delete is lost (it comes back after a crash), its blob's landed; then current and the generations it
        // named are lost too, so the stale file is all that is left newer than the seed.
        storage.inner.write(store.generationKey(old), oldBytes)
        val pointer = (store.pointer() as StoreRead.Found).value
        for (n in listOfNotNull(pointer.live, pointer.previous)) storage.inner.delete(store.generationKey(n))
        storage.inner.delete("crlite/compat/current")
        restart()
        assertIs<GenerationLoad.Failed>(store.load(old), "it fails at step 3")
        val load = installed(load(Seed(ts = ts - hour)))
        assertEquals(1, load.storeFailures, "the candidate that fails at step 3, once")
        assertIs<StoreRead.Found<*>>(store.readGeneration(old), "never deleted by a seed load")
    }
}
