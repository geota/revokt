// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.UpdaterRecord
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Spec §7.1's rollback guard through the sync (§9 data-path (a)): with a generation live, a changeset older than the
 * higher of the stored watermark and the live `<ts>` is `ROLLBACK_REFUSED` before any body; with none loaded the stored
 * watermark is not read, so older signed data installs, as Firefox imports when its local data does not verify. Each
 * read of the store that is not `Found` is an arm here: an absent or malformed `updater.json` beside a live generation
 * keeps the live floor, and a read that throws writes nothing and installs nothing. No rule reads the local clock.
 */
internal class CrliteRollbackTest : CrliteDeltaFixture() {
    private val updaterKey = "crlite/compat/updater.json"
    private val currentKey = "crlite/compat/current"
    private val older = ts - hour
    private val olderDirectory = GenerationNames.directory(older, "$older/${delta.id}")

    /** [server] moved back to [older], with the same records. */
    private fun older(server: Server): Server =
        server.apply {
            this.ts = older
            fetcher.requests.clear()
        }

    @Test
    fun `beside a live generation an older changeset is ROLLBACK_REFUSED before any body, and not a failure`() {
        val server = older(installedFirst())
        val now = ts + 2 * hour
        sync(server, now = now).assert(SyncOutcome.ROLLBACK_REFUSED)
        assertEquals(emptyList(), server.attachmentRequests())
        val s = sourceRecord(now)
        assertEquals(
            listOf<Any?>(ts, ts + hour, 0),
            listOf(s.lastVerifiedLastModified, s.lastVerifiedAtMillis, s.consecutiveFailures),
        )
        assertEquals(ts, updater(now).watermarkMillis)
        assertEquals(directory1, liveDirectory())
        assertEquals("$ts/${delta.id}", live().generationId)
    }

    @Test
    fun `beside a live generation a stored watermark above it is the floor, and equal to it installs`() {
        val server = installedFirst()
        val watermark = ts + 5_000
        store.writeUpdater(updater().copy(watermarkMillis = watermark), ts + hour)
        server.ts = watermark - 1
        server.fetcher.requests.clear()
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.ROLLBACK_REFUSED)
        server.ts = watermark
        sync(server, now = ts + 3 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(watermark, updater(ts + 3 * hour).watermarkMillis)
        assertEquals(watermark, live().sourceTimestampMillis)
    }

    @Test
    fun `beside a live generation an absent updater json keeps the live floor`() =
        refusedBeside { storage.inner.delete(updaterKey) }

    @Test
    fun `beside a live generation a malformed updater json keeps the live floor`() =
        refusedBeside { storage.inner.write(updaterKey, "{".encodeToByteArray()) }

    /** An older changeset after [damage] to `updater.json` beside a live generation: refused at the live floor. */
    private fun refusedBeside(damage: () -> Unit) {
        val server = older(installedFirst())
        damage()
        assertNull(updater().watermarkMillis)
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.ROLLBACK_REFUSED)
        assertEquals(emptyList(), server.attachmentRequests())
        assertEquals(directory1, liveDirectory())
        assertEquals("$ts/${delta.id}", live().generationId)
    }

    @Test
    fun `beside a live generation an updater json read that throws writes nothing and installs nothing`() {
        val server = older(installedFirst())
        val before = checkNotNull(storage.inner.read(updaterKey))
        storage.failRead = { if (it == updaterKey) IllegalStateException("read") else null }
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed())
        storage.failRead = { null }
        assertContentEquals(before, storage.inner.read(updaterKey))
        assertEquals(emptyList(), server.attachmentRequests())
        assertEquals(directory1, liveDirectory())
    }

    @Test
    fun `with no generation loaded the stored watermark is not read, and an older changeset installs`() {
        // A fresh loader whose stored generation did not load: the pointer reads, but nothing is live.
        val server = older(installedFirst())
        freshLoader()
        val now = ts + 2 * hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        installedOlder(now)
    }

    @Test
    fun `with no generation loaded beside an absent pointer an older changeset installs`() =
        installsAfter { storage.inner.delete(currentKey) }

    @Test
    fun `with no generation loaded beside a malformed pointer an older changeset installs`() =
        installsAfter { storage.inner.write(currentKey, "{".encodeToByteArray()) }

    @Test
    fun `with no generation loaded beside a malformed live meta json an older changeset installs`() =
        installsAfter { storage.inner.write("crlite/compat/$directory1/meta.json", "{".encodeToByteArray()) }

    /** An older changeset after [damage] to the stored generation, which a fresh loader does not load: installs. */
    private fun installsAfter(damage: () -> Unit) {
        val server = older(installedFirst())
        damage()
        freshLoader()
        val now = ts + 2 * hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        // The whole collection, as no stored records read to merge with.
        assertEquals(server.changesetUrl, server.fetcher.requests[1].url)
        installedOlder(now)
    }

    /** The older changeset installed with no generation loaded: the cursor moved back with it, the watermark stayed. */
    private fun installedOlder(now: Long) {
        assertEquals("$older/${delta.id}", live().generationId)
        assertEquals(olderDirectory, liveDirectory())
        assertEquals(older, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(ts, updater(now).watermarkMillis)
        // Now a generation is live, the high-water mark floors again: ts - 1 is refused, ts installs.
        val server = Server(ts = ts - 1)
        sync(server, now = now + hour).assert(SyncOutcome.ROLLBACK_REFUSED)
        sync(Server(), now = now + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals("$ts/${delta.id}", live().generationId)
    }

    @Test
    fun `with no generation loaded an updater json read that throws writes nothing and installs nothing`() {
        val server = older(installedFirst())
        freshLoader()
        val before = checkNotNull(storage.inner.read(updaterKey))
        storage.failRead = { if (it == updaterKey) IllegalStateException("read") else null }
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed())
        storage.failRead = { null }
        assertContentEquals(before, storage.inner.read(updaterKey))
        assertEquals(emptyList(), server.attachmentRequests())
        assertEquals(directory1, liveDirectory())
        assertNull(live().generationId)
    }

    @Test
    fun `with no generation and a malformed updater json an older changeset installs, counting the store failure`() {
        val server = older(installedFirst())
        storage.inner.write(updaterKey, "{".encodeToByteArray())
        freshLoader()
        val run = sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertEquals("$older/${delta.id}", live().generationId)
        // The malformed record read as empty, so the install wrote a fresh one: the watermark is the installed <ts>.
        assertEquals(older, updater(ts + 2 * hour).watermarkMillis)
    }

    @Test
    fun `a snapshot entry with a timestamp but no generation id is no generation, so the watermark is not read`() {
        val server = older(installedFirst())
        snapshot.publish(
            GenerationSnapshot(
                0,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, ts, null, false, false)),
                null,
            ),
        )
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals("$older/${delta.id}", live().generationId)
    }

    @Test
    fun `a snapshot with no CRLite entry is no generation, so the watermark is not read`() {
        val server = older(installedFirst())
        snapshot.publish(GenerationSnapshot(0, emptyMap(), null))
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals("$older/${delta.id}", live().generationId)
    }

    @Test
    fun `with no generation ever installed a stored watermark far ahead is not read`() {
        store.writeUpdater(UpdaterRecord(watermarkMillis = ts + 30 * day), ts)
        val now = ts + hour
        sync(Server(), now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(ts + 30 * day, updater(now).watermarkMillis)
        assertEquals(ts, sourceRecord(now).lastVerifiedLastModified)
    }

    @Test
    fun `content-signature far future - a changeset ahead of the clock installs and advances the watermark`() {
        val server = installedFirst()
        // Two days ahead of the local clock: no rule reads local time, so it installs like any other.
        val now = ts + 2 * hour
        server.ts = now + 2 * day
        server.fetcher.requests.clear()
        val run = sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(emptyList(), run.result.warnings)
        assertEquals(now + 2 * day, updater(now).watermarkMillis)
        assertEquals(now + 2 * day, sourceRecord(now).lastVerifiedLastModified)
        // The next server ts passes it, as Kinto's are monotonic per collection, so the feed does not freeze.
        server.ts = now + 2 * day + 1
        sync(server, now = now + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(now + 2 * day + 1, live().sourceTimestampMillis)
    }
}
