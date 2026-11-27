// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.Freshness
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.GenerationFileJson
import dev.revokt.engine.store.InMemoryStorage
import dev.revokt.engine.store.StorageBackend
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame

/** The storage, store, engine, snapshot and helpers of [InstallTest] (#130), split out so it stays one readable class. */
internal open class InstallFixture {
    /** A storage whose writes and deletes a test can fail or observe, key by key. */
    protected class Faulty(
        val inner: StorageBackend = InMemoryStorage(),
    ) : StorageBackend by inner {
        var fail: (String) -> Throwable? = { null }
        var failRead: (String) -> Throwable? = { null }
        var failNames: () -> Throwable? = { null }
        var onWrite: (String) -> Unit = {}
        val writes = mutableListOf<String>()
        val deletes = mutableListOf<String>()

        override fun read(name: String): ByteArray? {
            failRead(name)?.let { throw it }
            return inner.read(name)
        }

        override fun names(): Set<String> {
            failNames()?.let { throw it }
            return inner.names()
        }

        override fun write(
            name: String,
            bytes: ByteArray,
        ) {
            fail(name)?.let { throw it }
            onWrite(name)
            writes += name.removePrefix("crlite/compat/")
            inner.write(name, bytes)
        }

        override fun delete(name: String) {
            deletes += name.removePrefix("crlite/compat/")
            inner.delete(name)
        }
    }

    protected val storage = Faulty()
    protected val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
    protected val engine = TestEngine()
    protected val logger = UpdateFixtures.Recording()
    protected val empty =
        GenerationSnapshot(
            0,
            mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, true, false)),
            null,
        )
    protected val snapshot = SnapshotRef(empty)
    protected val now = 1_792_600_000_000
    protected val publication = Publication(false, null, false, now)

    protected fun install(
        pending: PendingGeneration,
        engine: TestEngine = this.engine,
        publication: Publication = this.publication,
        updater: UpdaterRecord? = UpdaterRecord(watermarkMillis = 1),
    ): InstallResult = install(pending, engine, store, snapshot, publication, updater, logger)

    /** A generation of the fixture full and delta at [timestamp], its bodies stored as blobs. */
    protected fun pending(
        timestamp: Long = TS,
        freshness: Freshness = Freshness.RECORD_LAST_MODIFIED,
        signature: ByteArray = ByteArray(96) { 9 },
    ) = UpdateFixtures.pending(store, freshness = freshness, sourceTimestampMillis = timestamp, signature = signature)

    /** The name [p]'s generation file has. */
    protected fun nameOf(p: PendingGeneration): String = GenerationFileJson.name(GenerationFileJson.write(p.file))

    protected fun failed(result: InstallResult): InstallResult.Failed = assertIs<InstallResult.Failed>(result)

    protected fun installed(result: InstallResult): InstallResult.Installed = assertIs<InstallResult.Installed>(result)

    /** The engine, the snapshot and the pointer are as they were, and nothing was deleted. */
    protected fun assertUntouched(
        live: String? = null,
        published: GenerationSnapshot = empty,
    ) {
        assertEquals(live, engine.live)
        assertSame(published, snapshot.snapshot)
        assertEquals(emptyList(), storage.deletes)
        if (live == null) assertEquals(StoreRead.Absent, store.pointer())
    }

    protected companion object {
        const val TS = 1_792_587_631_204L
    }
}
