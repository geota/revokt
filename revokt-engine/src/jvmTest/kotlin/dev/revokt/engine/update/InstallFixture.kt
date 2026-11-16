// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.RevoktStorage
import dev.revokt.TrustClass
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame

/** The storage, store, engine, snapshot and helpers of [InstallTest] (#130), split out so it stays one readable class. */
internal open class InstallFixture {
    /** A storage whose writes a test can fail or observe, key by key. */
    protected class Faulty(
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

    protected val storage = Faulty()
    protected val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
    protected val engine = TestEngine()
    protected val logger = UpdateFixtures.Recording()
    protected val empty =
        GenerationSnapshot(
            0,
            mapOf(Dataset.CRLITE to DatasetGeneration(null, null, null, false, null, null, true, false, false)),
            null,
        )
    protected val snapshot = SnapshotRef(empty)
    protected val now = 1_792_600_000_000
    protected val publication = Publication(false, null, false, now, 600_000)

    protected fun install(
        pending: PendingGeneration,
        engine: TestEngine = this.engine,
        publication: Publication = this.publication,
        updater: UpdaterRecord? = UpdaterRecord(watermarkMillis = 1),
    ): InstallResult = install(pending, engine, store, snapshot, publication, updater, logger)

    protected fun pending(
        id: String = "g1",
        trustClass: TrustClass = TrustClass.SIGNED,
        timestamp: Long = 1_792_587_631_204,
    ) = UpdateFixtures.pending(store, trustClass = trustClass, generationId = id, sourceTimestampMillis = timestamp)

    protected fun failed(result: InstallResult): InstallResult.Failed = assertIs<InstallResult.Failed>(result)

    /** [p]'s delta files, each the fixture body of its name (every fixture filename is its own derived name). */
    protected fun bytesOf(p: PendingGeneration): Map<String, ByteArray> =
        p.deltas.mapValues { (name, _) -> UpdateFixtures.bodies.getValue(name) }

    protected fun keysOf(directory: String): List<String> = storage.names().filter { it.contains("/$directory/") }

    /** The engine, the snapshot and the pointer are as they were, and [directory] is gone. */
    protected fun assertUntouched(
        directory: String,
        live: String? = null,
        published: GenerationSnapshot = empty,
    ) {
        assertEquals(live, engine.live)
        assertSame(published, snapshot.snapshot)
        assertEquals(emptyList(), keysOf(directory))
        if (live == null) assertEquals(StoreRead.Absent, store.pointer())
    }
}
