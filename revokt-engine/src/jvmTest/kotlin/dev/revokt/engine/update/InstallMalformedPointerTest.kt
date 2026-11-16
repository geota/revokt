// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreRead
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * #236 (finding B of the #214 store model): beside a malformed pointer, which may name any directory, a complete
 * target directory is held. It is compared, reused when it holds this generation, never reopened, rewritten or deleted,
 * and `STORE_FAILED` when it holds another; the flip then writes a pointer that reads, so the store heals.
 */
internal class InstallMalformedPointerTest : InstallFixture() {
    @Test
    fun `beside a malformed pointer a complete directory holding this generation is reused and the flip heals it`() {
        val dir = assertIs<InstallResult.Installed>(install(pending())).directory
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val meta = checkNotNull(storage.inner.read("crlite/compat/$dir/meta.json"))
        storage.writes.clear()
        // A fresh loader: nothing is live in its snapshot.
        val r = install(pending(), engine, store, SnapshotRef(empty), publication, null, logger)
        assertIs<InstallResult.Installed>(r)
        assertEquals(listOf("current"), storage.writes)
        assertTrue(meta.contentEquals(storage.inner.read("crlite/compat/$dir/meta.json")))
        assertEquals(StoreRead.Found(Pointer(dir, null)), store.pointer())
    }

    @Test
    fun `beside a malformed pointer a complete directory holding another generation fails and stays`() {
        val dir = assertIs<InstallResult.Installed>(install(pending())).directory
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val other = checkNotNull(store.meta(dir)).copy(collection = "security-state/other")
        storage.inner.write(
            "crlite/compat/$dir/meta.json",
            dev.revokt.engine.store.MetaJson
                .write(other),
        )
        val f = failed(install(pending(), engine, store, SnapshotRef(empty), publication, null, logger))
        assertEquals(SyncOutcome.STORE_FAILED to SyncStage.STORE, f.outcome to f.stage)
        assertTrue("holds another generation" in f.cause?.message.orEmpty())
        assertEquals(other, store.meta(dir))
        assertNotNull(store.file(dir, dev.revokt.engine.store.StoreLayout.INDEX))
        assertEquals(StoreRead.Malformed, store.pointer())
    }

    @Test
    fun `beside a malformed pointer a running loader keeps its live generation as previous, a fresh one has none`() {
        val g1 = assertIs<InstallResult.Installed>(install(pending("g1"))).directory
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val g2 = assertIs<InstallResult.Installed>(install(pending("g2", timestamp = 2_000_000_000_000))).directory
        assertEquals(StoreRead.Found(Pointer(g2, g1)), store.pointer())
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val fresh = SnapshotRef(empty)
        val r = install(pending("g3", timestamp = 2_000_000_000_001), engine, store, fresh, publication, null, logger)
        assertEquals(StoreRead.Found(Pointer(assertIs<InstallResult.Installed>(r).directory, null)), store.pointer())
    }

    @Test
    fun `beside a malformed pointer a malformed meta json is held and kept, and a new ts installs`() {
        val dir = assertIs<InstallResult.Installed>(install(pending())).directory
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        storage.inner.write("crlite/compat/$dir/meta.json", "{\"metaVersion\":2}".encodeToByteArray())
        val before = keysOf(dir).associateWith { checkNotNull(storage.inner.read(it)).toList() }
        val f = failed(install(pending(), engine, store, SnapshotRef(empty), publication, null, logger))
        assertEquals(SyncOutcome.STORE_FAILED to SyncStage.STORE, f.outcome to f.stage)
        assertEquals(before, keysOf(dir).associateWith { checkNotNull(storage.inner.read(it)).toList() })
        val r =
            install(
                pending("g2", timestamp = 2_000_000_000_000),
                engine,
                store,
                SnapshotRef(empty),
                publication,
                null,
                logger,
            )
        assertIs<InstallResult.Installed>(r)
    }

    @Test
    fun `beside a malformed pointer a live generation of a lower trust class is not kept as previous`() {
        assertIs<InstallResult.Installed>(install(pending("g1", TrustClass.MIRROR)))
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        val g2 = assertIs<InstallResult.Installed>(install(pending("g2", timestamp = 2_000_000_000_000))).directory
        assertEquals(StoreRead.Found(Pointer(g2, null)), store.pointer())
    }
}
