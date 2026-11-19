// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreRead
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The pointer's new `previous` (spec §6.5, #249): the generation the engine served before the install comes first, so
 * a flip that failed after activation never loses it to prune, and every candidate is read once, its fault counted.
 */
internal class InstallPreviousTest : InstallFixture() {
    @Test
    fun `a pointed previous that does not read counts a store failure even beside a qualifying live (#249)`() {
        fun dir(r: InstallResult) = assertIs<InstallResult.Installed>(r).directory
        val g1 = dir(install(pending("g1")))
        val g2 = dir(install(pending("g2", timestamp = 2_000_000_000_000)))
        storage.inner.delete("crlite/compat/$g1/meta.json")
        val r = assertIs<InstallResult.Installed>(install(pending("g3", timestamp = 2_000_000_000_001)))
        assertEquals(1, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.directory, g2)), store.pointer())
    }

    @Test
    fun `a served generation the pointer also names is read once, so its fault counts once (#249)`() {
        fun dir(r: InstallResult) = assertIs<InstallResult.Installed>(r).directory
        val g1 = dir(install(pending("g1")))
        val g2 = dir(install(pending("g2", timestamp = 2_000_000_000_000)))
        // g2 is both served and the pointer's live; its directory is gone, so the fallback is the pointer's previous.
        for (key in keysOf(g2)) storage.inner.delete(key)
        val r = assertIs<InstallResult.Installed>(install(pending("g3", timestamp = 2_000_000_000_001)))
        assertEquals(1, r.storeFailures)
        assertEquals(StoreRead.Found(Pointer(r.directory, g1)), store.pointer())
    }

    @Test
    fun `a flip that failed after activation keeps the generation the engine served as the next previous (#249)`() {
        fun dir(r: InstallResult) = assertIs<InstallResult.Installed>(r).directory
        val g1 = dir(install(pending("g1")))
        val g2 = dir(install(pending("g2", timestamp = 2_000_000_000_000)))
        assertEquals(StoreRead.Found(Pointer(g2, g1)), store.pointer())
        // g3 activates and is served, but its flip throws: current still names g2 and g1.
        storage.fail = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        val p3 = pending("g3", timestamp = 2_000_000_000_001)
        assertEquals(true, failed(install(p3)).activated)
        assertEquals("g3", engine.live)
        assertEquals(StoreRead.Found(Pointer(g2, g1)), store.pointer())
        storage.fail = { null }
        // The next install keeps g3, the generation the engine served, not the pointer's old live g2.
        val g4 = dir(install(pending("g4", timestamp = 2_000_000_000_002)))
        assertEquals(StoreRead.Found(Pointer(g4, p3.meta.directory)), store.pointer())
        assertTrue(store.prune() > 0)
        assertNotNull(store.readGeneration(p3.meta.directory), "the served generation survives prune")
        assertNull(store.readGeneration(g1))
        assertNull(store.readGeneration(g2))
    }
}
