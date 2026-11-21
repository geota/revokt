// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * [Publication.heal], the seed's rule (b) (#138): the install holds a complete directory of its name and completes an
 * incomplete one, except the engine's live directory, which is held whatever its `meta.json` says, so a running
 * loader's live generation is never rewritten while it is served.
 */
internal class InstallHealTest : InstallFixture() {
    private val heal = Publication(true, 1, false, now, pointerCounted = true, heal = true)

    @Test
    fun `under heal the engine's live directory with a damaged meta json is held, never rewritten, STORE_FAILED`() {
        val live = assertIs<InstallResult.Installed>(install(pending("g1"))).directory
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        storage.inner.write("crlite/compat/$live/meta.json", "{".encodeToByteArray())
        val generation = pending("g1")
        val before =
            storage.inner
                .names()
                .filter { "/$live/" in it }
                .associateWith { storage.inner.read(it)?.toList() }
        val f = assertIs<InstallResult.Failed>(install(generation, engine, store, snapshot, heal, null, logger))
        assertEquals(SyncOutcome.STORE_FAILED to SyncStage.STORE, f.outcome to f.stage)
        assertTrue("meta.json is not readable" in f.cause?.message.orEmpty(), "${f.cause}")
        val after =
            storage.inner
                .names()
                .filter { "/$live/" in it }
                .associateWith { storage.inner.read(it)?.toList() }
        assertEquals(before, after, "the live directory is byte-identical")
        assertEquals("g1", engine.live)
    }

    @Test
    fun `under heal a damaged directory the engine does not serve is completed afresh`() {
        val dir = assertIs<InstallResult.Installed>(install(pending("g1"))).directory
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        storage.inner.write("crlite/compat/$dir/meta.json", "{".encodeToByteArray())
        val r = install(pending("g1"), engine, store, SnapshotRef(empty), heal, null, logger)
        assertIs<InstallResult.Installed>(r)
        assertTrue(store.meta(dir) != null)
    }
}
