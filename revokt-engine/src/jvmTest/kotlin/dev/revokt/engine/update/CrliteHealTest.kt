// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.RevoktInternalApi
import dev.revokt.SyncOutcome
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.log
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A heal flip never prunes (#256, the lead's decision on r256's review): when the pointer was malformed before an
 * install, the store is not pruned after its flip, since the damaged pointer may have named any directory; the next
 * install over a valid pointer prunes as usual. The case is r256's: a member name damaged in `current`, which the strict
 * reader reads as malformed, then a fresh loader's install, which keeps no `previous`.
 */
internal class CrliteHealTest : CrliteSyncFixture() {
    private val ts2 = ts + 1_000
    private val ts3 = ts + 2_000

    private val delta2 =
        Rec(
            "e7d1f0a2-0000-4000-8000-000000000002",
            true,
            ts + 500,
            "20261022-1-compat.filter.delta",
            UpdateFixtures.v4(listOf(log(2) to (1_000L to 2_000L))),
            parent = full.id,
        )

    private fun serve(
        server: Server,
        at: Long,
    ) {
        server.ts = at
        server.records = listOf(full, delta, delta2).map { it.json() }
        server.bodies = listOf(full, delta, delta2).associate { it.location to it.body }
    }

    private fun freshLoader() =
        snapshot.publish(
            GenerationSnapshot(
                0,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false)),
                null,
            ),
        )

    @Test
    fun `a heal flip keeps what the damaged pointer named, and the next install over a valid pointer prunes it`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val g1 = checkNotNull(liveName())
        // r256's S3: the live member still reads, but an unknown member makes the pointer malformed (#246).
        storage.inner.write("crlite/compat/current", "{\"live\":\"$g1\",\"x\":1}".encodeToByteArray())
        assertEquals(StoreRead.Malformed, store.pointer())
        freshLoader()
        serve(server, ts2)
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        val g2 = checkNotNull(liveName())
        // A fresh loader has no previous beside a malformed pointer, and the heal does not prune: g1 stays.
        assertEquals(StoreRead.Found(Pointer(g2, null)), store.pointer())
        assertIs<StoreRead.Found<*>>(store.readGeneration(g1), "the heal flip pruned g1")
        // The next install flips over a valid pointer, so it prunes what that pointer no longer names.
        serve(server, ts3)
        sync(server, now = ts3 + hour).assert(SyncOutcome.INSTALLED)
        val g3 = checkNotNull(liveName())
        assertEquals(StoreRead.Found(Pointer(g3, g2)), store.pointer())
        assertEquals(StoreRead.Absent, store.readGeneration(g1), "the install after the heal prunes g1")
        assertIs<StoreRead.Found<*>>(store.readGeneration(g2))
    }
}
