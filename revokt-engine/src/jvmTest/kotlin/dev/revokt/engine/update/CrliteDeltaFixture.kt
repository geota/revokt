// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.RevoktLimits
import dev.revokt.SyncOutcome
import dev.revokt.engine.fetch.json
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
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

/** The second generation and the helpers [CrliteDeltaSyncTest] and [CrliteDeltaBaseTest] share. */
internal open class CrliteDeltaFixture : CrliteSyncFixture() {
    protected val ts2 = ts + 1_000

    /** A second delta, after the cursor, in another encoding (each filter is read in its own, #137). */
    protected val delta2 =
        Rec(
            "e7d1f0a2-0000-4000-8000-000000000002",
            true,
            ts + 500,
            "20261022-1-compat.filter.delta",
            UpdateFixtures.v4(listOf(log(2) to (1_000L to 2_000L))),
            parent = full.id,
        )

    /** The first delta's tombstone, after the cursor. */
    protected val tombstone = """{"id":"${delta.id}","last_modified":${ts + 600},"deleted":true}"""

    /** A full that re-parents the channel: another body, so no stored blob holds it. */
    protected val full2 =
        Rec(
            "a3c9e1b4-0000-4000-8000-000000000003",
            false,
            ts + 700,
            "20261101-1-compat.filter",
            UpdateFixtures.v4(listOf(log(3) to (1_000L to 2_000L))),
        )

    /** The first generation's file name, once [installedFirst] installed it. */
    protected var name1: String? = null

    /** [server] after the first generation installed, moved to `ts2` with [records] and [tombstones]. */
    protected fun next(
        server: Server,
        records: List<Rec>,
        tombstones: List<String> = emptyList(),
    ) {
        server.ts = ts2
        server.records = records.map { it.json() }
        server.bodies = (listOf(full, delta) + records).associate { it.location to it.body }
        server.tombstones = tombstones
        server.fetcher.requests.clear()
    }

    protected fun installedFirst(): Server {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        name1 = assertNotNull(liveName())
        assertEquals("$ts/${delta.id}", stored(name1).generationId)
        return server
    }

    protected fun freshLoader() =
        snapshot.publish(
            GenerationSnapshot(
                0,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false)),
                null,
            ),
        )
}
