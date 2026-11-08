// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.Freshness
import dev.revokt.TrustClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The internal generation snapshot (#120, spec §5.1 flow step 2): an immutable value the loader publishes. */
class GenerationSnapshotTest {
    private val seed =
        DatasetGeneration(
            generationId = "seed-2026-11-01",
            trustClass = TrustClass.BUNDLED,
            freshness = Freshness.SEED_SIGNED_TIME,
            fromSeed = true,
            sourceTimestampMillis = 1_700_000_000_000,
            seedFormat = 1,
            pending = false,
            staleGateOpen = false,
            clockBehind = false,
        )

    @Test
    fun `a snapshot holds a read-only copy of its datasets and is a value`() {
        val given = mutableMapOf(Dataset.CRLITE to seed)
        val s = GenerationSnapshot(3, given, 1_800_000_000_000)
        given.clear()
        assertEquals(mapOf(Dataset.CRLITE to seed), s.datasets)
        @Suppress("UNCHECKED_CAST") // The check is that the read-only view cannot be cast back and changed.
        assertFailsWith<UnsupportedOperationException> {
            (s.datasets as MutableMap<Dataset, DatasetGeneration>).clear()
        }
        val same = GenerationSnapshot(3, mapOf(Dataset.CRLITE to seed), 1_800_000_000_000)
        assertEquals(s, same)
        assertEquals(s.hashCode(), same.hashCode())
        assertEquals(s.toString(), same.toString())
        assertNotEquals(s, GenerationSnapshot(4, s.datasets, s.coverageEndMillis))
        assertNotEquals(s, GenerationSnapshot(3, emptyMap(), s.coverageEndMillis))
        assertNotEquals(s, GenerationSnapshot(3, s.datasets, null))
        assertNotEquals<Any>(s, "snapshot")
    }

    @Test
    fun `a dataset's trust class is null exactly when its generation id is`() {
        for (broken in listOf({ seed.copy(trustClass = null) }, { seed.copy(generationId = null) })) {
            val e = assertFailsWith<IllegalArgumentException> { broken() }
            assertTrue("trustClass is null exactly when generationId is" in e.message!!, e.message)
        }
        seed.copy(trustClass = null, generationId = null, pending = true)
    }
}
