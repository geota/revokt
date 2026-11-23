// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RevoktLimitsTest {
    private val hour = 60L * 60 * 1_000

    @Test
    fun `limits match the spec 5-1 table`() {
        assertEquals(16, RevoktLimits.MAX_DEPTH)
        assertEquals(64, RevoktLimits.MAX_PRESENTED)
        assertEquals(1L shl 20, RevoktLimits.MAX_PRESENTED_BYTES)
        assertEquals(256, RevoktLimits.MAX_EXPLORED)
        assertEquals(8, RevoktLimits.FALLBACK_MAX_PRESENTED)
        assertEquals(1_024, RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
        assertEquals(5_000, RevoktLimits.ENGINE_CLOSE_DRAIN)
        assertEquals(30_000, RevoktLimits.FETCH_TIMEOUT)
        assertEquals(262_144, RevoktLimits.MAX_CERT_BYTES)
        assertEquals(16L shl 20, RevoktLimits.MAX_FILTER_BYTES)
        assertEquals(4L shl 20, RevoktLimits.MAX_JSON_BYTES)
        assertEquals(64L shl 10, RevoktLimits.MAX_X5U_BYTES)
        assertEquals(1_024, RevoktLimits.MAX_CHANGESET_RECORDS)
        assertEquals(24 * hour, RevoktLimits.MAX_BACKOFF)
    }

    @Test
    fun `fallback limit is below the presented cap so the skip rule is reachable`() {
        assertTrue(RevoktLimits.FALLBACK_MAX_PRESENTED < RevoktLimits.MAX_PRESENTED)
    }
}
