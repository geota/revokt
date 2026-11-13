// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.port.Timestamp
import dev.revokt.clubcard.port.TimestampInterval
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** `TimestampInterval.contains` (#7) is upstream's `low <= ts && ts <= high`: inclusive at both ends, unsigned. */
@OptIn(RevoktInternalApi::class)
class TimestampIntervalTest {
    @Test
    fun `interval contains is inclusive at both ends`() {
        val interval = TimestampInterval(Timestamp(1000), Timestamp(2000))
        assertTrue(Timestamp(1000) in interval)
        assertTrue(Timestamp(2000) in interval)
        assertTrue(Timestamp(1500) in interval)
        assertFalse(Timestamp(999) in interval)
        assertFalse(Timestamp(2001) in interval)
    }

    @Test
    fun `interval contains compares unsigned`() {
        val upper = TimestampInterval(Timestamp(Long.MAX_VALUE), Timestamp.MAX)
        assertTrue(Timestamp(-1) in upper)
        assertTrue(Timestamp(Long.MIN_VALUE) in upper)
        assertFalse(Timestamp(0) in upper)
        val all = TimestampInterval(Timestamp.MIN, Timestamp.MAX)
        assertTrue(Timestamp(0) in all)
        assertTrue(Timestamp(-1) in all)
        val empty = TimestampInterval(Timestamp(5), Timestamp(4))
        assertFalse(Timestamp(5) in empty)
        assertFalse(Timestamp(4) in empty)
    }
}
