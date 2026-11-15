// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** RFC 9110 §5.6.7's IMF-fixdate, a C2SP mirror's `If-Modified-Since` (spec §7.3). */
class ImfFixdateTest {
    @Test
    fun `RFC 9110's own example and the epoch`() {
        assertEquals("Sun, 06 Nov 1994 08:49:37 GMT", ImfFixdate.format(784_111_777_000))
        assertEquals("Thu, 01 Jan 1970 00:00:00 GMT", ImfFixdate.format(0))
    }

    @Test
    fun `milliseconds are dropped, never rounded`() {
        assertEquals("Sun, 06 Nov 1994 08:49:37 GMT", ImfFixdate.format(784_111_777_999))
    }

    @Test
    fun `leap days, century rules and the last representable second`() {
        assertEquals("Thu, 29 Feb 2024 12:00:00 GMT", ImfFixdate.format(1_709_208_000_000))
        assertEquals("Tue, 29 Feb 2000 23:59:59 GMT", ImfFixdate.format(951_868_799_000))
        assertEquals("Mon, 01 Mar 2100 00:00:00 GMT", ImfFixdate.format(4_107_542_400_000))
        assertEquals("Fri, 31 Dec 9999 23:59:59 GMT", ImfFixdate.format(ImfFixdate.MAX_MILLIS))
    }

    @Test
    fun `a time before the epoch or past year 9999 has no IMF-fixdate`() {
        assertNull(ImfFixdate.format(-1))
        assertNull(ImfFixdate.format(ImfFixdate.MAX_MILLIS + 1))
        assertNull(ImfFixdate.format(Long.MAX_VALUE))
    }
}
