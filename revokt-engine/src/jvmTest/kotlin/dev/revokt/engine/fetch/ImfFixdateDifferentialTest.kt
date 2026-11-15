// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

/** [ImfFixdate] against `java.time`'s formatter for RFC 9110's IMF-fixdate pattern, over the whole range it formats. */
class ImfFixdateDifferentialTest {
    private val imf = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US).withZone(ZoneOffset.UTC)

    @Test
    fun `every sampled time formats as java time formats it`() {
        val random = Random(194)
        val samples =
            (0 until 200_000).map { random.nextLong(0, ImfFixdate.MAX_MILLIS + 1) } +
                (0 until 20_000).map { random.nextLong(0, 4_102_444_800_000) } +
                listOf(0L, 86_399_999L, 86_400_000L, 951_782_400_000L, 951_868_800_000L, ImfFixdate.MAX_MILLIS)
        for (millis in samples) {
            assertEquals(imf.format(Instant.ofEpochMilli(millis)), ImfFixdate.format(millis), "$millis")
        }
    }
}
