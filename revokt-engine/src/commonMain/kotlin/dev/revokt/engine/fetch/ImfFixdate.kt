// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

/**
 * RFC 9110 §5.6.7's IMF-fixdate, the one form a sender generates for an HTTP date: `Sun, 06 Nov 1994 08:49:37 GMT`, in
 * UTC, to the second. Used for a C2SP mirror's `If-Modified-Since` (spec §7.3).
 */
internal object ImfFixdate {
    /** 9999-12-31T23:59:59.999Z: IMF-fixdate's year is four digits. */
    const val MAX_MILLIS: Long = 253_402_300_799_999

    private const val MILLIS_PER_SECOND = 1_000L
    private const val SECONDS_PER_DAY = 86_400L
    private const val SECONDS_PER_HOUR = 3_600L
    private const val SECONDS_PER_MINUTE = 60L
    private const val DAYS_PER_WEEK = 7L

    /** 1970-01-01 was a Thursday, index 4 of [DAYS] counted from Sunday. */
    private const val EPOCH_WEEKDAY = 4L

    private val DAYS = listOf("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
    private val MONTHS = listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

    /**
     * [epochMillis] as an IMF-fixdate, its milliseconds dropped (an HTTP date has whole seconds), or null outside
     * 1970-01-01T00:00:00Z to [MAX_MILLIS], which has no four-digit year or reads as before the epoch.
     */
    fun format(epochMillis: Long): String? {
        if (epochMillis !in 0..MAX_MILLIS) return null
        val seconds = epochMillis / MILLIS_PER_SECOND
        val days = seconds / SECONDS_PER_DAY
        val ofDay = seconds % SECONDS_PER_DAY
        val (year, month, day) = civil(days)
        val weekday = DAYS[((days + EPOCH_WEEKDAY) % DAYS_PER_WEEK).toInt()]
        return weekday + ", " + two(day) + " " + MONTHS[month - 1] + " " + year.toString().padStart(4, '0') + " " +
            two(ofDay / SECONDS_PER_HOUR) + ":" + two(ofDay % SECONDS_PER_HOUR / SECONDS_PER_MINUTE) + ":" +
            two(ofDay % SECONDS_PER_MINUTE) + " GMT"
    }

    private fun two(n: Number): String = n.toString().padStart(2, '0')

    /**
     * The proleptic Gregorian (year, month 1 to 12, day 1 to 31) of [days] since 1970-01-01, for [days] ≥ 0: Howard
     * Hinnant's `civil_from_days`, over 400-year eras of 146097 days counted from 0000-03-01.
     */
    @Suppress("MagicNumber") // The calendar's own constants, named in the KDoc.
    private fun civil(days: Long): Triple<Long, Int, Int> {
        val z = days + 719_468
        val era = z / 146_097
        val doe = z - era * 146_097
        val yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365
        val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        val mp = (5 * doy + 2) / 153
        val day = (doy - (153 * mp + 2) / 5 + 1).toInt()
        val month = (if (mp < 10) mp + 3 else mp - 9).toInt()
        val year = yoe + era * 400 + if (month <= 2) 1 else 0
        return Triple(year, month, day)
    }
}
