// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/**
 * Lenient `UTCTime` (`0x17`) and `GeneralizedTime` (`0x18`) decoding to epoch milliseconds (spec §9.2: non-DER times are
 * accepted). Seconds are optional, fractional seconds are truncated to milliseconds, the zone may be `Z`, `±hhmm` or
 * absent (taken as UTC). `UTCTime` years below 50 are 20YY, otherwise 19YY (RFC 5280 §4.1.2.5.1). Anything else
 * decodes to null; the certificate still parses.
 */
internal object DerTime {
    const val UTC_TIME: Int = 0x17
    const val GENERALIZED_TIME: Int = 0x18

    fun decode(
        tag: Int,
        der: ByteArray,
        content: Span,
        ctx: ParseContext,
    ): Long? {
        ctx.steps += content.length
        val c = Cursor(CharArray(content.length) { (der[content.start + it].toInt() and 0xff).toChar() })
        val year = if (tag == UTC_TIME) c.digits(2).let { if (it < 50) 2000 + it else 1900 + it } else c.digits(4)
        val month = c.digits(2)
        val day = c.digits(2)
        val hour = c.digits(2)
        val minute = c.optionalDigits(2)
        val second = c.optionalDigits(2)
        val millis = if (tag == GENERALIZED_TIME) c.optionalFraction() else 0
        val offsetMinutes = c.zone()
        if (!c.complete() || month !in 1..12 || day !in 1..31) return null
        if (hour > 23 || minute > 59 || second > 60) return null
        val minutes = (daysFromCivil(year.toLong(), month, day) * 24 + hour) * 60 + minute - offsetMinutes
        return minutes * 60_000 + second * 1000L + millis
    }

    /** Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`). */
    private fun daysFromCivil(
        y0: Long,
        month: Int,
        day: Int,
    ): Long {
        val y = if (month <= 2) y0 - 1 else y0
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400
        val doy = (153 * (if (month > 2) month - 3 else month + 9) + 2) / 5 + day - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    /** Reads left to right; any malformed field sets [bad] and reads as 0, so [decode] checks once at the end. */
    private class Cursor(
        private val text: CharArray,
    ) {
        private var i = 0
        private var bad = false

        fun complete(): Boolean = !bad && i == text.size

        private fun atDigit(): Boolean = i < text.size && text[i] in '0'..'9'

        fun digits(n: Int): Int {
            var v = 0
            repeat(n) {
                if (!atDigit()) {
                    bad = true
                    return 0
                }
                v = v * 10 + (text[i++] - '0')
            }
            return v
        }

        fun optionalDigits(n: Int): Int = if (atDigit()) digits(n) else 0

        /** `.fff…` or `,fff…` after the seconds, truncated to milliseconds; 0 when there is none. */
        fun optionalFraction(): Int {
            if (i >= text.size || (text[i] != '.' && text[i] != ',')) return 0
            i++
            if (!atDigit()) bad = true
            var millis = 0
            var scale = 100
            while (atDigit()) {
                millis += (text[i++] - '0') * scale
                scale /= 10
            }
            return millis
        }

        /** Minutes east of UTC: 0 for `Z` or no zone, else `±hhmm`. */
        fun zone(): Int {
            if (i == text.size) return 0
            val c = text[i++]
            if (c == 'Z') return 0
            if (c != '+' && c != '-') {
                bad = true
                return 0
            }
            val h = digits(2)
            val m = digits(2)
            if (h > 23 || m > 59) bad = true
            return (if (c == '+') 1 else -1) * (h * 60 + m)
        }
    }
}
