// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/** K5's value domains (spec §9.2): Go's PrintableString set with `*` and `&`, valid UTF-8, ASCII IA5String. */
internal object DirectoryStrings {
    private const val UTF8_STRING = 0x0c
    private const val PRINTABLE_STRING = 0x13
    private const val IA5_STRING = 0x16
    private const val PRINTABLE_PUNCTUATION = " '()+,-./:=?*&"

    fun valid(
        tag: Int,
        b: ByteArray,
        content: Span,
    ): Boolean =
        when (tag) {
            PRINTABLE_STRING -> (content.start until content.end).all { printable(b[it].toInt() and 0xff) }
            UTF8_STRING -> utf8(b, content)
            IA5_STRING -> (content.start until content.end).all { b[it] >= 0 }
            else -> false
        }

    private fun printable(c: Int): Boolean =
        c in 'a'.code..'z'.code || c in 'A'.code..'Z'.code || c in '0'.code..'9'.code ||
            PRINTABLE_PUNCTUATION.indexOf(c.toChar()) >= 0

    /** Well-formed UTF-8 as Go's `utf8.Valid` reads it: shortest forms only, no surrogates, nothing above U+10FFFF. */
    private fun utf8(
        b: ByteArray,
        content: Span,
    ): Boolean {
        var i = content.start
        while (i < content.end) {
            val (count, low, high) = utf8Lead(b[i].toInt() and 0xff) ?: return false
            if (content.end - i - 1 < count) return false
            // Only the first continuation octet has a narrowed range; the rest are 80..BF.
            if (count > 0 && (b[i + 1].toInt() and 0xff) !in low..high) return false
            if ((2..count).any { (b[i + it].toInt() and 0xff) !in 0x80..0xbf }) return false
            i += count + 1
        }
        return true
    }

    /** For a lead octet: the continuation count and the first continuation octet's range, or null for an invalid lead. */
    private fun utf8Lead(lead: Int): Triple<Int, Int, Int>? =
        when (lead) {
            in 0x00..0x7f -> Triple(0, 0, 0)
            in 0xc2..0xdf -> Triple(1, 0x80, 0xbf)
            0xe0 -> Triple(2, 0xa0, 0xbf)
            0xed -> Triple(2, 0x80, 0x9f)
            in 0xe1..0xef -> Triple(2, 0x80, 0xbf)
            0xf0 -> Triple(3, 0x90, 0xbf)
            in 0xf1..0xf3 -> Triple(3, 0x80, 0xbf)
            0xf4 -> Triple(3, 0x80, 0x8f)
            else -> null
        }
}

/**
 * K6's times (spec §9.2): `UTCTime` exactly `YYMMDDHHMMSSZ` (YY below 50 is 20YY), `GeneralizedTime` exactly
 * `YYYYMMDDHHMMSSZ` with a year from 1950 to 9999, a real Gregorian date and a time of day up to 23:59:59.
 */
internal object ProfileTime {
    private const val UTC_LENGTH = 13
    private const val GENERALIZED_LENGTH = 15
    private const val FIRST_YEAR = 1950
    private const val LAST_YEAR = 9999

    fun valid(
        tag: Int,
        b: ByteArray,
        content: Span,
    ): Boolean {
        val yearDigits =
            when {
                tag == DerTime.UTC_TIME && content.length == UTC_LENGTH -> 2
                tag == DerTime.GENERALIZED_TIME && content.length == GENERALIZED_LENGTH -> 4
                else -> return false
            }
        if (b[content.end - 1].toInt() != 'Z'.code) return false
        if ((content.start until content.end - 1).any { b[it].toInt() !in '0'.code..'9'.code }) return false
        var year = number(b, content.start, yearDigits)
        if (yearDigits == 2) year += if (year < 50) 2000 else 1900
        val rest = IntArray(5) { number(b, content.start + yearDigits + 2 * it, 2) }
        return year in FIRST_YEAR..LAST_YEAR && dateAndTime(year, rest)
    }

    /** Month, day, hour, minute and second of a year already in range. */
    private fun dateAndTime(
        year: Int,
        f: IntArray,
    ): Boolean = f[0] in 1..12 && f[1] in 1..daysIn(year, f[0]) && f[2] <= 23 && f[3] <= 59 && f[4] <= 59

    private fun number(
        b: ByteArray,
        at: Int,
        width: Int,
    ): Int = (0 until width).fold(0) { acc, k -> acc * 10 + (b[at + k].toInt() - '0'.code) }

    private fun daysIn(
        year: Int,
        month: Int,
    ): Int =
        when (month) {
            2 -> if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) 29 else 28
            4, 6, 9, 11 -> 30
            else -> 31
        }
}
