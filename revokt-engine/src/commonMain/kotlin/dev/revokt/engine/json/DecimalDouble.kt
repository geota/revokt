// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

/**
 * The nearest double to a decimal (ties to even), exactly, in common Kotlin, for every non-integer number the parser
 * reads: the result does not depend on a platform's `String.toDouble()`, and no `String` is made and the buffers are
 * reused across the numbers of one parse (spec §6.5's allocation budget). Short decimals take Clinger's fast path.
 *
 * The decimal is `D × 10^E` with `D` its first [MAX_DIGITS] significant digits; any non-zero digit beyond them only
 * makes the value larger than `D × 10^E` by less than a unit in its last digit, which no double's rounding boundary can
 * lie inside (a midpoint between two doubles has at most 768 significant digits), so it is a sticky bit. With `value =
 * P / Q`, `P = D × 10^max(E, 0)` and `Q = 10^max(-E, 0)`, the quotient `floor(P × 2^k / Q)` for the right `k` (long
 * division, [Big.divRem]) holds the 53-bit mantissa, its next bit and, with the remainder, every bit below.
 */
internal class DecimalDouble {
    private val p = Big.of(0, LIMBS)
    private val q = Big.of(0, LIMBS)

    // The decimal being read: digits end where the exponent starts, the point (or end) and the first non-zero digit.
    private var end = 0
    private var point = 0
    private var first = 0

    /**
     * The decimal number in `[from, to)` of [b]: valid JSON number syntax without the sign. Infinite when too large.
     */
    fun parse(
        b: ByteArray,
        from: Int,
        to: Int,
    ): Double {
        scan(b, from, to)
        if (first == end) return 0.0
        // The value is 0.d1d2… × 10^dp.
        val dp =
            (if (first < point) point - first else point + 1 - first) + if (end < to) exponent(b, end + 1, to) else 0L
        if (dp > 310) return Double.POSITIVE_INFINITY
        if (dp < -324) return 0.0
        val digits = significantDigits()
        if (digits <= 16) {
            val fast = fast(b, (dp - digits).toInt())
            if (!fast.isNaN()) return fast
        }
        val kept = minOf(digits, MAX_DIGITS)
        val truncated = readDigits(b, kept)
        val e = (dp - kept).toInt()
        q.set(1)
        if (e >= 0) p.mulPow10(e) else q.mulPow10(-e)
        return divide(truncated)
    }

    private fun scan(
        b: ByteArray,
        from: Int,
        to: Int,
    ) {
        end = from
        while (end < to && b[end] != 'e'.code.toByte() && b[end] != 'E'.code.toByte()) end++
        point = from
        while (point < end && b[point] != '.'.code.toByte()) point++
        first = from
        while (first < end && (b[first] == '0'.code.toByte() || b[first] == '.'.code.toByte())) first++
    }

    /** The digits from the first significant one to the end of the mantissa, the point excluded. */
    private fun significantDigits(): Int = end - first - if (point in first until end) 1 else 0

    /**
     * Clinger's fast path: with at most 16 digits below 2^53 and a decimal exponent [e] within ±22, one IEEE
     * multiplication or division of two exact doubles is the correctly rounded result. NaN when it does not apply.
     */
    private fun fast(
        b: ByteArray,
        e: Int,
    ): Double {
        if (e !in -22..22) return Double.NaN
        var significand = 0L
        for (i in first until end) {
            if (b[i] !=
                '.'.code.toByte()
            ) {
                significand = significand * 10 + (b[i] - '0'.code.toByte())
            }
        }
        if (significand > 1L shl 53) return Double.NaN
        return if (e >= 0) significand.toDouble() * EXACT_POWERS[e] else significand.toDouble() / EXACT_POWERS[-e]
    }

    /** Reads the first [kept] significant digits into p; true when a non-zero digit follows them. */
    private fun readDigits(
        b: ByteArray,
        kept: Int,
    ): Boolean {
        p.set(0)
        var read = 0
        for (i in first until end) {
            val c = b[i]
            if (c == '.'.code.toByte()) continue
            if (read == kept) {
                if (c != '0'.code.toByte()) return true
            } else {
                p.mulSmall(10).addSmall(c - '0'.code.toByte())
                read++
            }
        }
        return false
    }

    /** The exponent in `[from, to)`: an optional sign and digits, saturated far beyond any double's range. */
    private fun exponent(
        b: ByteArray,
        from: Int,
        to: Int,
    ): Long {
        val negative = b[from] == '-'.code.toByte()
        var e = 0L
        for (i in (if (negative || b[from] == '+'.code.toByte()) from + 1 else from) until to) {
            if (e < 1_000_000_000L) e = e * 10 + (b[i] - '0'.code.toByte())
        }
        return if (negative) -e else e
    }

    /** The double nearest `p / q`, rounding half to even, `truncated` meaning the true value is a little above it. */
    private fun divide(truncated: Boolean): Double {
        // p / q lies in (2^(d - 1), 2^(d + 1)); scale so that the quotient has 54 or 55 bits, or to the subnormal unit.
        // Below 2^-1021 the quotient is taken at the subnormal unit, 2^-1074, and may have fewer bits.
        val k = minOf(54 - (p.bitLength() - q.bitLength()), 1074)
        if (k >= 0) p.mulPow2(k) else q.mulPow2(-k)
        // p becomes the remainder; both are rescaled alike, so `2 × remainder` against q still holds.
        val quotient = p.divRem(q)
        val extra = maxOf(0, 64 - quotient.countLeadingZeroBits() - 53)
        var mantissa = quotient ushr extra
        val roundBit: Boolean
        val sticky: Boolean
        if (extra > 0) {
            roundBit = (quotient ushr (extra - 1)) and 1L == 1L
            sticky = quotient and ((1L shl (extra - 1)) - 1) != 0L || !p.isZero || truncated
        } else {
            // The remainder is in p: compare 2 × remainder with q.
            val c = p.mulPow2(1).compareTo(q)
            roundBit = c >= 0
            sticky = c != 0 || truncated
        }
        if (roundBit && (sticky || mantissa and 1L == 1L)) mantissa++
        var exponent = extra - k
        if (mantissa == 1L shl 53) {
            mantissa = mantissa ushr 1
            exponent++
        }
        return compose(mantissa, exponent)
    }

    /** `mantissa × 2^exponent` as a double: subnormal when the mantissa is below 2^52, infinite when too large. */
    private fun compose(
        mantissa: Long,
        exponent: Int,
    ): Double {
        if (mantissa < 1L shl 52) return Double.fromBits(mantissa)
        val biased = exponent + 52 + 1023
        if (biased >= 2047) return Double.POSITIVE_INFINITY
        return Double.fromBits((biased.toLong() shl 52) or (mantissa and 0xF_FFFF_FFFF_FFFFL))
    }

    companion object {
        /** 10^0 to 10^22, every one exact as a double. */
        private val EXACT_POWERS =
            DoubleArray(23).also { p ->
                p[0] = 1.0
                for (i in 1 until p.size) p[i] = p[i - 1] * 10.0
                // Double.fromBits goes through Double's companion object; touching it with this class keeps the first
                // number off the fast path from loading that class inside a measured parse (spec §6.5).
                check(Double.fromBits(0L) == 0.0)
            }

        /**
         * The 768 significant digits that decide every double's rounding: a midpoint between two doubles has at most
         * 768 (the one below the smallest normal has exactly 768), so none lies strictly inside the gap a dropped
         * non-zero digit leaves.
         */
        const val MAX_DIGITS = 768

        /** 768 digits (2 552 bits) times 2^1074, or 10^1092 (3 628 bits) times 2^55, plus a normalising shift. */
        const val LIMBS = 136
    }
}
