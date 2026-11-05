// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

/**
 * Rust's `format!("{:e}", f64)` with the exponent marker capitalised, which is what `canonical_json` 0.7.0 writes for a
 * float (its `normalize_number` regex only uppercases the `e`, since Rust writes no `+` and no leading exponent zero).
 * The digits are the shortest that round-trip, nearest the exact value: a port of Rust core's `flt2dec` decoder and
 * `strategy::dragon::format_shortest` (Burger and Dybvig's free-format algorithm). `{:e}` runs Grisu first and falls
 * back to Dragon whenever Grisu cannot guarantee the shortest nearest digits, which Dragon always produces.
 */
internal object ShortestDouble {
    /** Rust's `Big32x40`: 1280 bits hold every intermediate of a double's shortest digits. */
    private const val LIMBS = 40

    fun exponential(v: Double): String {
        require(v.isFinite()) { "not finite: $v" }
        val bits = v.toRawBits()
        val sign = if (bits < 0) "-" else ""
        if (v == 0.0) return sign + "0E0"
        val (digits, k) = shortest(bits)
        val out = StringBuilder(sign).append(digits[0])
        if (digits.length > 1) out.append('.').append(digits, 1, digits.length)
        return out.append('E').append(k - 1).toString()
    }

    /** The digits `d` and exponent `k` of `0.d × 10^k`, for a finite non-zero double's [bits]. */
    private fun shortest(bits: Long): Pair<String, Int> {
        // flt2dec::decoder::decode over f64::integer_decode: v = mant × 2^exp, rounding to it from (mant - minus) to
        // (mant + plus), bounds included when `inclusive`.
        val field = ((bits ushr 52) and 0x7FF).toInt()
        val fraction = bits and 0xF_FFFF_FFFF_FFFFL
        val m = if (field == 0) fraction shl 1 else fraction or (1L shl 52)
        val e = (if (field == 0) 0 else field) - 1075
        val inclusive = m and 1L == 0L
        return when {
            // Subnormal: neighbours (m - 2, e) and (m + 2, e), integer_decode having doubled m.
            field == 0 -> dragon(m, 1L, 1L, e, inclusive)

            // A normal power of two (zero fraction: Rust compares with the smallest normal's mantissa, 2^52, which
            // every power of two shares): the neighbour below is half as far.
            m == 1L shl 52 -> dragon(m shl 2, 1L, 2L, e - 2, inclusive)

            else -> dragon(m shl 1, 1L, 1L, e - 1, inclusive)
        }
    }

    /** `strategy::dragon::format_shortest`, step for step. */
    private fun dragon(
        dMant: Long,
        dMinus: Long,
        dPlus: Long,
        dExp: Int,
        inclusive: Boolean,
    ): Pair<String, Int> {
        val s = Scaled(dMant, dMinus, dPlus, dExp, inclusive)
        val digits = StringBuilder()
        var down: Boolean
        var up: Boolean
        while (true) {
            digits.append('0' + nextDigit(s.mant, s.multiples))
            down = s.below(s.mant, s.minus)
            up = s.below(s.scale, s.sum.setSum(s.mant, s.plus))
            if (down || up) break
            s.timesTen()
        }
        // Round up when only the upper condition holds, or on a tie-break towards it.
        val roundsUp = up && (!down || s.mant.mulPow2(1) >= s.scale)
        val k = if (roundsUp && roundUp(digits)) s.k + 1 else s.k
        return digits.toString() to k
    }

    /**
     * `format_shortest`'s set-up: `v = mant / scale`, `low = (mant - minus) / scale`, `high = (mant + plus) / scale`,
     * divided by `10^k` so that `scale < mant + plus <= 10 × scale`, the bounds compared inclusively or not as
     * [inclusive] says.
     */
    private class Scaled(
        dMant: Long,
        dMinus: Long,
        dPlus: Long,
        dExp: Int,
        val inclusive: Boolean,
    ) {
        val mant = Big.of(dMant, LIMBS)
        val minus = Big.of(dMinus, LIMBS)
        val plus = Big.of(dPlus, LIMBS)
        val scale = Big.of(1, LIMBS)
        val sum = Big.of(0, LIMBS)
        var k = estimateScalingFactor(dMant + dPlus, dExp)
        private val bounds = listOf(mant, minus, plus)

        init {
            if (dExp < 0) scale.mulPow2(-dExp) else bounds.forEach { it.mulPow2(dExp) }
            if (k >= 0) scale.mulPow10(k) else timesPow10(-k, dMant, dMinus, dPlus)
            if (below(scale, sum.setSum(mant, plus))) k++ else timesTen()
        }

        /**
         * mant, minus and plus times 10^[n], with the power computed once (k < 0 only for values below 1, where dExp is
         * negative and the three still hold dMant, dMinus and dPlus); the mantissa, below 2^55, in two parts below
         * 2^31.
         */
        private fun timesPow10(
            n: Int,
            dMant: Long,
            dMinus: Long,
            dPlus: Long,
        ) {
            minus.set(1).mulPow10(n)
            plus.set(minus).mulSmall(dPlus.toInt())
            mant.set(minus).mulSmall((dMant and 0x7FFF_FFFF).toInt())
            sum.set(minus).mulSmall((dMant ushr 31).toInt()).mulPow2(31)
            mant.setSum(mant, sum)
            minus.mulSmall(dMinus.toInt())
        }

        /** 8, 4, 2 and 1 × scale, for [nextDigit]. */
        val multiples = listOf(scale.copy().mulPow2(3), scale.copy().mulPow2(2), scale.copy().mulPow2(1), scale)

        /** `a.cmp(&b) < rounding`: `a <= b` when inclusive, else `a < b`. */
        fun below(
            a: Big,
            b: Big,
        ): Boolean = a.compareTo(b).let { if (inclusive) it <= 0 else it < 0 }

        fun timesTen() = bounds.forEach { it.mulSmall(10) }
    }

    /**
     * `div_rem_upto_16`: the digit `floor(mant / scale)`, leaving the remainder in [mant]; [multiples] is 8, 4, 2, 1 ×
     * scale.
     */
    private fun nextDigit(
        mant: Big,
        multiples: List<Big>,
    ): Int {
        var d = 0
        for (i in multiples.indices) {
            if (mant >= multiples[i]) {
                mant.sub(multiples[i])
                d += 8 shr i
            }
        }
        return d
    }

    /** `flt2dec::round_up`; true when an all-nines buffer became `10…0`, one digit longer, so the exponent grows. */
    private fun roundUp(digits: StringBuilder): Boolean {
        val i = digits.indexOfLast { it != '9' }
        for (j in i + 1 until digits.length) digits[j] = '0'
        if (i >= 0) {
            digits[i] = digits[i] + 1
            return false
        }
        digits[0] = '1'
        digits.append('0')
        return true
    }

    /** `estimator::estimate_scaling_factor`: `k_0` with `10^(k_0 - 1) < mant × 2^exp <= 10^(k_0 + 1)`. */
    private fun estimateScalingFactor(
        mant: Long,
        exp: Int,
    ): Int {
        val nbits = 64 - (mant - 1).countLeadingZeroBits()
        return (((nbits + exp).toLong() * 1_292_913_986L) shr 32).toInt()
    }
}
