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

            // The smallest normal: the neighbour below is half as far.
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
        val mant = Big(dMant)
        val minus = Big(dMinus)
        val plus = Big(dPlus)
        val scale = Big(1)
        val sum = Big(0)
        var k = estimateScalingFactor(dMant + dPlus, dExp)
        private val bounds = listOf(mant, minus, plus)

        init {
            if (dExp < 0) scale.mulPow2(-dExp) else bounds.forEach { it.mulPow2(dExp) }
            if (k >= 0) scale.mulPow10(k) else bounds.forEach { it.mulPow10(-k) }
            if (below(scale, sum.setSum(mant, plus))) k++ else timesTen()
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

    /** `div_rem_upto_16`: the digit `floor(mant / scale)`, leaving the remainder in [mant]; [multiples] is 8, 4, 2, 1 × scale. */
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

    /** An unsigned integer of [SIZE] 32-bit limbs, little-endian, as Rust's `Big32x40`; overflow is an error. */
    private class Big private constructor(
        private val limbs: IntArray,
    ) : Comparable<Big> {
        constructor(v: Long) : this(IntArray(SIZE)) {
            limbs[0] = v.toInt()
            limbs[1] = (v ushr 32).toInt()
        }

        fun copy(): Big = Big(limbs.copyOf())

        /** Multiplies by [m], below 2^31, so each limb product and carry fits a [Long]. */
        fun mulSmall(m: Int): Big {
            var carry = 0L
            for (i in 0 until SIZE) {
                val p = (limbs[i].toLong() and MASK) * m + carry
                limbs[i] = p.toInt()
                carry = p ushr 32
            }
            check(carry == 0L) { "bignum overflow" }
            return this
        }

        fun mulPow10(n: Int): Big {
            var left = n
            while (left >= 9) {
                mulSmall(1_000_000_000)
                left -= 9
            }
            return mulSmall(POW10[left])
        }

        fun mulPow2(n: Int): Big {
            val words = n ushr 5
            val shift = n and 31
            check(bitLength() + n <= SIZE * 32) { "bignum overflow" }
            for (i in SIZE - 1 downTo 0) {
                val hi = if (i - words >= 0) limbs[i - words] else 0
                val lo = if (i - words - 1 >= 0) limbs[i - words - 1] else 0
                limbs[i] = if (shift == 0) hi else (hi shl shift) or (lo ushr (32 - shift))
            }
            return this
        }

        /** Sets this to [a] + [b]. */
        fun setSum(
            a: Big,
            b: Big,
        ): Big {
            var carry = 0L
            for (i in 0 until SIZE) {
                val s = (a.limbs[i].toLong() and MASK) + (b.limbs[i].toLong() and MASK) + carry
                limbs[i] = s.toInt()
                carry = s ushr 32
            }
            check(carry == 0L) { "bignum overflow" }
            return this
        }

        /** Subtracts [other], at most this. */
        fun sub(other: Big) {
            var borrow = 0L
            for (i in 0 until SIZE) {
                val d = (limbs[i].toLong() and MASK) - (other.limbs[i].toLong() and MASK) - borrow
                limbs[i] = d.toInt()
                borrow = if (d < 0) 1L else 0L
            }
            check(borrow == 0L) { "bignum underflow" }
        }

        private fun bitLength(): Int {
            for (i in SIZE - 1 downTo 0) {
                if (limbs[i] != 0) return i * 32 + 32 - limbs[i].countLeadingZeroBits()
            }
            return 0
        }

        override fun compareTo(other: Big): Int {
            for (i in SIZE - 1 downTo 0) {
                if (limbs[i] !=
                    other.limbs[i]
                ) {
                    return (limbs[i].toLong() and MASK).compareTo(other.limbs[i].toLong() and MASK)
                }
            }
            return 0
        }

        companion object {
            const val SIZE = 40
            const val MASK = 0xFFFF_FFFFL
            val POW10 = intArrayOf(1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)
        }
    }
}
