// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

/**
 * A mutable unsigned integer of up to `capacity` 32-bit limbs, little-endian, like Rust core's `num::bignum` types:
 * [size] limbs are in use and every operation loops over those only; outgrowing the capacity is an error.
 */
internal class Big private constructor(
    private val limbs: IntArray,
    private var size: Int,
) : Comparable<Big> {
    fun copy(): Big = Big(limbs.copyOf(), size)

    /** Multiplies by [m], below 2^31, so each limb product and carry fits a [Long]. */
    fun mulSmall(m: Int): Big {
        var carry = 0L
        for (i in 0 until size) {
            val p = (limbs[i].toLong() and MASK) * m + carry
            limbs[i] = p.toInt()
            carry = p ushr 32
        }
        if (carry != 0L) append(carry.toInt())
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
        if (size == 0) return this
        val words = n ushr 5
        val shift = n and 31
        val grown = size + words + if (shift == 0) 0 else 1
        check(grown <= limbs.size || bitLength() + n <= limbs.size * 32) { "bignum overflow" }
        val top = minOf(grown, limbs.size)
        for (i in top - 1 downTo 0) {
            val hi = if (i - words >= 0) limbs[i - words] else 0
            val lo = if (i - words - 1 >= 0) limbs[i - words - 1] else 0
            limbs[i] = if (shift == 0) hi else (hi shl shift) or (lo ushr (32 - shift))
        }
        size = top
        trim()
        return this
    }

    /** Sets this to [a] + [b]. */
    fun setSum(
        a: Big,
        b: Big,
    ): Big {
        val n = maxOf(a.size, b.size)
        var carry = 0L
        for (i in 0 until n) {
            val s = (a.limbs[i].toLong() and MASK) + (b.limbs[i].toLong() and MASK) + carry
            limbs[i] = s.toInt()
            carry = s ushr 32
        }
        for (i in n until size) limbs[i] = 0
        size = n
        if (carry != 0L) append(carry.toInt())
        trim()
        return this
    }

    /** Subtracts [other], at most this. */
    fun sub(other: Big) {
        var borrow = 0L
        for (i in 0 until size) {
            val d = (limbs[i].toLong() and MASK) - (other.limbs[i].toLong() and MASK) - borrow
            limbs[i] = d.toInt()
            borrow = if (d < 0) 1L else 0L
        }
        check(borrow == 0L) { "bignum underflow" }
        trim()
    }

    /** Sets this to [v], read as unsigned. */
    fun set(v: Long): Big {
        for (i in 0 until size) limbs[i] = 0
        limbs[0] = v.toInt()
        limbs[1] = (v ushr 32).toInt()
        size = 2
        trim()
        return this
    }

    /** Sets this to [other], which must fit. */
    fun set(other: Big): Big {
        for (i in other.size until size) limbs[i] = 0
        other.limbs.copyInto(limbs, 0, 0, other.size)
        size = other.size
        return this
    }

    /** Adds [v], below 2^31. */
    fun addSmall(v: Int): Big {
        var carry = v.toLong()
        var i = 0
        while (carry != 0L) {
            if (i == size) {
                append(carry.toInt())
                return this
            }
            val s = (limbs[i].toLong() and MASK) + carry
            limbs[i++] = s.toInt()
            carry = s ushr 32
        }
        return this
    }

    /** Halves this, dropping the low bit. */
    fun shr1(): Big {
        for (i in 0 until size) {
            val high = if (i + 1 < size) limbs[i + 1] shl 31 else 0
            limbs[i] = (limbs[i] ushr 1) or high
        }
        trim()
        return this
    }

    val isZero: Boolean get() = size == 0

    /**
     * Divides this by [divisor] (Knuth's algorithm D over 32-bit digits) and returns the quotient, which must be below
     * 2^63. Both numbers are first shifted left by the same amount, so that the divisor's top bit is set; this is left
     * holding the remainder at that scale, so comparisons between the two still hold.
     */
    fun divRem(divisor: Big): Long {
        val shift = divisor.limbs[divisor.size - 1].countLeadingZeroBits()
        mulPow2(shift)
        divisor.mulPow2(shift)
        val n = divisor.size
        if (size < n) return 0
        check(size < limbs.size) { "bignum overflow" }
        val v = divisor.limbs
        val vTop = v[n - 1].toULong() and UMASK
        val vNext = if (n >= 2) v[n - 2].toULong() and UMASK else 0uL
        var quotient = 0L
        for (j in size - n downTo 0) {
            val top = ((limbs[j + n].toULong() and UMASK) shl 32) or (limbs[j + n - 1].toULong() and UMASK)
            var qhat = top / vTop
            var rhat = top % vTop
            val below = if (n >= 2) limbs[j + n - 2].toULong() and UMASK else 0uL
            while (qhat > UMASK || qhat * vNext > ((rhat shl 32) or below)) {
                qhat--
                rhat += vTop
                if (rhat > UMASK) break
            }
            if (subtractTimes(qhat, divisor, j)) {
                qhat--
                addAt(divisor, j)
            }
            check(quotient ushr 31 == 0L) { "quotient overflow" }
            quotient = (quotient shl 32) or qhat.toLong()
        }
        size = minOf(size, n)
        trim()
        return quotient
    }

    /** Subtracts [qhat] × [v] from the limbs at [at]; true when that went below zero. */
    private fun subtractTimes(
        qhat: ULong,
        v: Big,
        at: Int,
    ): Boolean {
        var carry = 0uL
        var borrow = 0L
        for (i in 0 until v.size) {
            val product = qhat * (v.limbs[i].toULong() and UMASK) + carry
            carry = product shr 32
            val t = (limbs[i + at].toLong() and MASK) - (product and UMASK).toLong() - borrow
            limbs[i + at] = t.toInt()
            borrow = if (t < 0) 1L else 0L
        }
        val t = (limbs[at + v.size].toLong() and MASK) - carry.toLong() - borrow
        limbs[at + v.size] = t.toInt()
        return t < 0
    }

    /** Adds [v] to the limbs at [at], dropping the final carry (algorithm D's add-back). */
    private fun addAt(
        v: Big,
        at: Int,
    ) {
        var carry = 0L
        for (i in 0 until v.size) {
            val s = (limbs[i + at].toLong() and MASK) + (v.limbs[i].toLong() and MASK) + carry
            limbs[i + at] = s.toInt()
            carry = s ushr 32
        }
        limbs[at + v.size] += carry.toInt()
    }

    override fun compareTo(other: Big): Int {
        if (size != other.size) return size.compareTo(other.size)
        for (i in size - 1 downTo 0) {
            if (limbs[i] !=
                other.limbs[i]
            ) {
                return (limbs[i].toLong() and MASK).compareTo(other.limbs[i].toLong() and MASK)
            }
        }
        return 0
    }

    private fun append(limb: Int) {
        check(size < limbs.size) { "bignum overflow" }
        limbs[size++] = limb
    }

    /** Drops leading zero limbs, so [size] is exact and [compareTo] can compare sizes first. */
    private fun trim() {
        while (size > 0 && limbs[size - 1] == 0) size--
    }

    fun bitLength(): Int = if (size == 0) 0 else size * 32 - limbs[size - 1].countLeadingZeroBits()

    companion object {
        private const val MASK = 0xFFFF_FFFFL
        private const val UMASK = 0xFFFF_FFFFuL
        private val POW10 = intArrayOf(1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)

        /** [v], read as unsigned, in a number of [capacity] limbs. */
        fun of(
            v: Long,
            capacity: Int,
        ): Big =
            Big(IntArray(capacity), 0).apply {
                limbs[0] = v.toInt()
                limbs[1] = (v ushr 32).toInt()
                size = 2
                trim()
            }
    }
}
