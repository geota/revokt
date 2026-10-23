// SPDX-FileCopyrightText: Mozilla Foundation and clubcard contributors; translation 2026 revokt contributors
// SPDX-License-Identifier: MPL-2.0
// Translation of clubcard 0.3.4 src/equation.rs (git ecca8d1a9e92f9f3b4b910c05fe11c190836501e), spec §3.1.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dev.revokt.clubcard.port

import dev.revokt.clubcard.RevoktInternalApi

/**
 * The word width `W` of every equation and filter column: `clubcard-crlite` instantiates `Clubcard<4, …>`, and
 * revokt ports that instantiation only (spec §6.2). A plain `val`, never `const`, so it is read, not inlined.
 */
@RevoktInternalApi
public val WORD_WIDTH: Int = 4

/**
 * An `Equation` is a representation of a GF(2) linear functional `a(x) = b + sum_i a_i x_i` where `a_i` is zero
 * except for `i` in a block of `64 * W` coefficients starting at `i = s`. An equation is *aligned* if `a_s = 1`.
 * (`a_i` above denotes the i-th bit, not the i-th 64-bit limb.)
 *
 * `s` is a `Long` because upstream's `usize` offsets are 32-bit in the v4 encoding and their sum must not overflow.
 */
@RevoktInternalApi
public class Equation(
    s: Long,
    /** The non-trivial columns; exactly [WORD_WIDTH] limbs. */
    public val a: LongArray,
    b: Int,
) {
    /** The row number. Written only by [add] and the `AsQuery` offset shifts in this module. */
    public var s: Long = s
        internal set

    /** The constant term, 0 or 1. */
    public var b: Int = b
        private set

    init {
        require(a.size == WORD_WIDTH) { "an Equation carries exactly $WORD_WIDTH limbs, got ${a.size}" }
    }

    /** Is this `a(x) = 1` or `a(x) = 0`? */
    public fun isZero(): Boolean = a.all { it == 0L }

    /**
     * Adds [other] into this, i.e. sets `a ^= other.a` and `b ^= other.b`, and then aligns the result.
     */
    public fun add(other: Equation) {
        require(s == other.s) { "equations must share a row to be added ($s != ${other.s})" }
        // Add the equations in GF(2).
        for (i in 0 until WORD_WIDTH) {
            a[i] = a[i] xor other.a[i]
        }
        b = b xor other.b
        // Exit early if this equation is now zero.
        if (isZero()) return
        // Shift until there is a non-zero bit in the lowest limb.
        while (a[0] == 0L) {
            a.rotateLeftOnce()
        }
        // Shift the first non-zero bit to position 0.
        val k = a[0].countTrailingZeroBits()
        if (k == 0) return
        for (i in 0 until WORD_WIDTH - 1) {
            a[i] = a[i] ushr k
            a[i] = a[i] or (a[i + 1] shl (64 - k))
        }
        a[WORD_WIDTH - 1] = a[WORD_WIDTH - 1] ushr k
        // Update the starting position.
        s += k
    }

    /**
     * Computes `a(z) = sum a_i z_i` over the column [z]. Only `64 * W` bits of `z` starting from position `s` matter;
     * a window past the end of the column reads as zero (bounds-checked exactly as upstream, so a column with or
     * without the §6.4 pad word evaluates alike).
     */
    public fun eval(z: LongArray): Int {
        val limb = s / 64
        if (limb >= z.size) return 0
        val first = limb.toInt()
        val shift = (s % 64).toInt()
        val end = minOf(z.size, first + WORD_WIDTH)
        var r = 0L
        for (i in first until end) {
            var tmp = z[i] ushr shift
            if (i + 1 < z.size && shift != 0) {
                tmp = tmp or (z[i + 1] shl (64 - shift))
            }
            r = r xor (tmp and a[i - first])
        }
        return r.countOneBits() and 1
    }

    override fun equals(other: Any?): Boolean =
        this === other || (other is Equation && s == other.s && b == other.b && a.contentEquals(other.a))

    override fun hashCode(): Int = (s.hashCode() * 31 + a.contentHashCode()) * 31 + b

    override fun toString(): String =
        "Equation(s=$s, a=${a.joinToString(prefix = "[", postfix = "]") { it.toULong().toString(16) }}, b=$b)"

    @RevoktInternalApi
    public companion object {
        /** Construct the equation `a(x) = sum_{i=s}^{s+64*W} a_i x^i`. The result is aligned. */
        public fun homogeneous(
            s: Long,
            a: LongArray,
        ): Equation = inhomogeneous(s, a, 0)

        /** Construct the equation `a(x) = b + sum_{i=s}^{s+64*W} a_i x^i`. The result is aligned. */
        public fun inhomogeneous(
            s: Long,
            a: LongArray,
            b: Int,
        ): Equation {
            val eq = Equation(0, a.copyOf(), b)
            eq.add(zero())
            eq.s += s
            return eq
        }

        /** Construct the equation `a(x) = 0`. */
        public fun zero(): Equation = Equation(0, LongArray(WORD_WIDTH), 0)
    }
}

/** `[u64; W]::rotate_left(1)`: the first limb moves to the end (`copyInto` allows the overlap). */
private fun LongArray.rotateLeftOnce() {
    val first = this[0]
    copyInto(this, destinationOffset = 0, startIndex = 1)
    this[lastIndex] = first
}
