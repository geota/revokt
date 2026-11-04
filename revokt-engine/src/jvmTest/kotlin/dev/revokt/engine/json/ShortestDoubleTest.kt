// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import java.math.BigDecimal
import java.math.MathContext
import java.math.RoundingMode
import java.util.Random
import kotlin.math.abs
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * [ShortestDouble] against the definition of Rust's shortest `{:e}`, checked exactly with [BigDecimal]: the digits
 * read back to the double, no decimal with one digit fewer does, and no decimal of as many digits is nearer the exact
 * value. `CanonicalJsonOracleTest` compares it with Rust itself.
 */
class ShortestDoubleTest {
    private fun check(v: Double) {
        if (!v.isFinite() || v == 0.0) return
        val s = ShortestDouble.exponential(v)
        assertEquals(v, s.toDouble(), s)
        val digits = s.removePrefix("-").substringBefore('E').replace(".", "")
        assertTrue(digits.first() != '0' && (digits.length == 1 || digits.last() != '0'), s)
        val exact = BigDecimal(abs(v))
        if (digits.length > 1) {
            for (mode in listOf(RoundingMode.FLOOR, RoundingMode.CEILING)) {
                val shorter = exact.round(MathContext(digits.length - 1, mode))
                assertNotEquals(abs(v), shorter.toDouble(), "$s: $shorter is shorter")
            }
        }
        val ours = BigDecimal(s.removePrefix("-"))
        for (other in listOf(ours - ours.ulp(), ours + ours.ulp())) {
            if (other.toDouble() == abs(v)) {
                assertTrue((other - exact).abs() >= (ours - exact).abs(), "$s: $other is nearer")
            }
        }
    }

    @Test
    fun `random bit patterns`() {
        val rng = Random(92)
        repeat(100_000) { check(Double.fromBits(rng.nextLong())) }
    }

    @Test
    fun `the edges of the format`() {
        val edges =
            listOf(
                Double.MIN_VALUE,
                Double.MAX_VALUE,
                java.lang.Double.MIN_NORMAL,
                1.0,
                0.1,
                1e23,
                5e-324,
                2.0.pow(53) + 2,
            ) +
                (-1074..1023).map { 2.0.pow(it) } + (-323..308).map { "1e$it".toDouble() } +
                (0 until 1000).map { Double.fromBits(it.toLong()) } +
                (0 until 1000).map { Double.fromBits(0x7FEF_FFFF_FFFF_FFFFL - it) } +
                (0 until 1000).map { Double.fromBits(0x0010_0000_0000_0000L + it - 500) }
        for (v in edges) {
            check(v)
            check(-v)
        }
        assertEquals("5E-324", ShortestDouble.exponential(Double.MIN_VALUE))
        assertEquals("1.7976931348623157E308", ShortestDouble.exponential(Double.MAX_VALUE))
        assertEquals("-0E0", ShortestDouble.exponential(-0.0))
    }

    private fun Double.pow(n: Int): Double = Math.pow(this, n.toDouble())
}
