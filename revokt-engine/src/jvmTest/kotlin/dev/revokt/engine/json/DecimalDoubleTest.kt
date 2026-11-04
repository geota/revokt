// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import java.math.BigDecimal
import java.math.BigInteger
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The parser's decimal reading against the JDK's `Double.parseDouble` (correctly rounded, half to even) and against
 * exact [BigDecimal] midpoints: random decimals of 1 to 30 digits across the whole exponent range, and the exact
 * midpoint between every sampled double and its successor, as is, a unit below and above, and pushed above by a digit
 * past the 768 that [DecimalDouble] keeps.
 */
class DecimalDoubleTest {
    private fun ours(text: String): Double = (Json.parse(text.encodeToByteArray()) as JsonDouble).value

    private fun same(
        expected: Double,
        text: String,
    ) = assertEquals(expected.toRawBits(), ours(text).toRawBits(), text)

    /** Always with an exponent, so the parser reads a double. */
    private fun exponential(d: BigDecimal): String = "${d.unscaledValue()}e${-d.scale()}"

    @Test
    fun `random decimals read as the JDK reads them`() {
        val rng = Random(92)
        repeat(300_000) {
            val digits =
                (
                    1..1 +
                        rng.nextInt(
                            30,
                        )
                ).joinToString("") { rng.nextInt(10).toString() }.trimStart('0').ifEmpty { "0" }
            val point = rng.nextInt(digits.length + 1)
            val mantissa =
                if (point in
                    1 until digits.length
                ) {
                    digits.substring(0, point) + "." + digits.substring(point)
                } else {
                    digits
                }
            val text = "${if (rng.nextBoolean()) "-" else ""}${mantissa}e${rng.nextInt(700) - 350}"
            val expected = text.toDouble()
            if (expected.isInfinite()) return@repeat
            same(expected, text)
        }
    }

    @Test
    fun `midpoints between neighbouring doubles round half to even, and any excess rounds up`() {
        val rng = Random(93)
        val samples =
            (0 until 100_000).map { Double.fromBits(rng.nextLong() and Long.MAX_VALUE) }.filter {
                it.isFinite() &&
                    it < Double.MAX_VALUE
            } +
                (0 until 64).map { Double.fromBits(it.toLong()) } +
                listOf(java.lang.Double.MIN_NORMAL, Math.nextDown(java.lang.Double.MIN_NORMAL))
        for (v in samples) {
            val low = BigDecimal(v)
            val high = BigDecimal(Math.nextUp(v))
            val mid = (low + high).divide(BigDecimal(2))
            val even = if (v.toRawBits() and 1L == 0L) v else Math.nextUp(v)
            same(even, exponential(mid))
            same(v, exponential(mid - mid.ulp()))
            same(Math.nextUp(v), exponential(mid + mid.ulp()))
            // Past 800 significant digits: zeros, then a 1 that only the sticky bit can see.
            val plain = mid.toPlainString()
            val significant = plain.replace(".", "").trimStart('0').length
            val padded = (if ('.' in plain) plain else "$plain.") + "0".repeat(maxOf(0, 820 - significant)) + "1"
            same(Math.nextUp(v), padded)
        }
    }

    @Test
    fun `the tie above the largest double overflows, and anything below it is the largest double`() {
        // 2^1024 - 2^970 lies halfway between Double.MAX_VALUE (odd mantissa) and 2^1024: ties to even round it up.
        val tie = BigInteger.ONE.shiftLeft(1024) - BigInteger.ONE.shiftLeft(970)
        val e = assertFailsWith<JsonParseException> { Json.parse(tie.toString().encodeToByteArray()) }
        assertEquals(JsonError.NUMBER_OUT_OF_RANGE, e.error)
        same(Double.MAX_VALUE, (tie - BigInteger.ONE).toString() + "." + "9".repeat(1000))
        same(Double.MAX_VALUE, (tie - BigInteger.ONE).toString())
    }
}
