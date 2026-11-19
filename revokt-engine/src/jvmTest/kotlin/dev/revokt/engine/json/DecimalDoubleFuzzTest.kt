// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import com.code_intelligence.jazzer.junit.FuzzTest
import java.util.Random

/**
 * The JSON parser's decimal reading as a fuzz target (#213), differential against the JDK's `Double.parseDouble`
 * (correctly rounded, half to even), as `DecimalDoubleTest` checks it with a fixed seed. Whenever [Json.parse] reads
 * the input as a [JsonDouble], the JDK must read the same text, with JSON's surrounding whitespace trimmed, to the
 * same bits. An input of the form `seed:<decimal>` instead checks [SEED_CASES] decimals of the test's generator under
 * `java.util.Random(<decimal>)`; the committed inputs hold its seed, `seed:92`. A JSON number is bounded only by
 * `RevoktLimits.MAX_JSON_BYTES`, so the fuzz job runs with `-max_len=4194305`. With `JAZZER_FUZZ` unset JUnit replays
 * `DecimalDoubleFuzzTestInputs/`.
 */
class DecimalDoubleFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private const val SEED_CASES = 64

        private val SEED = Regex("seed:(-?[0-9]{1,19})")

        /** JSON's whitespace: space, tab, line feed and carriage return. */
        private val JSON_SPACE = charArrayOf(' ', '\t', '\n', '\r')

        /** The static entry point a standalone Jazzer driver calls (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val seed =
                SEED
                    .matchEntire(String(data, Charsets.ISO_8859_1))
                    ?.groupValues
                    ?.get(1)
                    ?.toLongOrNull()
            if (seed != null) {
                val rng = Random(seed)
                repeat(SEED_CASES) { generated(rng) }
                return
            }
            val value =
                try {
                    Json.parse(data) as? JsonDouble ?: return
                } catch (_: JsonParseException) {
                    return
                }
            val text = String(data, Charsets.UTF_8).trim(*JSON_SPACE)
            check(value.value.toRawBits() == text.toDouble().toRawBits()) { "the JDK reads the number otherwise" }
        }

        /** One decimal of `DecimalDoubleTest`'s generator: 1 to 30 digits, a point anywhere, an exponent of ±350. */
        private fun generated(rng: Random) {
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
            if (expected.isInfinite()) return
            val ours = (Json.parse(text.encodeToByteArray()) as JsonDouble).value
            check(ours.toRawBits() == expected.toRawBits()) { "the JDK reads a generated decimal otherwise" }
        }
    }
}
