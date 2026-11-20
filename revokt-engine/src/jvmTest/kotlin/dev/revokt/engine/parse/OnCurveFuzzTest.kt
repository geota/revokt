// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.util.Random

/**
 * K7's on-curve check (spec §9.2, the keyability profile) as a fuzz target (#213), differential against `BigInteger`
 * arithmetic over the JDK's curve parameters, as `KeyabilityJdkTest` checks it with a fixed seed. The first input byte
 * picks P-256, P-384 or P-521; the next 2 × the curve's byte length are x and y, big-endian (zero-padded when the
 * input is short). [PrimeCurve.onCurve] must answer exactly `x < p && y < p && y² = x³ − 3x + b (mod p)`. An input of
 * the form `seed:<decimal>` instead checks [SEED_CASES] points per curve from `java.util.Random(<decimal>)`: on-curve
 * points from random x, their neighbours, and random pairs; the committed inputs hold the test's seed,
 * `seed:20261024`. The longest input is 1 + 2 × 66 bytes, so the fuzz job runs with `-max_len=133`. With
 * `JAZZER_FUZZ` unset JUnit replays `OnCurveFuzzTestInputs/`.
 */
class OnCurveFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun check(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private const val SEED_CASES = 16

        private val SEED = Regex("seed:(-?[0-9]{1,19})")

        private class Curve(
            val prime: PrimeCurve,
            val p: BigInteger,
            val b: BigInteger,
        )

        private val CURVES =
            listOf(
                "secp256r1" to PrimeCurve.P256,
                "secp384r1" to PrimeCurve.P384,
                "secp521r1" to PrimeCurve.P521,
            ).map { (name, prime) -> curve(name, prime) }

        private fun curve(
            name: String,
            prime: PrimeCurve,
        ): Curve {
            val spec =
                AlgorithmParameters
                    .getInstance("EC")
                    .apply { init(ECGenParameterSpec(name)) }
                    .getParameterSpec(ECParameterSpec::class.java)
            return Curve(prime, (spec.curve.field as ECFieldFp).p, spec.curve.b)
        }

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
                seeded(Random(seed))
                return
            }
            if (data.isEmpty()) return
            val curve = CURVES[(data[0].toInt() and 0xff) % CURVES.size]
            val n = curve.prime.byteLength
            val coordinates = data.copyOfRange(1, minOf(data.size, 1 + 2 * n)).copyOf(2 * n)
            agrees(curve, coordinates.copyOfRange(0, n), coordinates.copyOfRange(n, 2 * n))
        }

        private fun seeded(random: Random) {
            for (curve in CURVES) {
                val n = curve.prime.byteLength
                repeat(SEED_CASES) {
                    val x = BigInteger(curve.p.bitLength(), random).mod(curve.p)
                    val rhs =
                        x
                            .pow(3)
                            .subtract(x.multiply(BigInteger.valueOf(3)))
                            .add(curve.b)
                            .mod(curve.p)
                    val y = rhs.modPow(curve.p.add(BigInteger.ONE).shiftRight(2), curve.p)
                    for (candidate in listOf(y, curve.p - y, y + BigInteger.ONE)) {
                        fixed(x, n)?.let { xs -> fixed(candidate, n)?.let { ys -> agrees(curve, xs, ys) } }
                    }
                    agrees(curve, ByteArray(n).also(random::nextBytes), ByteArray(n).also(random::nextBytes))
                }
            }
        }

        private fun agrees(
            curve: Curve,
            x: ByteArray,
            y: ByteArray,
        ) {
            val bx = BigInteger(1, x)
            val by = BigInteger(1, y)
            val expected =
                bx < curve.p && by < curve.p &&
                    by.multiply(by).mod(curve.p) ==
                    bx
                        .pow(3)
                        .subtract(bx.multiply(BigInteger.valueOf(3)))
                        .add(curve.b)
                        .mod(curve.p)
            check(curve.prime.onCurve(x, y) == expected) { "onCurve disagrees with BigInteger" }
        }

        /** [v] big-endian in exactly [n] bytes, or null when it does not fit. */
        private fun fixed(
            v: BigInteger,
            n: Int,
        ): ByteArray? {
            val raw = v.toByteArray().dropWhile { it.toInt() == 0 }.toByteArray()
            return if (raw.size > n) null else ByteArray(n - raw.size) + raw
        }
    }
}
