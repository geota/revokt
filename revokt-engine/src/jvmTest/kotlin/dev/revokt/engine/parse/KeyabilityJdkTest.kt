// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.KeyabilityClause
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** K7's curves against the JDK's, and the profile over the committed real certificates (spec §9.2, revision 34). */
class KeyabilityJdkTest {
    private val curves =
        listOf(
            "secp256r1" to PrimeCurve.P256,
            "secp384r1" to PrimeCurve.P384,
            "secp521r1" to PrimeCurve.P521,
        )

    private fun fixed(
        v: BigInteger,
        n: Int,
    ): ByteArray {
        val raw = v.toByteArray().dropWhile { it.toInt() == 0 }.toByteArray()
        return ByteArray(n - raw.size) + raw
    }

    private fun spec(name: String): ECParameterSpec =
        AlgorithmParameters
            .getInstance("EC")
            .apply { init(ECGenParameterSpec(name)) }
            .getParameterSpec(ECParameterSpec::class.java)

    private fun onCurve(
        curve: PrimeCurve,
        point: ECPoint,
    ) = curve.onCurve(fixed(point.affineX, curve.byteLength), fixed(point.affineY, curve.byteLength))

    @Test
    fun `the on-curve check accepts the JDK's generators and keys and rejects their bit flips`() {
        val random = Random(20261024)
        for ((name, curve) in curves) {
            val g = spec(name).generator
            assertTrue(onCurve(curve, g), "$name generator")
            val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(name)) }
            repeat(20) { n ->
                val point = (generator.generateKeyPair().public as ECPublicKey).w
                assertTrue(onCurve(curve, point), "$name key $n")
                val x = fixed(point.affineX, curve.byteLength)
                val y = fixed(point.affineY, curve.byteLength)
                val flipped = if (random.nextBoolean()) x else y
                val bit = random.nextInt(curve.byteLength * 8)
                flipped[bit / 8] = (flipped[bit / 8].toInt() xor (1 shl (bit % 8))).toByte()
                assertFalse(curve.onCurve(x, y), "$name key $n with bit $bit flipped")
            }
            // A coordinate of p or more is outside even when it would satisfy the equation modulo p.
            val p = (spec(name).curve.field as java.security.spec.ECFieldFp).p
            val xPlusP = g.affineX + p
            if (xPlusP.bitLength() <= curve.byteLength * 8) {
                assertFalse(
                    curve.onCurve(fixed(xPlusP, curve.byteLength), fixed(g.affineY, curve.byteLength)),
                    "$name x + p",
                )
            }
            assertFalse(curve.onCurve(fixed(p, curve.byteLength), fixed(g.affineY, curve.byteLength)), "$name x = p")
        }
    }

    /**
     * The curve arithmetic against `BigInteger`: on-curve points from random x (where the right-hand side is a square),
     * their negation, ±1 and bit-flip neighbours, x + p and y + p where they fit, and random byte pairs.
     */
    @Test
    fun `onCurve agrees with BigInteger arithmetic on and off the curve`() {
        val random = java.util.Random(20261024)
        for ((name, curve) in curves) {
            val spec = spec(name)
            val p = (spec.curve.field as java.security.spec.ECFieldFp).p
            val b = spec.curve.b
            val n = curve.byteLength

            fun expected(
                x: BigInteger,
                y: BigInteger,
            ) = x < p && y < p &&
                y.multiply(y).mod(p) ==
                x
                    .pow(3)
                    .subtract(x.multiply(BigInteger.valueOf(3)))
                    .add(b)
                    .mod(p)

            fun check(
                x: BigInteger,
                y: BigInteger,
            ) {
                if (x.signum() < 0 || y.signum() < 0) return
                if (x.bitLength() > n * 8 || y.bitLength() > n * 8) return
                assertEquals(expected(x, y), curve.onCurve(fixed(x, n), fixed(y, n)), "$name x=$x y=$y")
            }
            var on = 0
            repeat(300) { k ->
                val x =
                    if (k <
                        20
                    ) {
                        BigInteger.valueOf(k.toLong())
                    } else if (k <
                        40
                    ) {
                        p - BigInteger.valueOf(k - 19L)
                    } else {
                        BigInteger(p.bitLength(), random).mod(p)
                    }
                val rhs =
                    x
                        .pow(3)
                        .subtract(x.multiply(BigInteger.valueOf(3)))
                        .add(b)
                        .mod(p)
                val y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
                if (y.multiply(y).mod(p) == rhs) on++
                for (candidate in listOf(y, p - y, y + BigInteger.ONE, y.flipBit(random.nextInt(p.bitLength())))) {
                    check(x, candidate)
                    check(x + p, candidate)
                    check(x, candidate + p)
                }
            }
            assertTrue(on > 100, "$name: only $on on-curve points")
            repeat(2000) { check(BigInteger(n * 8, random), BigInteger(n * 8, random)) }
            // x = p with y² = b: on the curve modulo p, outside because x is not below p.
            val rootB = b.modPow(p.add(BigInteger.ONE).shiftRight(2), p)
            assertEquals(b, rootB.multiply(rootB).mod(p), "$name: b is a square")
            assertFalse(curve.onCurve(fixed(p, n), fixed(rootB, n)), "$name x = p, y = sqrt(b)")
        }
        // x = p − 1 on P-384: below p in every limb but the lowest.
        val p384 = (spec("secp384r1").curve.field as java.security.spec.ECFieldFp).p
        val y =
            BigInteger(
                "8cdeadbbd04911a3c1931e26df3fa6439dca9c7eb286fbd46fc319f0e2bb780232baf57825fc0c1912ada2fefe84024c",
                16,
            )
        assertTrue(PrimeCurve.P384.onCurve(fixed(p384 - BigInteger.ONE, 48), fixed(y, 48)), "P-384 x = p - 1")
    }

    @Test
    fun `the committed real certificates are inside the profile through K7`() {
        val names =
            listOf("github.com", "letsencrypt.org", "www.google.com", "www.mozilla.org").flatMap { site ->
                (1..3).map { "$site-$it" }
            } +
                listOf(
                    "letsencrypt.org-4",
                    "mozilla-content-signing-c0",
                    "mozilla-content-signing-c1",
                    "mozilla-content-signing-c2",
                )
        for (name in names) {
            val der =
                checkNotNull(
                    javaClass.getResourceAsStream("certs/$name.der"),
                ) { "missing $name" }.use { it.readBytes() }
            val p = (CertificateParser.parse(der) as CertificateParse.Parsed).certificate
            // Every one carries extensions K8 lists, so until #28 the first failing clause is K8 and nothing earlier.
            assertEquals(KeyabilityClause.EXTENSION, Keyability.firstFailing(p), name)
        }
    }
}
