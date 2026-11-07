// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.VerifyResult
import dev.revokt.VerifyResult.INVALID
import dev.revokt.VerifyResult.VERIFIED
import dev.revokt.engine.parse.TestDer
import dev.revokt.verify.JcaFixtures.ECDSA_SHA256
import dev.revokt.verify.JcaFixtures.MESSAGE
import dev.revokt.verify.JcaFixtures.algId
import dev.revokt.verify.JcaFixtures.sign
import java.math.BigInteger
import java.math.BigInteger.ONE
import java.math.BigInteger.ZERO
import java.security.KeyFactory
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.ECPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Issue #172 (spec §3, revision 54, pending): an ECDSA signature is `INVALID` before the provider is called unless it
 * is a DER `ECDSA-Sig-Value` with `1 ≤ r ≤ n − 1` and `1 ≤ s ≤ n − 1`, `n` the order of the key's curve (SEC 1 §4.1.4
 * step 1). JDK 17.0.0 to 17.0.2 skipped that step and accepted `r = s = 0` (CVE-2022-21449). A recording provider over
 * SunEC shows which signatures reach it; every out-of-range signature here is one a correct verifier rejects.
 */
class JcaEcdsaRangeTest {
    private var calls = 0
    private val recording =
        TestProvider("ecdsa-recording")
            .signature("SHA256withECDSA") {
                calls++
                DelegatingSignature(Signature.getInstance("SHA256withECDSA", "SunEC"))
            }.keyFactory("EC") {
                calls++
                DelegatingKeyFactory(KeyFactory.getInstance("EC", "SunEC"))
            }
    private val verifier = JcaSignatureVerifier(recording).also { calls = 0 }
    private val curves = listOf("secp256r1", "secp384r1", "secp521r1")

    private fun order(pair: KeyPair): BigInteger = (pair.public as ECPublicKey).params.order

    private fun integer(value: BigInteger): ByteArray = TestDer.tlv(0x02, value.toByteArray())

    private fun signature(
        r: BigInteger,
        s: BigInteger,
    ): ByteArray = TestDer.seq(integer(r), integer(s))

    /** Verifies [signature] under [pair]'s key and returns the result with whether the provider was called. */
    private fun verify(
        pair: KeyPair,
        signature: ByteArray,
    ): Pair<VerifyResult, Boolean> {
        calls = 0
        val result = verifier.verify(algId(ECDSA_SHA256), pair.public.encoded, MESSAGE, signature)
        return result to (calls > 0)
    }

    @Test
    fun `verifier the P-256 order is the curve's n`() {
        val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        assertEquals(n, order(JcaFixtures.ec("secp256r1")))
    }

    @Test
    fun `verifier an ECDSA r or s outside 1 to n-1 is INVALID without a provider call`() {
        for (curve in curves) {
            val pair = JcaFixtures.ec(curve)
            val n = order(pair)
            val cases =
                listOf(
                    "r = 0" to signature(ZERO, ONE),
                    "s = 0" to signature(ONE, ZERO),
                    "r = s = 0" to signature(ZERO, ZERO),
                    "r = n" to signature(n, ONE),
                    "s = n" to signature(ONE, n),
                    "r = n + 1" to signature(n + ONE, ONE),
                    "s = n + 1" to signature(ONE, n + ONE),
                    "r = -1" to signature(ONE.negate(), ONE),
                    "s = -1" to signature(ONE, ONE.negate()),
                    "r = -(n - 1)" to signature((n - ONE).negate(), ONE),
                    "s = -(n - 1)" to signature(ONE, (n - ONE).negate()),
                )
            for ((what, sig) in cases) assertEquals(INVALID to false, verify(pair, sig), "$curve $what")
        }
    }

    @Test
    fun `verifier a malformed ECDSA-Sig-Value is INVALID without a provider call`() {
        val pair = JcaFixtures.ec("secp256r1")
        val one = integer(ONE)
        val genuine = sign("SHA256withECDSA", pair.private)
        val cases =
            listOf(
                "empty" to ByteArray(0),
                "raw r || s" to ByteArray(64) { 1 },
                "one INTEGER" to TestDer.seq(one),
                "three INTEGERs" to TestDer.seq(one, one, one),
                "a byte after the SEQUENCE" to TestDer.seq(one, one) + TestDer.bytes(0x00),
                "a genuine signature with a byte after it" to genuine + TestDer.bytes(0x00),
                "a NULL inside the SEQUENCE" to TestDer.seq(one, one, TestDer.bytes(0x05, 0x00)),
                "a SET" to TestDer.tlv(0x31, one, one),
                "r as an OCTET STRING" to TestDer.seq(TestDer.tlv(0x04, TestDer.bytes(1)), one),
                "s as an ENUMERATED" to TestDer.seq(one, TestDer.tlv(0x0a, TestDer.bytes(1))),
                "an empty INTEGER" to TestDer.seq(TestDer.tlv(0x02), one),
                "r with a redundant 0x00" to TestDer.seq(TestDer.tlv(0x02, TestDer.bytes(0x00, 0x01)), one),
                "s with a redundant 0xff" to TestDer.seq(one, TestDer.tlv(0x02, TestDer.bytes(0xff, 0xff))),
                "a non-minimal SEQUENCE length" to
                    TestDer.tlvWithLength(0x30, TestDer.bytes(0x81, 0x06), TestDer.concat(one, one)),
                "a non-minimal INTEGER length" to
                    TestDer.seq(TestDer.tlvWithLength(0x02, TestDer.bytes(0x81, 0x01), TestDer.bytes(1)), one),
                "an indefinite length" to TestDer.bytes(0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00),
                "a truncated SEQUENCE" to TestDer.seq(one, one).copyOf(7),
            )
        for ((what, sig) in cases) assertEquals(INVALID to false, verify(pair, sig), what)
        // A non-minimal header on a genuine signature (which is short enough for the short form): not DER, so INVALID.
        val content = genuine.copyOfRange(2, genuine.size)
        assertEquals(genuine[1].toInt(), content.size)
        val longForm = TestDer.tlvWithLength(0x30, TestDer.bytes(0x81, content.size), content)
        assertEquals(INVALID to false, verify(pair, longForm), "a genuine signature with a long-form length")
    }

    @Test
    fun `verifier an in-range ECDSA r and s reach the provider`() {
        for (curve in curves) {
            val pair = JcaFixtures.ec(curve)
            val n = order(pair)
            // Each bound: in range, so the provider decides, and these are no signature of MESSAGE.
            for ((r, s) in listOf(ONE to n - ONE, n - ONE to ONE, ONE to ONE, n - ONE to n - ONE)) {
                assertEquals(INVALID to true, verify(pair, signature(r, s)), "$curve r = $r, s = $s")
            }
        }
    }

    @Test
    fun `verifier genuine ECDSA signatures still verify, high s included`() {
        for (curve in curves) {
            val pair = JcaFixtures.ec(curve)
            val half = order(pair).shiftRight(1)
            val genuine = sign("SHA256withECDSA", pair.private)
            assertEquals(VERIFIED to true, verify(pair, genuine), curve)
            // The JDK's own signatures, made until one has s > n / 2 (each one has, with probability 1/2).
            val high =
                generateSequence { sign("SHA256withECDSA", pair.private) }
                    .take(HIGH_S_TRIES)
                    .first { s(it) > half }
            assertTrue(s(high) > half)
            assertEquals(VERIFIED to true, verify(pair, high), "$curve high s")
        }
    }

    /** The `s` of a DER `ECDSA-Sig-Value` the JDK made. */
    private fun s(signature: ByteArray): BigInteger {
        val r = JcaAlgorithms.ecdsaSignature(signature)
        return checkNotNull(r) { "the JDK's signature decodes" }.second
    }

    private companion object {
        const val HIGH_S_TRIES = 128
    }
}
