// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.VerifyResult
import dev.revokt.VerifyResult.INVALID
import dev.revokt.VerifyResult.UNSUPPORTED
import dev.revokt.VerifyResult.VERIFIED
import dev.revokt.engine.parse.TestDer
import dev.revokt.verify.JcaFixtures.ECDSA_SHA256
import dev.revokt.verify.JcaFixtures.EC_KEY
import dev.revokt.verify.JcaFixtures.MESSAGE
import dev.revokt.verify.JcaFixtures.algId
import dev.revokt.verify.JcaFixtures.sign
import dev.revokt.verify.JcaFixtures.spki
import java.math.BigInteger
import java.math.BigInteger.ONE
import java.math.BigInteger.ZERO
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §3 "ECDSA range check" (revision 54) and §9's verifier row [0.2, #172]: the curve probe decides first, so a
 * curve the provider lacks is `UNSUPPORTED`. Otherwise an ECDSA signature is `INVALID` before the provider's
 * `Signature` is created unless it is a DER `ECDSA-Sig-Value` with `1 ≤ r ≤ n − 1` and `1 ≤ s ≤ n − 1`, `n` the order
 * of the decoded key's curve (SEC 1 §4.1.4 step 1). JDK 17.0.0 to 17.0.2 and 18 GA skipped that step and accepted
 * `r = s = 0` (CVE-2022-21449).
 *
 * The provider is a stub over SunEC that counts its `Signature` instances. After the startup probe it answers `true`
 * to every signature when [accept] is set, so an `INVALID` there is revokt's own check, not the JDK's. Every
 * out-of-range signature here is one a correct verifier rejects.
 */
class JcaEcdsaRangeTest {
    private var signatures = 0
    private var accept = false
    private var opaqueKey = false
    private val stub =
        TestProvider("ecdsa-stub")
            .signature("SHA256withECDSA") {
                signatures++
                DelegatingSignature(Signature.getInstance("SHA256withECDSA", "SunEC")) { it || accept }
            }.keyFactory("EC") {
                val inner = KeyFactory.getInstance("EC", "SunEC")
                DelegatingKeyFactory(inner) { if (opaqueKey) OPAQUE else inner.generatePublic(it) }
            }
    private val verifier = JcaSignatureVerifier(stub)
    private val curves = listOf("secp256r1", "secp384r1", "secp521r1")

    private fun order(pair: KeyPair): BigInteger = (pair.public as ECPublicKey).params.order

    private fun integer(value: BigInteger): ByteArray = TestDer.tlv(0x02, value.toByteArray())

    private fun signature(
        r: BigInteger,
        s: BigInteger,
    ): ByteArray = TestDer.seq(integer(r), integer(s))

    /** The result for [signature] under [pair]'s key, the stub accepting all if [accepting]; and if a Signature ran. */
    private fun verify(
        pair: KeyPair,
        signature: ByteArray,
        accepting: Boolean = true,
    ): Pair<VerifyResult, Boolean> {
        accept = accepting
        signatures = 0
        val result = verifier.verify(algId(ECDSA_SHA256), pair.public.encoded, MESSAGE, signature)
        return result to (signatures > 0)
    }

    @Test
    fun `verifier the P-256 order is the curve's n`() {
        val n = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        assertEquals(n, order(JcaFixtures.ec("secp256r1")))
    }

    @Test
    fun `verifier an ECDSA r or s outside 1 to n-1 is INVALID under a provider that accepts everything`() {
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
    fun `verifier a malformed ECDSA-Sig-Value is INVALID under a provider that accepts everything`() {
        val pair = JcaFixtures.ec("secp256r1")
        val one = integer(ONE)
        val genuine = sign("SHA256withECDSA", pair.private)
        val cases =
            listOf(
                "empty" to ByteArray(0),
                "raw r || s" to ByteArray(64) { 1 },
                "one INTEGER (s missing)" to TestDer.seq(one),
                "three INTEGERs" to TestDer.seq(one, one, one),
                "a byte after the SEQUENCE" to TestDer.seq(one, one) + TestDer.bytes(0x00),
                "a genuine signature with a byte after it" to genuine + TestDer.bytes(0x00),
                "a NULL inside the SEQUENCE" to TestDer.seq(one, one, TestDer.bytes(0x05, 0x00)),
                "a SET" to TestDer.tlv(0x31, one, one),
                "r as an OCTET STRING" to TestDer.seq(TestDer.tlv(0x04, TestDer.bytes(1)), one),
                "s as an ENUMERATED" to TestDer.seq(one, TestDer.tlv(0x0a, TestDer.bytes(1))),
                "an empty INTEGER" to TestDer.seq(TestDer.tlv(0x02), one),
                "r with a redundant leading 00" to TestDer.seq(TestDer.tlv(0x02, TestDer.bytes(0x00, 0x01)), one),
                "s with a redundant leading 00" to TestDer.seq(one, TestDer.tlv(0x02, TestDer.bytes(0x00, 0x7f))),
                "s with a redundant leading ff" to TestDer.seq(one, TestDer.tlv(0x02, TestDer.bytes(0xff, 0xff))),
                "r = 0x80 without its 00 (negative)" to TestDer.seq(TestDer.tlv(0x02, TestDer.bytes(0x80)), one),
                "a non-minimal SEQUENCE length" to
                    TestDer.tlvWithLength(0x30, TestDer.bytes(0x81, 0x06), TestDer.concat(one, one)),
                "a non-minimal INTEGER length" to
                    TestDer.seq(TestDer.tlvWithLength(0x02, TestDer.bytes(0x81, 0x01), TestDer.bytes(1)), one),
                "an indefinite length" to TestDer.bytes(0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00),
                "a truncated SEQUENCE" to TestDer.seq(one, one).copyOf(7),
            )
        for ((what, sig) in cases) assertEquals(INVALID to false, verify(pair, sig), what)
        // The decoder itself refuses a negative INTEGER, before the range check would.
        assertNull(JcaAlgorithms.ecdsaSignature(signature(ONE.negate(), ONE)))
        assertNull(JcaAlgorithms.ecdsaSignature(signature(ONE, ONE.negate())))
        assertEquals(ONE to ONE, JcaAlgorithms.ecdsaSignature(signature(ONE, ONE)))
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
            // Each bound: in range, so the stub decides; no signature of MESSAGE, so SunEC alone says INVALID.
            for ((r, s) in listOf(ONE to n - ONE, n - ONE to ONE, ONE to ONE, n - ONE to n - ONE)) {
                assertEquals(VERIFIED to true, verify(pair, signature(r, s)), "$curve r = $r, s = $s under the stub")
                assertEquals(INVALID to true, verify(pair, signature(r, s), accepting = false), "$curve r = $r, s = $s")
            }
        }
    }

    @Test
    fun `verifier an ECDSA signature on a curve the probe marks unsupported is UNSUPPORTED whatever its r and s`() {
        // SunEC has no brainpool and no P-224 (spec Appendix A), so the stub over it supports neither curve.
        val n = order(JcaFixtures.ec("secp256r1"))
        for (curve in listOf(JcaFixtures.BRAINPOOL_P256, JcaFixtures.P224)) {
            assertTrue(curve in verifier.unsupportedOids(), curve)
            val key = spki(algId(EC_KEY, TestDer.oid(curve)), TestDer.bytes(0x04, 0x01, 0x02))
            val cases =
                listOf(
                    "r = s = 0" to signature(ZERO, ZERO),
                    "r = n" to signature(n, ONE),
                    "in range" to signature(ONE, ONE),
                    "malformed" to TestDer.bytes(0x30, 0x00),
                )
            for ((what, sig) in cases) {
                accept = true
                signatures = 0
                val result = verifier.verify(algId(ECDSA_SHA256), key, MESSAGE, sig)
                assertEquals(UNSUPPORTED to false, result to (signatures > 0), "$curve $what")
            }
        }
    }

    @Test
    fun `verifier a cached key still gets the range check`() {
        val pair = JcaFixtures.ec("secp256r1")
        val n = order(pair)
        assertEquals(VERIFIED to true, verify(pair, sign("SHA256withECDSA", pair.private), accepting = false))
        assertEquals(1, verifier.cachedKeyCount, "the key is cached")
        for ((what, sig) in listOf("r = s = 0" to signature(ZERO, ZERO), "s = n" to signature(ONE, n))) {
            assertEquals(INVALID to false, verify(pair, sig), "cached key, $what")
        }
    }

    @Test
    fun `verifier a key without a curve order is INVALID before the Signature`() {
        val pair = JcaFixtures.ec("secp256r1")
        opaqueKey = true
        assertEquals(INVALID to false, verify(pair, sign("SHA256withECDSA", pair.private)))
    }

    @Test
    fun `verifier genuine ECDSA signatures still verify, high s included`() {
        for (curve in curves) {
            val pair = JcaFixtures.ec(curve)
            val n = order(pair)
            val genuine = sign("SHA256withECDSA", pair.private)
            assertEquals(VERIFIED to true, verify(pair, genuine, accepting = false), curve)
            // §9's row: the same signature rewritten to (r, n − s), as valid under SEC 1. n is odd, so exactly one of
            // s and n − s is above n / 2: one of the two signatures verified here is a high-s one.
            val (r, s) = checkNotNull(JcaAlgorithms.ecdsaSignature(genuine)) { "the JDK's signature decodes" }
            val rewritten = signature(r, n - s)
            assertEquals(VERIFIED to true, verify(pair, rewritten, accepting = false), "$curve (r, n - s)")
        }
    }

    private companion object {
        /** A key that is no `ECPublicKey`, so it has no curve order. */
        val OPAQUE =
            object : PublicKey {
                override fun getAlgorithm() = "EC"

                override fun getFormat() = "X.509"

                override fun getEncoded() = ByteArray(0)
            }
    }
}
