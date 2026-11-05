// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.VerifyResult
import dev.revokt.VerifyResult.INVALID
import dev.revokt.VerifyResult.UNSUPPORTED
import dev.revokt.VerifyResult.VERIFIED
import dev.revokt.engine.parse.TestDer
import dev.revokt.verify.JcaFixtures.BRAINPOOL_P256
import dev.revokt.verify.JcaFixtures.COMPOSITE_MLDSA44_ED25519
import dev.revokt.verify.JcaFixtures.ECDSA_SHA1
import dev.revokt.verify.JcaFixtures.ECDSA_SHA256
import dev.revokt.verify.JcaFixtures.EC_KEY
import dev.revokt.verify.JcaFixtures.ED25519
import dev.revokt.verify.JcaFixtures.ED448
import dev.revokt.verify.JcaFixtures.MESSAGE
import dev.revokt.verify.JcaFixtures.ML_DSA_44
import dev.revokt.verify.JcaFixtures.ML_DSA_65
import dev.revokt.verify.JcaFixtures.NULL
import dev.revokt.verify.JcaFixtures.P224
import dev.revokt.verify.JcaFixtures.P256
import dev.revokt.verify.JcaFixtures.PSS
import dev.revokt.verify.JcaFixtures.SECP256K1
import dev.revokt.verify.JcaFixtures.SHA1
import dev.revokt.verify.JcaFixtures.SHA1_RSA
import dev.revokt.verify.JcaFixtures.SHA256
import dev.revokt.verify.JcaFixtures.SHA256_RSA
import dev.revokt.verify.JcaFixtures.SHA384
import dev.revokt.verify.JcaFixtures.SHA512
import dev.revokt.verify.JcaFixtures.SLH_DSA_SHA2_128S
import dev.revokt.verify.JcaFixtures.algId
import dev.revokt.verify.JcaFixtures.flip
import dev.revokt.verify.JcaFixtures.generate
import dev.revokt.verify.JcaFixtures.jdkVerifies
import dev.revokt.verify.JcaFixtures.pssParams
import dev.revokt.verify.JcaFixtures.pssSpec
import dev.revokt.verify.JcaFixtures.rsa
import dev.revokt.verify.JcaFixtures.sign
import dev.revokt.verify.JcaFixtures.spki
import java.security.KeyPair
import java.security.Signature
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec §3 "Verifier contract" and §9 "Verifier" against the test JDK's own providers: every listed algorithm verifies a
 * signature the JDK made and agrees with the JDK's own answer on tampered inputs; the classification rules (probe,
 * tables, key and parameter checks) and the key cache. Run on each matrix JDK with `-Prevokt.testJdk`.
 */
class JcaSignatureVerifierTest {
    private val verifier = JcaSignatureVerifier()

    /** One algorithm: the TBS `AlgorithmIdentifier`, the JCA name and parameters the JDK signs with, and a key pair. */
    private class Case(
        val label: String,
        val sigAlg: ByteArray,
        val jcaName: String,
        val pair: KeyPair,
        val params: AlgorithmParameterSpec? = null,
    ) {
        val signature: ByteArray = sign(jcaName, pair.private, params = params)
        val spki: ByteArray = pair.public.encoded
    }

    private fun cases(): List<Case> {
        val rsa = rsa()
        val pkcs1 =
            listOf(14 to "SHA224withRSA", 11 to "SHA256withRSA", 12 to "SHA384withRSA", 13 to "SHA512withRSA") +
                listOf(15 to "SHA512/224withRSA", 16 to "SHA512/256withRSA")
        val ecdsa =
            listOf(
                1 to "SHA224withECDSA",
                2 to "SHA256withECDSA",
                3 to "SHA384withECDSA",
                4 to "SHA512withECDSA",
            )
        val pssKey = JcaFixtures.pair("rsa-pss") { generate("RSASSA-PSS", size = 2048) }
        return pkcs1.map { (arc, name) -> Case(name, algId("${JcaFixtures.PKCS1}.$arc", NULL), name, rsa) } +
            listOf(SHA256 to "SHA-256", SHA384 to "SHA-384", SHA512 to "SHA-512").flatMap { (oid, name) ->
                val salt = name.substringAfter('-').toInt() / 8
                val sigAlg = algId(PSS, pssParams(oid, oid, salt))
                val spec = pssSpec(name, name, salt)
                listOf(
                    Case("PSS $name", sigAlg, "RSASSA-PSS", rsa, spec),
                    Case("PSS key $name", sigAlg, "RSASSA-PSS", pssKey, spec),
                )
            } +
            listOf("secp256r1", "secp384r1", "secp521r1").flatMap { curve ->
                ecdsa.map { (arc, name) ->
                    Case("$name $curve", algId("1.2.840.10045.4.3.$arc"), name, JcaFixtures.ec(curve))
                }
            } +
            listOf(ED25519 to "Ed25519", ED448 to "Ed448").map { (oid, name) ->
                Case(name, algId(oid), name, generate(name))
            } +
            mlDsa()
    }

    /** ML-DSA where the test JDK ships it (spec Appendix A: JDK 24, backported in 17.0.21 and 21.0.13). */
    private fun mlDsa(): List<Case> =
        if (!JdkFacts.shipsMlDsa()) {
            emptyList()
        } else {
            listOf(44 to 17, 65 to 18, 87 to 19).map { (level, arc) ->
                Case("ML-DSA-$level", algId("2.16.840.1.101.3.4.3.$arc"), "ML-DSA-$level", generate("ML-DSA-$level"))
            }
        }

    private fun verify(
        c: Case,
        sigAlg: ByteArray = c.sigAlg,
        spki: ByteArray = c.spki,
        message: ByteArray = MESSAGE,
        signature: ByteArray = c.signature,
    ): VerifyResult = verifier.verify(sigAlg, spki, message, signature)

    @Test
    fun `verifier every listed algorithm verifies the JDK's signature`() {
        val all = cases()
        assertEquals(if (JdkFacts.shipsMlDsa()) 29 else 26, all.size)
        for (c in all) {
            assertTrue(jdkVerifies(c.jcaName, c.pair.public, c.signature, params = c.params), c.label)
            assertEquals(VERIFIED, verify(c), c.label)
        }
    }

    @Test
    fun `verifier agrees with the JDK on a tampered message, signature or key`() {
        for (c in cases()) {
            val other = otherPair(c)
            val tampered =
                listOf(
                    "message" to Triple(flip(MESSAGE, 0), c.signature, c.pair),
                    "signature" to Triple(MESSAGE, flip(c.signature, c.signature.size / 2), c.pair),
                    "truncated" to Triple(MESSAGE, c.signature.copyOf(c.signature.size - 1), c.pair),
                    "empty" to Triple(MESSAGE, ByteArray(0), c.pair),
                    "wrong key" to Triple(MESSAGE, c.signature, other),
                )
            for ((what, t) in tampered) {
                val (message, signature, pair) = t
                assertFalse(jdkVerifies(c.jcaName, pair.public, signature, message, c.params), "${c.label} $what")
                assertEquals(
                    INVALID,
                    verify(c, spki = pair.public.encoded, message = message, signature = signature),
                    "${c.label} $what",
                )
            }
        }
    }

    private fun otherPair(c: Case): KeyPair =
        when (val algorithm = c.pair.public.algorithm) {
            "EC" -> generate("EC", c.pair.public.let { (it as java.security.interfaces.ECPublicKey).params })
            "RSA", "RSASSA-PSS" -> JcaFixtures.rsa("other-$algorithm")
            else -> generate(c.jcaName)
        }

    @Test
    fun `verifier probe on the JDK providers`() {
        val unsupported = verifier.unsupportedOids()
        // Spec Appendix A: SunEC has no brainpool since JDK 15; P-224 and secp256k1 are gone with the native library.
        assertTrue(BRAINPOOL_P256 in unsupported)
        assertTrue(P224 in unsupported)
        assertFalse(SECP256K1 in unsupported, "secp256k1 is outside the curve table, never probed")
        for (curve in listOf(P256, JcaFixtures.P384, JcaFixtures.P521)) assertFalse(curve in unsupported, curve)
        // Composite signatures are not one JCA operation: no JDK provider owns their OIDs.
        for (arc in 37..54) assertTrue("1.3.6.1.5.5.7.6.$arc" in unsupported, "composite $arc")
        // The matrix JDKs ship no SLH-DSA; the probe follows whatever the test JDK has.
        for (arc in 20..31) {
            val oid = "2.16.840.1.101.3.4.3.$arc"
            assertEquals(
                runCatching { Signature.getInstance(JcaAlgorithms.SIGNATURES.getValue(oid).jcaName) }.isFailure,
                oid in unsupported,
                oid,
            )
        }
        assertEquals(!JdkFacts.shipsMlDsa(), ML_DSA_44 in unsupported)
        val tables = JcaAlgorithms.SIGNATURES.keys + JcaAlgorithms.KEYS.keys + JcaAlgorithms.CURVES
        assertTrue(tables.containsAll(unsupported), "the probe reports table OIDs only")
        assertEquals(verifier.unsupportedOids(), JcaSignatureVerifier().unsupportedOids(), "the probe is deterministic")
    }

    @Test
    fun `verifier an unsupported signature, key or curve OID is UNSUPPORTED whatever the bytes`() {
        val garbage = TestDer.bytes(1, 2, 3)
        val ec = spki(algId(EC_KEY, TestDer.oid(P256)))
        // A brainpool key on SunEC: the curve OID decides, before any parse or exception.
        assertEquals(
            UNSUPPORTED,
            verifier.verify(algId(ECDSA_SHA256), spki(algId(EC_KEY, TestDer.oid(BRAINPOOL_P256))), MESSAGE, garbage),
        )
        assertEquals(UNSUPPORTED, verifier.verify(algId(COMPOSITE_MLDSA44_ED25519), ec, MESSAGE, garbage))
        assertEquals(
            UNSUPPORTED,
            verifier.verify(algId(ECDSA_SHA256), spki(algId(COMPOSITE_MLDSA44_ED25519)), MESSAGE, garbage),
        )
        assertEquals(
            UNSUPPORTED,
            verifier.verify(algId(SLH_DSA_SHA2_128S), spki(algId(SLH_DSA_SHA2_128S)), MESSAGE, garbage),
        )
    }

    @Test
    fun `verifier signature OIDs outside the table are INVALID even when the JDK would verify them`() {
        val rsa = rsa()
        val ec = JcaFixtures.ec("secp256r1")
        val sha1Rsa = sign("SHA1withRSA", rsa.private)
        assertTrue(jdkVerifies("SHA1withRSA", rsa.public, sha1Rsa))
        assertEquals(INVALID, verifier.verify(algId(SHA1_RSA, NULL), rsa.public.encoded, MESSAGE, sha1Rsa))
        val sha1Ec = sign("SHA1withECDSA", ec.private)
        assertEquals(INVALID, verifier.verify(algId(ECDSA_SHA1), ec.public.encoded, MESSAGE, sha1Ec))
        val sha3 = sign("SHA3-256withRSA", rsa.private)
        assertEquals(
            INVALID,
            verifier.verify(algId("2.16.840.1.101.3.4.3.14", NULL), rsa.public.encoded, MESSAGE, sha3),
        )
        assertEquals(INVALID, verifier.verify(algId("1.3.6.1.4.1.55555.1"), rsa.public.encoded, MESSAGE, sha3))
    }

    @Test
    fun `verifier a padded OID arc is INVALID, as the JDK rejects it`() {
        val rsa = rsa()
        val signature = sign("SHA256withRSA", rsa.private)
        val padded =
            TestDer.seq(
                TestDer.tlv(0x06, TestDer.bytes(0x2a, 0x86, 0x48, 0x80, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b)),
                NULL,
            )
        assertTrue(
            runCatching {
                java.security.AlgorithmParameters
                    .getInstance("RSASSA-PSS")
                    .init(TestDer.seq(TestDer.tlv(0xa0, padded)))
            }.isFailure,
            "the JDK's ObjectIdentifier rejects the padded arc",
        )
        assertEquals(INVALID, verifier.verify(padded, rsa.public.encoded, MESSAGE, signature))
        assertEquals(VERIFIED, verifier.verify(algId(SHA256_RSA, NULL), rsa.public.encoded, MESSAGE, signature))
    }

    @Test
    fun `verifier an unsupported OID outside its own role is INVALID`() {
        val garbage = TestDer.bytes(1, 2, 3)
        val ed = generate("Ed25519")
        assertTrue(P224 in verifier.unsupportedOids() && BRAINPOOL_P256 in verifier.unsupportedOids())
        // A curve OID in the signature position.
        assertEquals(INVALID, verifier.verify(algId(P224), ed.public.encoded, MESSAGE, garbage))
        assertEquals(
            INVALID,
            verifier.verify(algId(BRAINPOOL_P256), ed.public.encoded, MESSAGE, garbage),
        )
        // A curve OID as the parameters of a key other than id-ecPublicKey: no probe entry in that role, so the JDK's
        // KeyFactory decides (it reads the key and ignores the parameters, so the verifier answers as the JDK does).
        val edBits = ed.public.encoded.copyOfRange(ed.public.encoded.size - 32, ed.public.encoded.size)
        val signature = sign("Ed25519", ed.private)
        val withCurve = spki(algId(ED25519, TestDer.oid(BRAINPOOL_P256)), edBits)
        val jdk =
            runCatching {
                val key =
                    java.security.KeyFactory
                        .getInstance(
                            "Ed25519",
                        ).generatePublic(java.security.spec.X509EncodedKeySpec(withCurve))
                jdkVerifies("Ed25519", key, signature)
            }.getOrDefault(false)
        assertEquals(if (jdk) VERIFIED else INVALID, verifier.verify(algId(ED25519), withCurve, MESSAGE, signature))
        // A curve OID as the key OID.
        assertEquals(INVALID, verifier.verify(algId(ED25519), spki(algId(BRAINPOOL_P256), edBits), MESSAGE, signature))
        assertEquals(VERIFIED, verifier.verify(algId(ED25519), spki(algId(ED25519), edBits), MESSAGE, signature))
    }

    @Test
    fun `verifier key-OID gaps are INVALID`() {
        val ec = JcaFixtures.ec("secp256r1")
        val signature = sign("SHA256withECDSA", ec.private)
        val bits = ec.public.encoded.copyOfRange(ec.public.encoded.size - 65, ec.public.encoded.size)
        // The EC point under a DSA, an X25519, a private-arc OID; an EC key without a named curve; secp256k1, unlisted.
        val gaps =
            listOf(
                algId("1.2.840.10040.4.1"),
                algId("1.3.101.110"),
                algId("1.3.6.1.4.1.55555.2"),
                algId(EC_KEY),
                algId(EC_KEY, NULL),
                algId(EC_KEY, TestDer.oid(SECP256K1)),
            )
        for (gap in gaps) {
            assertEquals(
                INVALID,
                verifier.verify(algId(ECDSA_SHA256), spki(gap, bits), MESSAGE, signature),
            )
        }
        assertEquals(
            VERIFIED,
            verifier.verify(algId(ECDSA_SHA256), spki(algId(EC_KEY, TestDer.oid(P256)), bits), MESSAGE, signature),
        )
    }

    @Test
    fun `verifier a key that cannot have made the signature is INVALID`() {
        val rsa = rsa()
        val ec = JcaFixtures.ec("secp256r1")
        val ed = generate("Ed25519")
        val ed448 = generate("Ed448")
        assertEquals(
            INVALID,
            verifier.verify(algId(SHA256_RSA, NULL), ec.public.encoded, MESSAGE, sign("SHA256withRSA", rsa.private)),
        )
        assertEquals(
            INVALID,
            verifier.verify(algId(ECDSA_SHA256), rsa.public.encoded, MESSAGE, sign("SHA256withECDSA", ec.private)),
        )
        assertEquals(
            INVALID,
            verifier.verify(algId(ED25519), ed448.public.encoded, MESSAGE, sign("Ed448", ed448.private)),
        )
        assertEquals(INVALID, verifier.verify(algId(ED448), ed.public.encoded, MESSAGE, sign("Ed25519", ed.private)))
        if (JdkFacts.shipsMlDsa()) {
            val ml65 = generate("ML-DSA-65")
            assertEquals(
                INVALID,
                verifier.verify(algId(ML_DSA_44), ml65.public.encoded, MESSAGE, sign("ML-DSA-65", ml65.private)),
            )
        }
        // RFC 4055 §1.2: an id-RSASSA-PSS key signs PSS only. The JDK signs and verifies PKCS#1 v1.5 with it.
        val pssKey = JcaFixtures.pair("rsa-pss") { generate("RSASSA-PSS", size = 2048) }
        val v15 = sign("SHA256withRSA", pssKey.private)
        assertTrue(jdkVerifies("SHA256withRSA", pssKey.public, v15))
        assertEquals(INVALID, verifier.verify(algId(SHA256_RSA, NULL), pssKey.public.encoded, MESSAGE, v15))
    }

    @Test
    fun `verifier parameters other than absent or NULL outside PSS are INVALID`() {
        val rsa = rsa()
        val ec = JcaFixtures.ec("secp256r1")
        val ed = generate("Ed25519")
        val pkcs1 = sign("SHA256withRSA", rsa.private)
        assertEquals(VERIFIED, verifier.verify(algId(SHA256_RSA, NULL), rsa.public.encoded, MESSAGE, pkcs1))
        assertEquals(VERIFIED, verifier.verify(algId(SHA256_RSA), rsa.public.encoded, MESSAGE, pkcs1))
        assertEquals(
            INVALID,
            verifier.verify(algId(SHA256_RSA, TestDer.tlv(0x02, TestDer.bytes(0))), rsa.public.encoded, MESSAGE, pkcs1),
        )
        assertEquals(
            INVALID,
            verifier.verify(algId(SHA256_RSA, pssParams(SHA256, SHA256, 32)), rsa.public.encoded, MESSAGE, pkcs1),
        )
        val ecdsa = sign("SHA256withECDSA", ec.private)
        assertEquals(VERIFIED, verifier.verify(algId(ECDSA_SHA256, NULL), ec.public.encoded, MESSAGE, ecdsa))
        assertEquals(
            INVALID,
            verifier.verify(algId(ECDSA_SHA256, TestDer.oid(P256)), ec.public.encoded, MESSAGE, ecdsa),
        )
        assertEquals(
            INVALID,
            verifier.verify(algId(ED25519, TestDer.oid(P256)), ed.public.encoded, MESSAGE, sign("Ed25519", ed.private)),
        )
    }

    @Test
    fun `verifier PSS parameters explicit`() {
        val rsa = rsa()
        for ((hash, name, salt) in listOf(
            Triple(SHA256, "SHA-256", 32),
            Triple(SHA384, "SHA-384", 0),
            Triple(SHA512, "SHA-512", 20),
        )) {
            val signature = sign("RSASSA-PSS", rsa.private, params = pssSpec(name, name, salt))
            assertEquals(
                VERIFIED,
                verifier.verify(algId(PSS, pssParams(hash, hash, salt)), rsa.public.encoded, MESSAGE, signature),
                name,
            )
            // The salt length is honoured: the same signature under another declared length is INVALID.
            assertEquals(
                INVALID,
                verifier.verify(algId(PSS, pssParams(hash, hash, salt + 1)), rsa.public.encoded, MESSAGE, signature),
                name,
            )
            // The hash is honoured.
            val other = if (hash == SHA256) SHA384 else SHA256
            assertEquals(
                INVALID,
                verifier.verify(algId(PSS, pssParams(other, hash, salt)), rsa.public.encoded, MESSAGE, signature),
                name,
            )
            // DEFAULT values written out (DER omits them; the JDK accepts both) and the trailer field written out.
            assertEquals(
                VERIFIED,
                verifier.verify(algId(PSS, pssParams(hash, hash, salt, 1)), rsa.public.encoded, MESSAGE, signature),
                name,
            )
        }
    }

    @Test
    fun `verifier PSS parameters mismatched MGF hash`() {
        val rsa = rsa()
        val signature = sign("RSASSA-PSS", rsa.private, params = pssSpec("SHA-256", "SHA-384", 32))
        assertTrue(jdkVerifies("RSASSA-PSS", rsa.public, signature, params = pssSpec("SHA-256", "SHA-384", 32)))
        // Declared as signed: honoured, so it verifies; declared with the message hash for MGF1: INVALID.
        assertEquals(
            VERIFIED,
            verifier.verify(algId(PSS, pssParams(SHA256, SHA384, 32)), rsa.public.encoded, MESSAGE, signature),
        )
        assertEquals(
            INVALID,
            verifier.verify(algId(PSS, pssParams(SHA256, SHA256, 32)), rsa.public.encoded, MESSAGE, signature),
        )
    }

    @Test
    fun `verifier PSS parameters defaults`() {
        val rsa = rsa()
        // All DEFAULT: SHA-1, MGF1 with SHA-1, salt 20. The JDK verifies it; SHA-1 is outside the SHA-2 rule, so INVALID.
        val sha1 = sign("RSASSA-PSS", rsa.private, params = pssSpec("SHA-1", "SHA-1", 20))
        assertTrue(jdkVerifies("RSASSA-PSS", rsa.public, sha1, params = pssSpec("SHA-1", "SHA-1", 20)))
        assertEquals(INVALID, verifier.verify(algId(PSS, pssParams()), rsa.public.encoded, MESSAGE, sha1))
        // SHA-1 as the message hash under an SHA-2 MGF1: the JDK verifies it; outside the rule.
        val sha1Hash = sign("RSASSA-PSS", rsa.private, params = pssSpec("SHA-1", "SHA-256", 20))
        assertTrue(jdkVerifies("RSASSA-PSS", rsa.public, sha1Hash, params = pssSpec("SHA-1", "SHA-256", 20)))
        assertEquals(
            INVALID,
            verifier.verify(algId(PSS, pssParams(SHA1, SHA256)), rsa.public.encoded, MESSAGE, sha1Hash),
        )
        // Only the hash given: MGF1 defaults to SHA-1, also outside the rule.
        val mgfSha1 = sign("RSASSA-PSS", rsa.private, params = pssSpec("SHA-256", "SHA-1", 20))
        assertEquals(INVALID, verifier.verify(algId(PSS, pssParams(SHA256)), rsa.public.encoded, MESSAGE, mgfSha1))
        // The salt and trailer defaults apply: SHA-256 with MGF1 SHA-256 and the default salt 20.
        val salt20 = sign("RSASSA-PSS", rsa.private, params = pssSpec("SHA-256", "SHA-256", 20))
        assertEquals(
            VERIFIED,
            verifier.verify(algId(PSS, pssParams(SHA256, SHA256)), rsa.public.encoded, MESSAGE, salt20),
        )
        // Absent and malformed parameters, and a trailer field other than 1.
        assertEquals(INVALID, verifier.verify(algId(PSS), rsa.public.encoded, MESSAGE, salt20))
        assertEquals(INVALID, verifier.verify(algId(PSS, NULL), rsa.public.encoded, MESSAGE, salt20))
        assertEquals(
            INVALID,
            verifier.verify(algId(PSS, pssParams(SHA256, SHA256, 20, 2)), rsa.public.encoded, MESSAGE, salt20),
        )
        assertEquals(
            INVALID,
            verifier.verify(algId(PSS, pssParams(SHA256, SHA1, 20)), rsa.public.encoded, MESSAGE, salt20),
        )
        // A salt no key has room for: the JDK's own length check overflows near Int.MAX_VALUE; INVALID, never a throw.
        for (salt in listOf(223, 2048, 2049, Int.MAX_VALUE - 34, Int.MAX_VALUE)) {
            assertEquals(
                INVALID,
                verifier.verify(algId(PSS, pssParams(SHA256, SHA256, salt)), rsa.public.encoded, MESSAGE, salt20),
                "$salt",
            )
        }
    }

    @Test
    fun `verifier PSS key parameters are the JDK's to enforce`() {
        val spec = pssSpec("SHA-256", "SHA-256", 32)
        val restricted =
            JcaFixtures.pair("rsa-pss-restricted") {
                generate("RSASSA-PSS", RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4, spec))
            }
        val good = sign("RSASSA-PSS", restricted.private, params = spec)
        assertEquals(
            VERIFIED,
            verifier.verify(algId(PSS, pssParams(SHA256, SHA256, 32)), restricted.public.encoded, MESSAGE, good),
        )
        // A signature under other parameters than the key allows: the JDK refuses the pair, so INVALID.
        val unrestricted = JcaFixtures.pair("rsa-pss") { generate("RSASSA-PSS", size = 2048) }
        assertEquals(
            INVALID,
            verifier.verify(algId(PSS, pssParams(SHA384, SHA384, 48)), restricted.public.encoded, MESSAGE, good),
        )
        assertFalse(jdkVerifies("RSASSA-PSS", restricted.public, good, params = pssSpec("SHA-384", "SHA-384", 48)))
        assertEquals(
            INVALID,
            verifier.verify(algId(PSS, pssParams(SHA256, SHA256, 32)), unrestricted.public.encoded, MESSAGE, good),
        )
    }

    @Test
    fun `verifier an off-curve point on a supported OID is INVALID`() {
        val ec = JcaFixtures.ec("secp256r1")
        val signature = sign("SHA256withECDSA", ec.private)
        val offCurve = flip(ec.public.encoded)
        assertFalse(jdkVerifiesSpki(offCurve, signature))
        assertEquals(INVALID, verifier.verify(algId(ECDSA_SHA256), offCurve, MESSAGE, signature))
        // A compressed point and a point of the wrong length.
        val bits = ec.public.encoded.copyOfRange(ec.public.encoded.size - 65, ec.public.encoded.size)
        val compressed = byteArrayOf(0x02) + bits.copyOfRange(1, 33)
        for (b in listOf(compressed, bits.copyOf(64), ByteArray(0), byteArrayOf(0x00))) {
            assertEquals(
                INVALID,
                verifier.verify(algId(ECDSA_SHA256), spki(algId(EC_KEY, TestDer.oid(P256)), b), MESSAGE, signature),
            )
        }
        assertEquals(0, verifier.cachedKeyCount)
    }

    private fun jdkVerifiesSpki(
        spki: ByteArray,
        signature: ByteArray,
    ): Boolean =
        runCatching {
            val key =
                java.security.KeyFactory
                    .getInstance(
                        "EC",
                    ).generatePublic(java.security.spec.X509EncodedKeySpec(spki))
            jdkVerifies("SHA256withECDSA", key, signature)
        }.getOrDefault(false)

    @Test
    fun `verifier malformed inputs are INVALID and never throw`() {
        val ec = JcaFixtures.ec("secp256r1")
        val sigAlg = algId(ECDSA_SHA256)
        val key = ec.public.encoded
        val signature = sign("SHA256withECDSA", ec.private)
        val junk =
            listOf(
                ByteArray(0),
                TestDer.bytes(0x30),
                TestDer.bytes(0x30, 0x00),
                TestDer.bytes(0x30, 0x80, 0x00, 0x00),
                TestDer.bytes(0x05, 0x00),
                TestDer.seq(TestDer.tlv(0x06)),
                TestDer.seq(TestDer.tlv(0x06, TestDer.bytes(0x81))),
            )
        for (j in junk) {
            assertEquals(INVALID, verifier.verify(j, key, MESSAGE, signature))
            assertEquals(INVALID, verifier.verify(sigAlg, j, MESSAGE, signature))
        }
        assertEquals(INVALID, verifier.verify(sigAlg + TestDer.bytes(0x00), key, MESSAGE, signature), "trailing bytes")
        assertEquals(INVALID, verifier.verify(sigAlg, key + TestDer.bytes(0x00), MESSAGE, signature), "trailing bytes")
        assertEquals(
            INVALID,
            verifier.verify(TestDer.seq(TestDer.oid(ECDSA_SHA256), NULL, NULL), key, MESSAGE, signature),
        )
        // An SPKI with an element after the BIT STRING, or no BIT STRING.
        val inner = key.copyOfRange(2, key.size)
        assertEquals(INVALID, verifier.verify(sigAlg, TestDer.seq(inner, NULL), MESSAGE, signature))
        assertEquals(
            INVALID,
            verifier.verify(sigAlg, TestDer.seq(algId(EC_KEY, TestDer.oid(P256))), MESSAGE, signature),
        )
        // A non-DER ECDSA signature and a raw (r ‖ s) one.
        assertEquals(
            INVALID,
            verifier.verify(sigAlg, key, MESSAGE, TestDer.bytes(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00)),
        )
        assertEquals(INVALID, verifier.verify(sigAlg, key, MESSAGE, ByteArray(64) { 1 }))
        assertEquals(VERIFIED, verifier.verify(sigAlg, key, MESSAGE, signature))
    }

    @Test
    fun `verifier key cache holds only keys that produced VERIFIED`() {
        val v = JcaSignatureVerifier()
        val ed = generate("Ed25519")
        val signature = sign("Ed25519", ed.private)
        assertEquals(INVALID, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, flip(signature)))
        assertEquals(0, v.cachedKeyCount, "a key whose verification was INVALID is not cached")
        assertEquals(INVALID, v.verify(algId(ED25519), spki(algId(ED25519), ByteArray(32) { 7 }), MESSAGE, signature))
        assertEquals(INVALID, v.verify(algId(ED25519), spki(algId(ED25519), ByteArray(3)), MESSAGE, signature))
        assertEquals(0, v.cachedKeyCount, "a junk key is never cached")
        assertEquals(VERIFIED, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, signature))
        assertEquals(1, v.cachedKeyCount)
        // The cached key still checks every signature.
        assertEquals(INVALID, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, flip(signature)))
        assertEquals(INVALID, v.verify(algId(ED25519), ed.public.encoded, flip(MESSAGE, 0), signature))
        assertEquals(VERIFIED, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, signature))
        assertEquals(1, v.cachedKeyCount)
        // A cached key under a signature OID it cannot have made is still INVALID (the table check runs first).
        assertEquals(INVALID, v.verify(algId(ED448), ed.public.encoded, MESSAGE, signature))
    }

    @Test
    fun `verifier key cache is bounded at 1024 entries`() {
        val v = JcaSignatureVerifier()
        val pairs = List(1_025) { generate("Ed25519") }
        for (p in pairs) {
            assertEquals(
                VERIFIED,
                v.verify(algId(ED25519), p.public.encoded, MESSAGE, sign("Ed25519", p.private)),
            )
        }
        assertEquals(1_024, v.cachedKeyCount)
        // The evicted (least recently used) key is parsed again and still verifies.
        assertEquals(
            VERIFIED,
            v.verify(algId(ED25519), pairs[0].public.encoded, MESSAGE, sign("Ed25519", pairs[0].private)),
        )
        assertEquals(1_024, v.cachedKeyCount)
    }

    @Test
    fun `verifier a curve outside P-256 verifies on its own curve only`() {
        val p384 = JcaFixtures.ec("secp384r1")
        val signature = sign("SHA384withECDSA", p384.private)
        assertEquals(
            VERIFIED,
            verifier.verify(algId(JcaFixtures.ECDSA_SHA384), p384.public.encoded, MESSAGE, signature),
        )
        val p256 = generate("EC", ECGenParameterSpec("secp256r1"))
        assertEquals(INVALID, verifier.verify(algId(JcaFixtures.ECDSA_SHA384), p256.public.encoded, MESSAGE, signature))
    }
}
