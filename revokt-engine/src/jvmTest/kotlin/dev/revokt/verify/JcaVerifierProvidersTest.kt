// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.VerifyResult.INVALID
import dev.revokt.VerifyResult.UNSUPPORTED
import dev.revokt.VerifyResult.VERIFIED
import dev.revokt.engine.parse.TestDer
import dev.revokt.verify.JcaFixtures.COMPOSITE_MLDSA44_ED25519
import dev.revokt.verify.JcaFixtures.ECDSA_SHA256
import dev.revokt.verify.JcaFixtures.ED25519
import dev.revokt.verify.JcaFixtures.MESSAGE
import dev.revokt.verify.JcaFixtures.ML_DSA_44
import dev.revokt.verify.JcaFixtures.NULL
import dev.revokt.verify.JcaFixtures.P256
import dev.revokt.verify.JcaFixtures.PSS
import dev.revokt.verify.JcaFixtures.SHA256
import dev.revokt.verify.JcaFixtures.SHA256_RSA
import dev.revokt.verify.JcaFixtures.algId
import dev.revokt.verify.JcaFixtures.flip
import dev.revokt.verify.JcaFixtures.generate
import dev.revokt.verify.JcaFixtures.pssParams
import dev.revokt.verify.JcaFixtures.pssSpec
import dev.revokt.verify.JcaFixtures.sign
import dev.revokt.verify.JcaFixtures.spki
import org.conscrypt.Conscrypt
import java.security.KeyFactory
import java.security.ProviderException
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.SignatureException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Spec §3 and §10: `UNSUPPORTED` is decided by the startup probe against the given provider, never by a server-chosen
 * exception, and provider exceptions never escape the walk: a throwing provider is `INVALID` plus `VerifierError`
 * through [verifyClassified]. Providers differ, so the probe is checked against SunEC alone and Conscrypt too.
 */
class JcaVerifierProvidersTest {
    private val ed = generate("Ed25519")
    private val edSignature = sign("Ed25519", ed.private)
    private val tables =
        JcaAlgorithms.SIGNATURES.keys + JcaAlgorithms.KEYS.keys + JcaAlgorithms.CURVES

    private fun edProvider(
        onVerify: (Boolean) -> Boolean = { it },
        onPublic: ((KeyFactory, java.security.spec.KeySpec) -> PublicKey)? = null,
    ): TestProvider =
        TestProvider("ed-only")
            .signature("Ed25519") { DelegatingSignature(Signature.getInstance("Ed25519", "SunEC"), onVerify) }
            .keyFactory("Ed25519") {
                val inner = KeyFactory.getInstance("Ed25519", "SunEC")
                DelegatingKeyFactory(
                    inner,
                    onPublic?.let { f -> { spec -> f(inner, spec) } } ?: { inner.generatePublic(it) },
                )
            }

    @Test
    fun `verifier probe covers exactly what the given provider has`() {
        val v = JcaSignatureVerifier(edProvider())
        assertEquals(tables - ED25519, v.unsupportedOids())
        assertEquals(VERIFIED, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, edSignature))
        assertEquals(INVALID, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, flip(edSignature)))
        val ec = JcaFixtures.ec("secp256r1")
        assertEquals(
            UNSUPPORTED,
            v.verify(algId(ECDSA_SHA256), ec.public.encoded, MESSAGE, sign("SHA256withECDSA", ec.private)),
        )
    }

    @Test
    fun `verifier a throwing provider is INVALID plus VerifierError`() {
        val boom = IllegalStateException("provider bug")
        val v = JcaSignatureVerifier(edProvider(onVerify = { throw boom }))
        val thrown =
            assertFailsWith<ProviderException> { v.verify(algId(ED25519), ed.public.encoded, MESSAGE, edSignature) }
        assertSame(boom, thrown.cause)
        val classified = v.verifyClassified(algId(ED25519), ed.public.encoded, MESSAGE, edSignature)
        assertEquals(INVALID, classified.result)
        assertEquals("Ed25519 on $ED25519 threw java.lang.IllegalStateException", classified.error)
        assertEquals(0, v.cachedKeyCount)
    }

    @Test
    fun `verifier a KeyFactory that throws a RuntimeException is INVALID plus VerifierError`() {
        val v = JcaSignatureVerifier(edProvider(onPublic = { _, _ -> throw ArrayIndexOutOfBoundsException(3) }))
        assertFailsWith<ProviderException> { v.verify(algId(ED25519), ed.public.encoded, MESSAGE, edSignature) }
        assertEquals(INVALID, v.verifyClassified(algId(ED25519), ed.public.encoded, MESSAGE, edSignature).result)
    }

    @Test
    fun `verifier a GeneralSecurityException from the provider is INVALID without a finding`() {
        val v = JcaSignatureVerifier(edProvider(onVerify = { throw SignatureException("bad encoding") }))
        val classified = v.verifyClassified(algId(ED25519), ed.public.encoded, MESSAGE, edSignature)
        assertEquals(INVALID, classified.result)
        assertNull(classified.error)
    }

    @Test
    fun `verifier a provider's JVM error is INVALID plus VerifierError unless fatal`() {
        val overflow = JcaSignatureVerifier(edProvider(onVerify = { throw StackOverflowError() }))
        // An Error is not the provider's RuntimeException: it propagates unwrapped, and the classification catches it.
        assertFailsWith<StackOverflowError> { overflow.verify(algId(ED25519), ed.public.encoded, MESSAGE, edSignature) }
        val classified = overflow.verifyClassified(algId(ED25519), ed.public.encoded, MESSAGE, edSignature)
        assertEquals(INVALID, classified.result)
        assertEquals("StackOverflowError", classified.error)
        val oom = JcaSignatureVerifier(edProvider(onVerify = { throw OutOfMemoryError("test") }))
        assertFailsWith<OutOfMemoryError> {
            oom.verifyClassified(
                algId(ED25519),
                ed.public.encoded,
                MESSAGE,
                edSignature,
            )
        }
    }

    @Test
    fun `verifier a provider's non-fatal Error is INVALID plus VerifierError`() {
        // Spec §5.5: every throwable but a VirtualMachineError (other than StackOverflowError) is caught.
        for (error in listOf(AssertionError("provider assertion"), NoClassDefFoundError("provider/Missing"))) {
            val v = JcaSignatureVerifier(edProvider(onVerify = { throw error }))
            val thrown =
                runCatching {
                    v.verify(
                        algId(ED25519),
                        ed.public.encoded,
                        MESSAGE,
                        edSignature,
                    )
                }.exceptionOrNull()
            assertSame(error, thrown, "an Error is not wrapped")
            val classified = v.verifyClassified(algId(ED25519), ed.public.encoded, MESSAGE, edSignature)
            assertEquals(INVALID, classified.result)
            assertEquals(error.message, classified.error)
        }
    }

    @Test
    fun `verifier a provider whose services fail to link while probed has them unsupported`() {
        val linkage =
            TestProvider("linkage")
                .signature("Ed25519") { throw NoClassDefFoundError("provider/Ed25519Spi") }
                .keyFactory("Ed25519") { throw UnsatisfiedLinkError("no native library") }
                .signature(
                    "SHA256withRSA",
                ) { DelegatingSignature(Signature.getInstance("SHA256withRSA", "SunRsaSign")) }
                .keyFactory("RSA") { DelegatingKeyFactory(KeyFactory.getInstance("RSA", "SunRsaSign")) }
        val v = JcaSignatureVerifier(linkage)
        assertTrue(ED25519 in v.unsupportedOids())
        assertEquals(UNSUPPORTED, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, edSignature))
        val rsa = JcaFixtures.rsa()
        assertEquals(
            VERIFIED,
            v.verify(algId(SHA256_RSA, NULL), rsa.public.encoded, MESSAGE, sign("SHA256withRSA", rsa.private)),
        )
        // A fatal error while probing is not swallowed (§5.5).
        val fatal = TestProvider("fatal").signature("Ed25519") { throw OutOfMemoryError("probe") }
        assertFailsWith<OutOfMemoryError> { JcaSignatureVerifier(fatal) }
    }

    @Test
    fun `verifier a composite OID needs the provider's KeyFactory too`() {
        val signatureOnly =
            TestProvider("composite-signature-only").signature(COMPOSITE_MLDSA44_ED25519) {
                AcceptingSignature()
            }
        val v = JcaSignatureVerifier(signatureOnly)
        assertTrue(COMPOSITE_MLDSA44_ED25519 in v.unsupportedOids())
        val compositeSpki = spki(algId(COMPOSITE_MLDSA44_ED25519), TestDer.bytes(1, 2, 3))
        assertEquals(UNSUPPORTED, v.verify(algId(COMPOSITE_MLDSA44_ED25519), compositeSpki, MESSAGE, TestDer.bytes(1)))
    }

    @Test
    fun `verifier an unsupported key OID in the signature position is INVALID`() {
        // SunEC alone has no RSA KeyFactory: rsaEncryption is unsupported as a key, and is no signature OID.
        val sunEc = JcaSignatureVerifier(Security.getProvider("SunEC"))
        assertTrue(JcaFixtures.RSA_KEY in sunEc.unsupportedOids())
        assertEquals(INVALID, sunEc.verify(algId(JcaFixtures.RSA_KEY, NULL), ed.public.encoded, MESSAGE, edSignature))
        assertEquals(UNSUPPORTED, sunEc.verify(algId(ED25519), JcaFixtures.rsa().public.encoded, MESSAGE, edSignature))
    }

    @Test
    fun `verifier a provider that throws while probed has nothing supported`() {
        val broken =
            TestProvider("broken")
                .signature("Ed25519") { throw IllegalStateException("cannot construct") }
                .keyFactory("Ed25519") { DelegatingKeyFactory(KeyFactory.getInstance("Ed25519", "SunEC")) }
        val v = JcaSignatureVerifier(broken)
        assertEquals(tables, v.unsupportedOids())
        assertEquals(UNSUPPORTED, v.verify(algId(ED25519), ed.public.encoded, MESSAGE, edSignature))
    }

    @Test
    fun `verifier a provider whose ECDSA accepts the probe's junk gets no curve`() {
        val yes =
            TestProvider("ecdsa-yes")
                .signature(
                    "SHA256withECDSA",
                ) { DelegatingSignature(Signature.getInstance("SHA256withECDSA", "SunEC")) { true } }
                .keyFactory("EC") { DelegatingKeyFactory(KeyFactory.getInstance("EC", "SunEC")) }
        val v = JcaSignatureVerifier(yes)
        assertTrue(JcaAlgorithms.CURVES.all { it in v.unsupportedOids() })
        assertFalse(ECDSA_SHA256 in v.unsupportedOids())
        val ec = JcaFixtures.ec("secp256r1")
        assertEquals(UNSUPPORTED, v.verify(algId(ECDSA_SHA256), ec.public.encoded, MESSAGE, TestDer.bytes(1)))
    }

    @Test
    fun `verifier the reject rules are the verifier's own, not the provider's`() {
        // A provider that accepts every signature: what is still INVALID is decided by the verifier's tables and rules.
        // It has the RSASSA-PSS KeyFactory too: the PSS OID names a key and a signature, and one OID set covers both roles.
        val key =
            object : PublicKey {
                override fun getAlgorithm() = "any"

                override fun getFormat() = "X.509"

                override fun getEncoded() = ByteArray(0)
            }
        val accepting = TestProvider("accepting")
        for (name in listOf("RSASSA-PSS", "SHA256withRSA", "SHA1withRSA", "SHA256withECDSA", "SHA1withECDSA")) {
            accepting.signature(name) { AcceptingSignature() }
        }
        // It has the RSASSA-PSS KeyFactory too: the PSS OID names a key and a signature, and one OID set covers both roles.
        for (name in listOf("RSA", "RSASSA-PSS", "EC")) {
            accepting.keyFactory(name) {
                DelegatingKeyFactory(KeyFactory.getInstance(name)) { key }
            }
        }
        val v = JcaSignatureVerifier(accepting)
        val rsaKey = spki(algId(JcaFixtures.RSA_KEY, NULL), TestDer.bytes(1))
        val junk = TestDer.bytes(1)
        assertEquals(VERIFIED, v.verify(algId(PSS, pssParams(SHA256, SHA256, 32)), rsaKey, MESSAGE, junk))
        assertEquals(VERIFIED, v.verify(algId(SHA256_RSA, NULL), rsaKey, MESSAGE, junk))
        val rejected =
            listOf(
                "trailer field 2" to algId(PSS, pssParams(SHA256, SHA256, 32, 2)),
                "SHA-1 PSS hash" to algId(PSS, pssParams(JcaFixtures.SHA1, SHA256, 32)),
                "SHA-1 MGF1 hash" to algId(PSS, pssParams(SHA256, JcaFixtures.SHA1, 32)),
                "salt past every key" to algId(PSS, pssParams(SHA256, SHA256, 2049)),
                "absent PSS parameters" to algId(PSS),
                "PKCS#1 with parameters" to algId(SHA256_RSA, TestDer.oid(P256)),
                "SHA-1 PKCS#1" to algId(JcaFixtures.SHA1_RSA, NULL),
            )
        for ((what, sigAlg) in rejected) assertEquals(INVALID, v.verify(sigAlg, rsaKey, MESSAGE, junk), what)
        assertEquals(
            VERIFIED,
            v.verify(algId(PSS, pssParams(SHA256, SHA256, 2048)), rsaKey, MESSAGE, junk),
            "salt at the cap",
        )
        // The probe's junk signature verifies here, so no curve is supported; a curve outside the table is never tried.
        assertTrue(P256 in v.unsupportedOids())
        for (params in listOf(TestDer.oid(JcaFixtures.SECP256K1), NULL, ByteArray(0))) {
            val ecKey = spki(algId(JcaFixtures.EC_KEY, params), TestDer.bytes(4, 1, 2))
            assertEquals(INVALID, v.verify(algId(ECDSA_SHA256), ecKey, MESSAGE, junk))
            assertEquals(INVALID, v.verify(algId(JcaFixtures.ECDSA_SHA1), ecKey, MESSAGE, junk))
        }
    }

    @Test
    fun `verifier a curve whose encoded key the provider cannot decode is unsupported`() {
        // The provider's ECDSA runs on SunEC's keys, but its KeyFactory refuses encoded ones: verify decodes through it.
        val provider =
            TestProvider("ec-no-x509")
                .signature("SHA256withECDSA") { DelegatingSignature(Signature.getInstance("SHA256withECDSA", "SunEC")) }
                .keyFactory("EC") {
                    DelegatingKeyFactory(KeyFactory.getInstance("EC", "SunEC")) {
                        throw java.security.spec.InvalidKeySpecException("no X.509")
                    }
                }
        val v = JcaSignatureVerifier(provider)
        assertTrue(JcaAlgorithms.CURVES.all { it in v.unsupportedOids() })
        assertFalse(ECDSA_SHA256 in v.unsupportedOids())
    }

    @Test
    fun `verifier a composite OID is verified by a provider that owns it`() {
        val expected = TestDer.bytes(9, 9, 9)
        val key =
            object : PublicKey {
                override fun getAlgorithm() = COMPOSITE_MLDSA44_ED25519

                override fun getFormat() = "X.509"

                override fun getEncoded() = ByteArray(0)
            }
        val owner =
            TestProvider("composite-owner")
                .signature(COMPOSITE_MLDSA44_ED25519) {
                    // A stand-in for a composite implementation: it accepts exactly `expected` (routing only).
                    object : DelegatingSignature(Signature.getInstance("Ed25519", "SunEC")) {
                        override fun engineInitVerify(publicKey: PublicKey) = Unit

                        override fun engineUpdate(b: Byte) = Unit

                        override fun engineUpdate(
                            b: ByteArray,
                            off: Int,
                            len: Int,
                        ) = Unit

                        override fun engineVerify(sigBytes: ByteArray) = sigBytes.contentEquals(expected)
                    }
                }.keyFactory(
                    COMPOSITE_MLDSA44_ED25519,
                ) { DelegatingKeyFactory(KeyFactory.getInstance("Ed25519", "SunEC")) { key } }
                .keyFactory("RSA") { DelegatingKeyFactory(KeyFactory.getInstance("RSA", "SunRsaSign")) }
        val v = JcaSignatureVerifier(owner)
        assertFalse(COMPOSITE_MLDSA44_ED25519 in v.unsupportedOids())
        assertTrue("1.3.6.1.5.5.7.6.40" in v.unsupportedOids())
        val compositeSpki = spki(algId(COMPOSITE_MLDSA44_ED25519), TestDer.bytes(1, 2, 3))
        assertEquals(VERIFIED, v.verify(algId(COMPOSITE_MLDSA44_ED25519), compositeSpki, MESSAGE, expected))
        assertEquals(INVALID, v.verify(algId(COMPOSITE_MLDSA44_ED25519), compositeSpki, MESSAGE, flip(expected)))
        // Another composite OID is not the provider's; its key OID equals its signature OID, so an RSA key the provider
        // does support cannot have made it.
        assertEquals(UNSUPPORTED, v.verify(algId("1.3.6.1.5.5.7.6.40"), compositeSpki, MESSAGE, expected))
        assertFalse(JcaFixtures.RSA_KEY in v.unsupportedOids())
        assertEquals(
            INVALID,
            v.verify(algId(COMPOSITE_MLDSA44_ED25519), JcaFixtures.rsa().public.encoded, MESSAGE, expected),
        )
        assertEquals(
            UNSUPPORTED,
            JcaSignatureVerifier().verify(algId(COMPOSITE_MLDSA44_ED25519), compositeSpki, MESSAGE, expected),
        )
    }

    @Test
    fun `verifier PQ chain matrix without ML-DSA in the provider`() {
        // SunEC alone has no ML-DSA (nor RSA): the probe says so and an ML-DSA link is UNSUPPORTED, whatever the JDK.
        val sunEc = JcaSignatureVerifier(Security.getProvider("SunEC"))
        for (oid in listOf(ML_DSA_44, JcaFixtures.ML_DSA_65, JcaFixtures.ML_DSA_87, SHA256_RSA, PSS)) {
            assertTrue(oid in sunEc.unsupportedOids(), oid)
        }
        val mlDsaSpki = spki(algId(ML_DSA_44), ByteArray(1312))
        assertEquals(UNSUPPORTED, sunEc.verify(algId(ML_DSA_44), mlDsaSpki, MESSAGE, ByteArray(2420)))
        assertEquals(VERIFIED, sunEc.verify(algId(ED25519), ed.public.encoded, MESSAGE, edSignature))
        if (JdkFacts.shipsMlDsa()) {
            val ml = generate("ML-DSA-44")
            val signature = sign("ML-DSA-44", ml.private)
            assertEquals(UNSUPPORTED, sunEc.verify(algId(ML_DSA_44), ml.public.encoded, MESSAGE, signature))
            assertEquals(
                VERIFIED,
                JcaSignatureVerifier().verify(algId(ML_DSA_44), ml.public.encoded, MESSAGE, signature),
            )
        } else {
            assertEquals(
                UNSUPPORTED,
                JcaSignatureVerifier().verify(algId(ML_DSA_44), mlDsaSpki, MESSAGE, ByteArray(2420)),
            )
        }
    }

    @Test
    fun `verifier Conscrypt agrees with the JDK wherever its probe says supported`() {
        val conscrypt = JcaSignatureVerifier(Conscrypt.newProvider())
        val jdk = JcaSignatureVerifier()
        val unsupported = conscrypt.unsupportedOids()
        // Conscrypt names PSS `SHA256withRSA/PSS`, not `RSASSA-PSS`, and has no Ed448 nor brainpool.
        assertTrue(PSS in unsupported)
        assertTrue(JcaFixtures.ED448 in unsupported)
        assertTrue(JcaFixtures.BRAINPOOL_P256 in unsupported)
        val rsa = JcaFixtures.rsa()
        val ec = JcaFixtures.ec("secp256r1")
        val links =
            listOf(
                Triple(algId(SHA256_RSA, NULL), rsa.public.encoded, sign("SHA256withRSA", rsa.private)),
                Triple(algId(ECDSA_SHA256), ec.public.encoded, sign("SHA256withECDSA", ec.private)),
                Triple(algId(ED25519), ed.public.encoded, edSignature),
                Triple(
                    algId(PSS, pssParams(SHA256, SHA256, 32)),
                    rsa.public.encoded,
                    sign("RSASSA-PSS", rsa.private, params = pssSpec("SHA-256", "SHA-256", 32)),
                ),
            )
        for ((sigAlg, key, signature) in links) {
            val expected =
                if (dev.revokt.engine.parse.VerifierInput
                        .algorithm(sigAlg)!!
                        .oid in
                    unsupported
                ) {
                    UNSUPPORTED
                } else {
                    VERIFIED
                }
            assertEquals(expected, conscrypt.verify(sigAlg, key, MESSAGE, signature))
            assertEquals(VERIFIED, jdk.verify(sigAlg, key, MESSAGE, signature))
            if (expected == VERIFIED) assertEquals(INVALID, conscrypt.verify(sigAlg, key, MESSAGE, flip(signature)))
        }
        val offCurve = flip(ec.public.encoded)
        assertEquals(
            INVALID,
            conscrypt.verify(algId(ECDSA_SHA256), offCurve, MESSAGE, sign("SHA256withECDSA", ec.private)),
        )
        assertEquals(
            INVALID,
            conscrypt.verify(
                algId(ECDSA_SHA256),
                spki(algId(JcaFixtures.EC_KEY, TestDer.oid(P256)), ByteArray(65)),
                MESSAGE,
                TestDer.bytes(1),
            ),
        )
    }

    @Test
    fun `verifier PQ algorithms under Conscrypt`() {
        // Conscrypt 2.7.0 and 2.8.0 register ML-DSA-44/65/87, SLH-DSA-SHA2-128s and the composite ML-DSA-44 with Ed25519.
        val provider = Conscrypt.newProvider()
        val conscrypt = JcaSignatureVerifier(provider)
        val unsupported = conscrypt.unsupportedOids()
        val pq =
            listOf(
                ML_DSA_44 to "ML-DSA-44",
                JcaFixtures.ML_DSA_65 to "ML-DSA-65",
                JcaFixtures.ML_DSA_87 to "ML-DSA-87",
                JcaFixtures.SLH_DSA_SHA2_128S to "SLH-DSA-SHA2-128s",
                COMPOSITE_MLDSA44_ED25519 to COMPOSITE_MLDSA44_ED25519,
            )
        for ((oid, name) in pq) {
            assertFalse(oid in unsupported, name)
            val pair =
                java.security.KeyPairGenerator
                    .getInstance(name, provider)
                    .generateKeyPair()
            assertEquals(
                oid,
                dev.revokt.engine.parse.VerifierInput
                    .spkiAlgorithm(pair.public.encoded)
                    ?.oid,
                "$name SPKI",
            )
            val s = Signature.getInstance(name, provider)
            s.initSign(pair.private)
            s.update(MESSAGE)
            val signature = s.sign()
            assertEquals(VERIFIED, conscrypt.verify(algId(oid), pair.public.encoded, MESSAGE, signature), name)
            assertEquals(INVALID, conscrypt.verify(algId(oid), pair.public.encoded, MESSAGE, flip(signature)), name)
            assertEquals(INVALID, conscrypt.verify(algId(oid), pair.public.encoded, flip(MESSAGE, 0), signature), name)
            // The JDK's providers: ML-DSA where Appendix A says the JDK ships it; no SLH-DSA, no composite.
            val jdk = JcaSignatureVerifier().verify(algId(oid), pair.public.encoded, MESSAGE, signature)
            val jdkHas = name.startsWith("ML-DSA") && JdkFacts.shipsMlDsa()
            assertEquals(if (jdkHas) VERIFIED else UNSUPPORTED, jdk, "$name on the JDK")
        }
        // The other SLH-DSA sets are not Conscrypt's.
        assertTrue("2.16.840.1.101.3.4.3.21" in unsupported)
    }
}
