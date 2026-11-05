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
}
