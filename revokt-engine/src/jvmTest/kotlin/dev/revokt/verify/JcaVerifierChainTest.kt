// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.VerifyResult
import dev.revokt.VerifyResult.INVALID
import dev.revokt.VerifyResult.UNSUPPORTED
import dev.revokt.VerifyResult.VERIFIED
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.Cert
import dev.revokt.verify.JcaFixtures.algId
import dev.revokt.verify.JcaFixtures.generate
import java.io.ByteArrayInputStream
import java.security.KeyPair
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec §9 "Verifier" over certificates, as the walker calls the verifier (the child's TBS `signature` field, the
 * candidate's raw SPKI, the TBS, the signature value): the OID harvest of the committed chains and the PQ chain matrix,
 * each link checked against the test JDK's `X509Certificate.verify`.
 */
class JcaVerifierChainTest {
    private val verifier = JcaSignatureVerifier()

    private fun cert(der: ByteArray): Cert =
        when (val r = CertificateParser.parse(der)) {
            is CertificateParse.Parsed -> Cert.of(r.certificate, ::canonicalSubject)
            is CertificateParse.Failed -> error("unparseable: ${r.reason} ${r.detail}")
        }

    private fun x509(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private fun JcaSignatureVerifier.link(
        child: Cert,
        issuer: Cert,
    ): VerifyResult = verify(child.tbsSigAlg, issuer.spki, child.tbs, child.sig)

    private fun jdkLink(
        child: ByteArray,
        issuer: ByteArray,
    ): Boolean = runCatching { x509(child).verify(x509(issuer).publicKey) }.isSuccess

    private val chains =
        mapOf(
            "github.com" to 3,
            "letsencrypt.org" to 4,
            "www.google.com" to 3,
            "www.mozilla.org" to 3,
            "mozilla-content-signing-c" to 3,
        )

    private fun fixture(name: String): ByteArray =
        checkNotNull(CertificateParser::class.java.getResourceAsStream("certs/$name.der")) {
            "missing $name"
        }.use { it.readBytes() }

    @Test
    fun `verifier OID harvest of the committed chains`() {
        val seen = sortedSetOf<String>()
        var links = 0
        for ((host, length) in chains) {
            val names =
                if (host.endsWith(
                        "-c",
                    )
                ) {
                    (0 until length).map { "$host$it" }
                } else {
                    (1..length).map { "$host-$it" }
                }
            val ders = names.map(::fixture)
            val certs = ders.map(::cert)
            for (c in certs) seen += listOfNotNull(c.tbsSigOid, c.keyOid, c.curveOid)
            for (i in 0 until certs.size - 1) {
                assertTrue(jdkLink(ders[i], ders[i + 1]), "${names[i]} under ${names[i + 1]} (JDK)")
                assertEquals(VERIFIED, verifier.link(certs[i], certs[i + 1]), "${names[i]} under ${names[i + 1]}")
                // The same link under the wrong issuer: the JDK and the verifier both refuse it.
                val wrong = certs[(i + 2) % certs.size]
                assertEquals(jdkLink(ders[i], ders[(i + 2) % certs.size]), verifier.link(certs[i], wrong) == VERIFIED)
                links++
            }
        }
        assertEquals(11, links)
        // Every OID the chains use is in the verifier's tables and supported on every matrix JDK.
        val tables = JcaAlgorithms.SIGNATURES.keys + JcaAlgorithms.KEYS.keys + JcaAlgorithms.CURVES
        for (oid in seen) {
            assertTrue(oid in tables, "$oid is not classified")
            assertTrue(oid !in verifier.unsupportedOids(), "$oid is unsupported")
        }
        assertEquals(
            sortedSetOf(
                "1.2.840.10045.2.1",
                "1.2.840.10045.3.1.7",
                "1.2.840.10045.4.3.2",
                "1.2.840.10045.4.3.3",
                "1.2.840.113549.1.1.1",
                "1.2.840.113549.1.1.11",
                "1.2.840.113549.1.1.12",
                "1.3.132.0.34",
            ),
            seen,
        )
    }

    /** A certificate for [pair] named [subject], issued by [issuer] under [sigAlg]/[jcaName], really signed. */
    private fun issue(
        subject: String,
        pair: KeyPair,
        issuer: String,
        issuerPair: KeyPair,
        sigAlg: ByteArray,
        jcaName: String,
        params: AlgorithmParameterSpec? = null,
    ): ByteArray {
        val unsigned =
            TestCert(
                tbsSignature = sigAlg,
                issuer = TestCert.name(issuer),
                subject = TestCert.name(subject),
                spki = pair.public.encoded,
                outerAlgorithm = sigAlg,
            )
        val signature = JcaFixtures.sign(jcaName, issuerPair.private, unsigned.tbs, params)
        return TestCert(
            tbsSignature = sigAlg,
            issuer = TestCert.name(issuer),
            subject = TestCert.name(subject),
            spki = pair.public.encoded,
            outerAlgorithm = sigAlg,
            signature = TestDer.tlv(0x03, TestDer.bytes(0x00), signature),
        ).der
    }

    @Test
    fun `verifier PQ chain matrix`() {
        if (!JdkFacts.shipsMlDsa()) {
            // Appendix A: a JDK without ML-DSA cannot have made these keys; the probe must say so.
            assertTrue(JcaFixtures.ML_DSA_44 in verifier.unsupportedOids())
            return
        }
        val root = generate("ML-DSA-87")
        val intermediate = generate("ML-DSA-65")
        val leaf = generate("ML-DSA-44")
        val rootDer = issue("PQ Root", root, "PQ Root", root, algId(JcaFixtures.ML_DSA_87), "ML-DSA-87")
        val intermediateDer =
            issue("PQ Intermediate", intermediate, "PQ Root", root, algId(JcaFixtures.ML_DSA_87), "ML-DSA-87")
        val leafDer =
            issue("pq.example", leaf, "PQ Intermediate", intermediate, algId(JcaFixtures.ML_DSA_65), "ML-DSA-65")
        val (r, i, l) = listOf(rootDer, intermediateDer, leafDer).map(::cert)
        val sunEc = JcaSignatureVerifier(Security.getProvider("SunEC"))
        for ((child, issuer, ders) in listOf(
            Triple(l, i, leafDer to intermediateDer),
            Triple(
                i,
                r,
                intermediateDer to rootDer,
            ),
            Triple(r, r, rootDer to rootDer),
        )) {
            assertTrue(jdkLink(ders.first, ders.second))
            assertEquals(VERIFIED, verifier.link(child, issuer))
            assertEquals(UNSUPPORTED, sunEc.link(child, issuer))
        }
        // The leaf under the root: the root's ML-DSA-87 key cannot have made an ML-DSA-65 signature.
        assertEquals(INVALID, verifier.link(l, r))
        assertEquals(false, jdkLink(leafDer, rootDer))
    }

    @Test
    fun `verifier mixed classical chain with PSS, ECDSA and EdDSA links`() {
        val root = JcaFixtures.rsa()
        val intermediate = JcaFixtures.ec("secp384r1")
        val leaf = generate("Ed25519")
        val pss = JcaFixtures.pssSpec("SHA-384", "SHA-384", 48)
        val pssAlg = algId(JcaFixtures.PSS, JcaFixtures.pssParams(JcaFixtures.SHA384, JcaFixtures.SHA384, 48))
        val intermediateDer = issue("EC Intermediate", intermediate, "RSA Root", root, pssAlg, "RSASSA-PSS", pss)
        val leafDer =
            issue(
                "ed.example",
                leaf,
                "EC Intermediate",
                intermediate,
                algId(JcaFixtures.ECDSA_SHA384),
                "SHA384withECDSA",
            )
        val rootDer =
            issue("RSA Root", root, "RSA Root", root, algId(JcaFixtures.SHA256_RSA, JcaFixtures.NULL), "SHA256withRSA")
        val (r, i, l) = listOf(rootDer, intermediateDer, leafDer).map(::cert)
        assertTrue(jdkLink(intermediateDer, rootDer))
        assertTrue(jdkLink(leafDer, intermediateDer))
        assertEquals(VERIFIED, verifier.link(i, r))
        assertEquals(VERIFIED, verifier.link(l, i))
        assertEquals(VERIFIED, verifier.link(r, r))
        assertEquals(INVALID, verifier.link(l, r))
        assertEquals(INVALID, verifier.link(i, i))
    }
}
