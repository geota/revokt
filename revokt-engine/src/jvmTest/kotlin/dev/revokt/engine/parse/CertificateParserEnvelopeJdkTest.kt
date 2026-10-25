// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.ParseReason
import java.io.ByteArrayInputStream
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Spec §9.2 "The unsigned headers" (revision 34) against the JDK on real leaves: the envelope forms the JDK verifies
 * parse to the base certificate's `Cert.tbs`, fields and `Cert.sig`, and `Cert.tbs` equals `getTBSCertificate()`
 * wherever the JDK verifies a variant. The reject-side forms are `STRUCTURE` and verify on no JDK.
 */
class CertificateParserEnvelopeJdkTest {
    private class Chain(
        val name: String,
        val leaf: ByteArray,
        val issuerKey: PublicKey,
        val rsa: Boolean,
    )

    private val factory = CertificateFactory.getInstance("X.509")

    private fun load(name: String): ByteArray =
        checkNotNull(
            javaClass.getResourceAsStream("certs/$name.der"),
        ) { "missing fixture $name" }.use { it.readBytes() }

    private fun jdk(der: ByteArray): X509Certificate? =
        runCatching { factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate }.getOrNull()

    private val chains =
        listOf(
            Triple("letsencrypt.org-1", "letsencrypt.org-2", false),
            Triple("www.google.com-1", "www.google.com-2", false),
            Triple("www.mozilla.org-1", "www.mozilla.org-2", true),
        ).map { (leaf, issuer, rsa) -> Chain(leaf, load(leaf), jdk(load(issuer))!!.publicKey, rsa) }

    @Test
    fun `envelope forms parse to the JDK's verified message and the base certificate's fields`() {
        var verifiedCount = 0
        for (chain in chains) {
            val base = (CertificateParser.parse(chain.leaf) as CertificateParse.Parsed).certificate
            assertEquals(false, base.envelope.algorithmIdMismatch, "${chain.name} base")
            for (v in EnvelopeVariants.of(chain.rsa)) if (check(chain, base, v)) verifiedCount++
        }
        assertTrue(verifiedCount >= if (modern) 30 else 8, "only $verifiedCount variants verified")
    }

    private val modern = Runtime.version().feature() >= 17

    /** Checks one variant of [chain]'s leaf; returns whether the JDK verified it. */
    private fun check(
        chain: Chain,
        base: ParsedCertificate,
        v: EnvelopeVariants.Variant,
    ): Boolean {
        val label = "${chain.name} ${v.name}"
        val der = v.build(DerNode.parse(chain.leaf))
        val jdkCert = jdk(der)
        val verified = jdkCert != null && runCatching { jdkCert.verify(chain.issuerKey) }.isSuccess
        val parse = CertificateParser.parse(der)
        if (verified) {
            val p =
                (parse as? CertificateParse.Parsed)?.certificate
                    ?: fail("$label: JDK verifies, revokt ${parse.describe()}")
            assertContentEquals(jdkCert.tbsCertificate, p.tbsBytes, "$label: Cert.tbs is getTBSCertificate()")
        }
        when (v.expected) {
            EnvelopeVariants.Expected.SAME_AS_BASE -> {
                if (modern) assertTrue(verified, "$label: the JDK verifies it")
                val p = (parse as? CertificateParse.Parsed)?.certificate ?: fail("$label: ${parse.describe()}")
                assertSameAsBase(label, base, p, v.algorithmIdMismatch)
                assertTrue(p.steps <= 8L * der.size + 1024, "$label steps")
            }

            EnvelopeVariants.Expected.STRUCTURE -> {
                assertTrue(!verified, "$label: the JDK must not verify it")
                assertEquals(ParseReason.STRUCTURE, (parse as? CertificateParse.Failed)?.reason, label)
            }

            EnvelopeVariants.Expected.PARSED_JDK_REJECTS -> {
                assertTrue(!verified, "$label: the JDK must not verify it")
                assertTrue(parse is CertificateParse.Parsed, "$label: ${parse.describe()}")
            }
        }
        return verified
    }

    private fun assertSameAsBase(
        label: String,
        base: ParsedCertificate,
        p: ParsedCertificate,
        algorithmIdMismatch: Boolean,
    ) {
        assertContentEquals(base.tbsBytes, p.tbsBytes, "$label tbs")
        assertContentEquals(base.rawSerial(), p.rawSerial(), "$label serial")
        assertContentEquals(base.rawSpki(), p.rawSpki(), "$label spki")
        assertContentEquals(base.rawSubject(), p.rawSubject(), "$label subject")
        assertContentEquals(base.rawIssuer(), p.rawIssuer(), "$label issuer")
        assertEquals(base.fields.scts, p.fields.scts, "$label scts")
        assertContentEquals(base.envelope.signature, p.envelope.signature, "$label Cert.sig")
        assertEquals(algorithmIdMismatch, p.envelope.algorithmIdMismatch, "$label AlgorithmIdMismatch")
    }

    /**
     * Spec §9.2 revision 35: JDK 11 verifies an indefinite `signatureValue` whose content reads as a chain of minimal
     * TLVs (about 0.45 % of ECDSA signatures); JDK 17 and later reject it. A fresh P-256 key re-signs a real TBS until
     * revokt accepts the indefinite form a few times; wherever the JDK verifies one, revokt must parse it to the JDK's
     * message and signature.
     */
    @Test
    fun `an indefinite signatureValue that JDK 11 verifies parses to the JDK's message and signature`() {
        val leaf = DerNode.parse(chains.first().leaf)
        val tbs = leaf.child(0).encode()
        val keys =
            java.security.KeyPairGenerator
                .getInstance("EC")
                .apply { initialize(256) }
                .generateKeyPair()
        val signer = java.security.Signature.getInstance("SHA384withECDSA")
        var parsedCount = 0
        var verifiedCount = 0
        var tries = 0
        while (parsedCount < 3 && tries++ < 20_000) {
            signer.initSign(keys.private)
            signer.update(tbs)
            val sig = signer.sign()
            val der =
                TestDer.seq(
                    tbs,
                    leaf.child(1).encode(),
                    TestDer.bytes(0x03, 0x80, 0x00) + sig + TestDer.bytes(0, 0),
                )
            val parse = CertificateParser.parse(der)
            val jdkCert = jdk(der)
            val verified = jdkCert != null && runCatching { jdkCert.verify(keys.public) }.isSuccess
            if (verified) {
                verifiedCount++
                val p =
                    (parse as? CertificateParse.Parsed)?.certificate ?: fail("JDK verifies, revokt ${parse.describe()}")
                assertContentEquals(jdkCert.tbsCertificate, p.tbsBytes)
                assertContentEquals(sig, p.envelope.signature)
            }
            if (parse is CertificateParse.Parsed) parsedCount++
        }
        assertEquals(3, parsedCount, "revokt accepted the indefinite form $parsedCount times in $tries signatures")
        if (Runtime.version().feature() == 11) {
            assertEquals(parsedCount, verifiedCount, "JDK 11 verifies every form revokt accepts here")
        } else {
            assertEquals(0, verifiedCount, "JDK 17 and later reject an indefinite signatureValue")
        }
    }

    private fun CertificateParse.describe(): String =
        when (this) {
            is CertificateParse.Parsed -> "Parsed"
            is CertificateParse.Failed -> "$reason: $detail"
        }
}
