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
    private enum class Expected {
        /** Parsed with the base certificate's fields; the JDK verifies it (asserted on JDK 17 and later, Appendix A). */
        SAME_AS_BASE,

        /** `STRUCTURE`; the JDK rejects it or fails to verify it. */
        STRUCTURE,

        /** Parsed (a form the JDK rejects, harmless for D1); the JDK does not verify it. */
        PARSED_JDK_REJECTS,
    }

    private class Variant(
        val name: String,
        val expected: Expected,
        val algorithmIdMismatch: Boolean = false,
        val build: (DerNode) -> ByteArray,
    )

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

    private fun DerNode.tbs() = child(0)

    private fun DerNode.alg() = child(1)

    private fun DerNode.sig() = child(2)

    private val ind = LengthForm.Indefinite

    private fun variants(rsa: Boolean): List<Variant> =
        tbsVariants() + algorithmVariants() + signatureVariants() + if (rsa) rsaVariants() else emptyList()

    private fun tbsVariants(): List<Variant> =
        listOf(
            Variant("tbs-long-leading-zero", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = LengthForm.Long(3)
                c.encode()
            },
            Variant("tbs-indefinite", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                c.encode()
            },
            Variant("tbs-indefinite-version", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                c.tbs().child(0).form = ind
                c.encode()
            },
            Variant("tbs-indefinite-validity", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                c.tbs().child(4).form = ind
                c.encode()
            },
            Variant("tbs-indefinite-subject-chain", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                val subject = c.tbs().child(5)
                subject.form = ind
                for (rdn in subject.children!!) {
                    rdn.form = ind
                    rdn.children!!.forEach { it.form = ind }
                }
                c.encode()
            },
            Variant("tbs-indefinite-extension-chain", Expected.SAME_AS_BASE) { c ->
                c.tbs().form = ind
                val wrapper = c.tbs().child(7)
                wrapper.form = ind
                wrapper.child(0).form = ind
                val extension = wrapper.child(0, 0)
                extension.form = ind
                extension.children!!.last().form = ind // extnValue as 04 80 … 00 00
                c.encode()
            },
        ) + tbsRejectVariants()

    private fun algorithmVariants(): List<Variant> =
        listOf(
            Variant("alg-long", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().form = LengthForm.Long(1)
                c.encode()
            },
            Variant("alg-indefinite", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().form = ind
                c.encode()
            },
            Variant("alg-oid-header-81", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().child(0).form = LengthForm.Long(1)
                c.encode()
            },
            Variant("alg-null-flipped", Expected.SAME_AS_BASE) { c ->
                val params = c.alg().children!!
                if (params.size == 2) params.removeAt(1) else params.add(DerNode(0x05, ByteArray(0), null))
                c.encode()
            },
            Variant("alg-indefinite-oid-header-81", Expected.STRUCTURE) { c ->
                c.alg().form = ind
                c.alg().child(0).form = LengthForm.Long(1)
                c.encode()
            },
        )

    private fun signatureVariants(): List<Variant> =
        listOf(
            Variant("sig-long-4", Expected.SAME_AS_BASE) { c ->
                c.sig().form = LengthForm.Long(4)
                c.encode()
            },
            Variant("sig-indefinite", Expected.STRUCTURE) { c ->
                c.sig().form = ind
                c.encode()
            },
            Variant("sig-length-85", Expected.PARSED_JDK_REJECTS) { c ->
                c.sig().form = LengthForm.Long(5)
                c.encode()
            },
        )

    private fun tbsRejectVariants(): List<Variant> =
        listOf(
            Variant("tbs-indefinite-serial-81", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                c.tbs().child(1).form = LengthForm.Long(1)
                c.encode()
            },
            Variant("tbs-indefinite-serial-84", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                c.tbs().child(1).form = LengthForm.Long(4)
                c.encode()
            },
            Variant("tbs-indefinite-spki-83", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                c.tbs().child(6).form = LengthForm.Long(3)
                c.encode()
            },
            Variant("tbs-indefinite-double-eoc", Expected.STRUCTURE) { c ->
                c.tbs().form = ind
                TestDer.seq(c.tbs().encode(), TestDer.bytes(0, 0), c.alg().encode(), c.sig().encode())
            },
            Variant("tbs-definite-validity-indefinite", Expected.STRUCTURE) { c ->
                c.tbs().child(4).form = ind
                c.encode()
            },
            Variant("tbs-length-85", Expected.PARSED_JDK_REJECTS) { c ->
                c.tbs().form = LengthForm.Long(5)
                c.encode()
            },
            // A definite subject holding an indefinite RDN under an indefinite TBS: the converter skips the subject
            // whole, so the JDK verifies over bytes the CA did not sign; revokt does not descend into names.
            Variant("tbs-indefinite-definite-subject-indefinite-rdn", Expected.PARSED_JDK_REJECTS) { c ->
                c.tbs().form = ind
                c.tbs().child(5, 0).form = ind
                c.encode()
            },
        )

    private fun rsaVariants(): List<Variant> =
        listOf(
            Variant("alg-indefinite-null-indefinite", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().form = ind
                c.alg().child(1).form = ind
                c.encode()
            },
            Variant("alg-null-81", Expected.SAME_AS_BASE, algorithmIdMismatch = true) { c ->
                c.alg().child(1).form = LengthForm.Long(1)
                c.encode()
            },
            Variant("sig-unused-bits-1-padding-set", Expected.SAME_AS_BASE) { c ->
                val bits = c.sig().content
                check(bits[bits.lastIndex].toInt() and 1 == 0) { "the fixture's last signature bit must be 0" }
                bits[0] = 1
                bits[bits.lastIndex] = (bits[bits.lastIndex].toInt() or 1).toByte()
                c.encode()
            },
        )

    @Test
    fun `envelope forms parse to the JDK's verified message and the base certificate's fields`() {
        var verifiedCount = 0
        for (chain in chains) {
            val base = (CertificateParser.parse(chain.leaf) as CertificateParse.Parsed).certificate
            assertEquals(false, base.envelope.algorithmIdMismatch, "${chain.name} base")
            for (v in variants(chain.rsa)) if (check(chain, base, v)) verifiedCount++
        }
        assertTrue(verifiedCount >= if (modern) 30 else 8, "only $verifiedCount variants verified")
    }

    private val modern = Runtime.version().feature() >= 17

    /** Checks one variant of [chain]'s leaf; returns whether the JDK verified it. */
    private fun check(
        chain: Chain,
        base: ParsedCertificate,
        v: Variant,
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
            Expected.SAME_AS_BASE -> {
                if (modern) assertTrue(verified, "$label: the JDK verifies it")
                val p = (parse as? CertificateParse.Parsed)?.certificate ?: fail("$label: ${parse.describe()}")
                assertSameAsBase(label, base, p, v.algorithmIdMismatch)
                assertTrue(p.steps <= 8L * der.size + 1024, "$label steps")
            }

            Expected.STRUCTURE -> {
                assertTrue(!verified, "$label: the JDK must not verify it")
                assertEquals(ParseReason.STRUCTURE, (parse as? CertificateParse.Failed)?.reason, label)
            }

            Expected.PARSED_JDK_REJECTS -> {
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

    private fun CertificateParse.describe(): String =
        when (this) {
            is CertificateParse.Parsed -> "Parsed"
            is CertificateParse.Failed -> "$reason: $detail"
        }
}
