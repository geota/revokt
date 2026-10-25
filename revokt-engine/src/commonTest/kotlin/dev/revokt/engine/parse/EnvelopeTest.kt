// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.ParseReason
import dev.revokt.RevoktLimits
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import dev.revokt.engine.parse.TestDer.tlvWithLength
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/** Spec §9.2 "The unsigned headers" (revision 34): the envelope reading, `Cert.tbs`, `Cert.sig` and §5.1's mismatch. */
class EnvelopeTest {
    private fun parsed(der: ByteArray): ParsedCertificate =
        when (val r = CertificateParser.parse(der)) {
            is CertificateParse.Parsed -> r.certificate
            is CertificateParse.Failed -> fail("expected Parsed, got ${r.reason}: ${r.detail}")
        }

    private fun failed(der: ByteArray): CertificateParse.Failed =
        assertIs<CertificateParse.Failed>(CertificateParser.parse(der))

    private fun headerLength(tlv: ByteArray): Int =
        if (tlv[1].toInt() and 0x80 ==
            0
        ) {
            2
        } else {
            2 + (tlv[1].toInt() and 0x7f)
        }

    private fun contentOf(tlv: ByteArray): ByteArray = tlv.copyOfRange(headerLength(tlv), tlv.size)

    /** [tlv] (written with a definite header) re-written with an indefinite length. */
    private fun indefinite(tlv: ByteArray): ByteArray =
        bytes(tlv[0].toInt() and 0xff, 0x80) + contentOf(tlv) + bytes(0, 0)

    /** A certificate whose TBS is [tbs] as given, with [cert]'s outer algorithm and signature. */
    private fun withTbs(
        cert: TestCert,
        tbs: ByteArray,
    ): ByteArray = seq(tbs, cert.outerAlgorithm, cert.signature)

    @Test
    fun `an indefinite TBS header and chain re-encode to the minimal TBS`() {
        val cert = TestCert()
        val base = parsed(cert.der)
        val p = parsed(withTbs(cert, indefinite(cert.tbs)))
        assertTrue(p.envelope.tbsIndefinite)
        assertContentEquals(cert.tbs, p.tbsBytes)
        assertContentEquals(base.rawSerial(), p.rawSerial())
        assertEquals(base.fields.ski, p.fields.ski)
        // The chain below it: an indefinite validity and an indefinite [3] down to an extnValue as 04 80 … 00 00.
        val ski = TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x04, bytes(1, 2, 3, 4)))
        val skiIndefinite =
            indefinite(
                seq(TestDer.oid(Oid.SUBJECT_KEY_IDENTIFIER), indefinite(tlv(0x04, tlv(0x04, bytes(1, 2, 3, 4))))),
            )
        val chained =
            TestCert(
                validity = indefinite(cert.validity),
                extensions = listOf(skiIndefinite),
                extensionsWrapper = { exts -> indefinite(tlv(0xa3, indefinite(seq(*exts.toTypedArray())))) },
            )
        val q = parsed(withTbs(cert, indefinite(chained.tbs)))
        assertContentEquals(TestCert(extensions = listOf(ski)).tbs, q.tbsBytes)
        assertContentEquals(bytes(1, 2, 3, 4), q.fields.ski!!.bytes(q.tbsBytes))
    }

    @Test
    fun `the converter reads one tag octet and rejects non-minimal and long lengths on the chain`() {
        val cert = TestCert()
        // After the extensions the rest of the TBS is ignored unparsed, so a multi-octet tag survives there.
        val trailing = TestCert(tbsTrailing = bytes(0x9f, 0x01, 0x02, 0x05, 0x00))
        val definite = parsed(trailing.der)
        val viaConverter = parsed(withTbs(cert, indefinite(trailing.tbs)))
        assertContentEquals(definite.tbsBytes, viaConverter.tbsBytes)
        assertEquals(listOf(IgnoredSite.TBS_AFTER_EXTENSIONS), viaConverter.ignoredElements.map { it.site })
        val serial81 = TestCert(serial = tlvWithLength(0x02, bytes(0x81, 0x04), bytes(0, 0x8f, 0x12, 0x34)))
        assertContains(failed(withTbs(cert, indefinite(serial81.tbs))).detail, "non-minimal length in indefinite TBS")
        val serial85 = TestCert(serial = tlvWithLength(0x02, bytes(0x85, 0, 0, 0, 0, 1), bytes(1)))
        assertContains(failed(withTbs(cert, indefinite(serial85.tbs))).detail, "length of 5 bytes in indefinite TBS")
        val open = bytes(0x30, 0x80) + contentOf(cert.tbs)
        assertContains(failed(seq(open)).detail, "unterminated indefinite TBS")
        // The same non-minimal serial under a definite TBS is accepted and recorded (the profile decides, K1).
        assertEquals(listOf(HeaderSite.SERIAL), parsed(serial81.der).nonMinimalHeaders.map { it.site })
    }

    @Test
    fun `a deep indefinite chain converts in linear time within the step budget`() {
        // 60 000 nested indefinite SEQUENCEs after the extensions, where the TBS read ignores them unparsed. Copying each
        // closed element into its parent would be quadratic here; the two-pass converter is linear (spec §9.2 D5).
        val depth = 60_000
        val chain = ByteArray(4 * depth) { i -> if (i < 2 * depth) (if (i % 2 == 0) 0x30 else 0x80).toByte() else 0 }
        val cert = TestCert()
        val der = withTbs(cert, indefinite(TestCert(tbsTrailing = chain).tbs))
        assertTrue(der.size <= RevoktLimits.MAX_CERT_BYTES)
        val p = parsed(der)
        assertEquals(listOf(IgnoredSite.TBS_AFTER_EXTENSIONS), p.ignoredElements.map { it.site })
        assertTrue(p.steps <= 8L * der.size + 1024, "steps ${p.steps} for ${der.size} bytes")
    }

    @Test
    fun `an indefinite element under a definite parent is a structure error`() {
        val cert = TestCert(validity = indefinite(TestCert().validity))
        assertEquals(ParseReason.STRUCTURE, failed(cert.der).reason)
    }

    @Test
    fun `an indefinite signatureValue is a structure error`() {
        // Spec §9.2 revision 38: JDK 17 and later reject it, even when its content reads as a chain of minimal TLVs.
        val content = bytes(0x00, 0x02, 0x01, 0x05) // u = 00 read as a tag, then length 02 and two octets
        val failure = failed(TestCert(signature = bytes(0x03, 0x80) + content + bytes(0, 0)).der)
        assertEquals(ParseReason.STRUCTURE, failure.reason)
        assertContains(failure.detail, "indefinite SIGNATURE_VALUE")
        assertContentEquals(
            bytes(0x02, 0x01, 0x05),
            parsed(TestCert(signature = tlv(0x03, content)).der).envelope.signature,
        )
    }

    @Test
    fun `every length bound fails as a structure error, never an exception`() {
        val cert = TestCert()
        val open = bytes(0x30, 0x80) + contentOf(cert.tbs)
        val cases =
            mapOf(
                "TBS length over every byte left" to
                    seq(bytes(0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0)),
                "signatureValue one byte longer than left" to
                    TestCert(signature = tlvWithLength(0x03, bytes(0x0a), bytes(0, 1, 2, 3, 4, 5, 6, 7, 8))).der,
                "signatureValue length octets cut off" to seq(cert.tbs, cert.outerAlgorithm, bytes(0x03, 0x82, 0x01)),
                "one byte after an open indefinite TBS" to seq(open + bytes(0x05)),
                "length octets cut off on the chain" to seq(open + bytes(0x02, 0x82, 0x01)),
            )
        for ((name, der) in cases) assertEquals(ParseReason.STRUCTURE, failed(der).reason, name)
    }

    @Test
    fun `end-of-contents needs both octets zero, and the step count covers both passes`() {
        val trailing = TestCert(tbsTrailing = bytes(0x00, 0x01, 0x05))
        val viaConverter = parsed(withTbs(trailing, indefinite(trailing.tbs)))
        assertContentEquals(parsed(trailing.der).tbsBytes, viaConverter.tbsBytes)
        // Two converter passes over the TBS content, then the TBS read on Cert.tbs: pinned as D5 measures it.
        val cert = TestCert()
        assertEquals(112, parsed(cert.der).steps)
        assertEquals(440, parsed(withTbs(cert, indefinite(cert.tbs))).steps)
    }

    @Test
    fun `minimal lengths switch form at 128, 256 and 65536 octets`() {
        val expected =
            mapOf(
                127 to bytes(0x7f),
                128 to bytes(0x81, 0x80),
                255 to bytes(0x81, 0xff),
                256 to bytes(0x82, 0x01, 0x00),
                65_535 to bytes(0x82, 0xff, 0xff),
                65_536 to bytes(0x83, 0x01, 0x00, 0x00),
            )
        for ((n, b) in expected) assertContentEquals(b, minimalLength(n), "$n")
    }

    @Test
    fun `the unsigned headers accept any definite length form and record the non-minimal ones`() {
        val cert = TestCert()
        val tbsContent = contentOf(cert.tbs)
        val long =
            tlvWithLength(0x30, bytes(0x85, 0, 0, 0, tbsContent.size shr 8, tbsContent.size and 0xff), tbsContent)
        val der = withTbs(cert, long)
        val p = parsed(der)
        assertContentEquals(cert.tbs, p.tbsBytes)
        assertEquals(listOf(HeaderSite.TBS), p.nonMinimalHeaders.map { it.site })
        assertEquals(
            headerLength(der),
            p.nonMinimalHeaders.single().offset,
            "an envelope site's offset indexes the input",
        )
        val sigContent = cert.signature.copyOfRange(2, cert.signature.size)
        val alg =
            parsed(
                TestCert(
                    outerAlgorithm = tlvWithLength(0x30, bytes(0x81, 0x0a), TestDer.oid("1.2.840.10045.4.3.2")),
                ).der,
            )
        assertEquals(listOf(HeaderSite.SIGNATURE_ALGORITHM), alg.nonMinimalHeaders.map { it.site }, "81 0a is recorded")
        val q = parsed(TestCert(signature = tlvWithLength(0x03, bytes(0x84, 0, 0, 0, sigContent.size), sigContent)).der)
        assertContentEquals(parsed(cert.der).envelope.signature, q.envelope.signature)
        assertEquals(listOf(HeaderSite.SIGNATURE_VALUE), q.nonMinimalHeaders.map { it.site })
        assertEquals(ParseReason.STRUCTURE, failed(TestCert(signature = bytes(0x03, 0xff)).der).reason)
    }

    @Test
    fun `Cert sig clears the padding bits and tolerates the forms the JDK rejects`() {
        fun sig(content: ByteArray) = parsed(TestCert(signature = tlv(0x03, content)).der).envelope.signature
        assertContentEquals(bytes(0x30, 0x06), sig(bytes(0x00, 0x30, 0x06)))
        assertContentEquals(bytes(0xfe), sig(bytes(0x01, 0xff)))
        assertContentEquals(bytes(0xab, 0x80), sig(bytes(0x07, 0xab, 0xff)))
        assertContentEquals(bytes(0x00), sig(bytes(0x09, 0xff)))
        assertContentEquals(ByteArray(0), sig(ByteArray(0)))
        assertContentEquals(ByteArray(0), sig(bytes(0x03)))
    }

    @Test
    fun `AlgorithmIdMismatch normalises NULL parameters and treats any other outer form as a mismatch`() {
        val ecdsa = TestDer.oid("1.2.840.10045.4.3.2")
        val rsa = TestDer.oid("1.2.840.113549.1.1.11")
        val nul = tlv(0x05)

        fun mismatch(
            tbsSignature: ByteArray,
            outer: ByteArray,
        ) = parsed(TestCert(tbsSignature = tbsSignature, outerAlgorithm = outer).der).envelope.algorithmIdMismatch
        assertEquals(false, mismatch(seq(ecdsa), seq(ecdsa)))
        assertEquals(false, mismatch(seq(ecdsa), seq(ecdsa, nul)), "NULL parameters added")
        assertEquals(false, mismatch(seq(rsa, nul), seq(rsa)), "NULL parameters removed")
        assertEquals(true, mismatch(seq(rsa, nul), seq(ecdsa, nul)), "another OID")
        assertEquals(true, mismatch(seq(ecdsa), seq(ecdsa, tlv(0x02, bytes(1)))), "other parameters")
        assertEquals(true, mismatch(seq(ecdsa), seq(ecdsa, nul, nul)), "two parameters")
        assertEquals(
            true,
            mismatch(seq(ecdsa), tlvWithLength(0x30, bytes(0x81, 0x0a), TestDer.oid("1.2.840.10045.4.3.2"))),
        )
        assertEquals(true, mismatch(seq(ecdsa), indefinite(seq(ecdsa))), "indefinite")
        assertEquals(
            true,
            mismatch(
                seq(ecdsa),
                seq(tlvWithLength(0x06, bytes(0x81, 0x08), TestDer.oidContent("1.2.840.10045.4.3.2"))),
            ),
        )
        assertEquals(true, mismatch(seq(rsa, nul), seq(rsa, tlvWithLength(0x05, bytes(0x81, 0x00), ByteArray(0)))))
        assertEquals(true, mismatch(seq(ecdsa), seq()), "empty")
        assertEquals(true, mismatch(seq(ecdsa), seq(tlv(0x04, bytes(1)))), "not an OID")
        // A non-minimal TBS signature cannot match: the comparison is between minimal DER forms only.
        assertEquals(
            true,
            mismatch(tlvWithLength(0x30, bytes(0x81, 0x0a), TestDer.oid("1.2.840.10045.4.3.2")), seq(ecdsa)),
        )
    }
}
