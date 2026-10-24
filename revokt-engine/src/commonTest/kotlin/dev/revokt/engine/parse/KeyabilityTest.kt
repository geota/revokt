// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.KeyabilityClause
import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.oid
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import dev.revokt.engine.parse.TestDer.tlvWithLength
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

/** Spec §9.2 K1–K4 (revision 34) on both sides of each edge. Until #25 no certificate passes K5, so "inside" is NAME. */
class KeyabilityTest {
    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

    private val p256X = hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
    private val p256Y = hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    private val p256 = oid("1.2.840.10045.3.1.7")

    private fun ecSpki(
        point: ByteArray = bytes(0x04) + p256X + p256Y,
        curve: ByteArray = p256,
        unused: Int = 0,
    ) = seq(seq(oid("1.2.840.10045.2.1"), curve), tlv(0x03, bytes(unused), point))

    private fun rsaSpki(
        n: ByteArray = bytes(0x00, 0xc1, 0x23),
        e: ByteArray = bytes(0x01, 0x00, 0x01),
        parameters: ByteArray = tlv(0x05),
        trailing: ByteArray = ByteArray(0),
    ) = seq(
        seq(oid("1.2.840.113549.1.1.1"), parameters),
        tlv(0x03, bytes(0), seq(tlv(0x02, n), tlv(0x02, e)), trailing),
    )

    private val unknownExtension = TestDer.extension("1.3.6.1.4.1.99999.1", tlv(0x04, bytes(1, 2)))

    /** Inside the profile: a P-256 key (the generator), an opaque extension and nothing K8 lists. */
    private fun keyable(
        version: ByteArray = TestDer.tlv(0xa0, TestDer.tlv(0x02, TestDer.bytes(2))),
        serial: ByteArray = tlv(0x02, bytes(0x00, 0x8f, 0x12, 0x34)),
        issuer: ByteArray = TestCert.name("Test CA"),
        subject: ByteArray = TestCert.name("leaf.example"),
        validity: ByteArray = seq(tlv(0x17, ascii("261022134530Z")), tlv(0x18, ascii("20500101000000Z"))),
        spki: ByteArray = ecSpki(),
        uniqueIds: ByteArray = ByteArray(0),
        extensions: List<ByteArray> = listOf(unknownExtension),
        extensionsWrapper: ((List<ByteArray>) -> ByteArray)? = null,
        tbsTrailing: ByteArray = ByteArray(0),
        tbsSignature: ByteArray = seq(oid("1.2.840.10045.4.3.2")),
    ) = TestCert(
        version = version,
        serial = serial,
        tbsSignature = tbsSignature,
        issuer = issuer,
        validity = validity,
        subject = subject,
        spki = spki,
        uniqueIds = uniqueIds,
        extensions = extensions,
        extensionsWrapper = extensionsWrapper ?: TestCert().extensionsWrapper,
        tbsTrailing = tbsTrailing,
    )

    private fun clause(cert: TestCert): KeyabilityClause? =
        when (val r = CertificateParser.parse(cert.der)) {
            is CertificateParse.Parsed -> Keyability.firstFailing(r.certificate)
            is CertificateParse.Failed -> fail("expected Parsed, got ${r.reason}: ${r.detail}")
        }

    private fun name(value: ByteArray) = seq(tlv(0x31, seq(oid("2.5.4.3"), value)))

    private fun assertClause(
        expected: KeyabilityClause?,
        cases: Map<String, TestCert>,
    ) {
        for ((label, cert) in cases) assertEquals(expected, clause(cert), label)
    }

    @Test
    fun `the reference leaf and the honest edge cases pass K1 to K4`() {
        assertClause(
            KeyabilityClause.NAME,
            mapOf(
                "reference" to keyable(),
                "v1 without extensions" to keyable(version = ByteArray(0), extensions = emptyList()),
                "explicit v1" to keyable(version = tlv(0xa0, tlv(0x02, bytes(0))), extensions = emptyList()),
                "negative serial" to keyable(serial = tlv(0x02, bytes(0xff, 0x01))),
                "zero serial" to keyable(serial = tlv(0x02, bytes(0))),
                "21-octet serial" to keyable(serial = tlv(0x02, ByteArray(21) { (it + 1).toByte() })),
                "explicit FALSE critical" to
                    keyable(extensions = listOf(TestDer.extension("1.3.6.1.4.1.99999.2", ByteArray(0), false))),
                "critical FF" to
                    keyable(extensions = listOf(TestDer.extension("1.3.6.1.4.1.99999.2", ByteArray(0), true))),
                "non-minimal inside an opaque value" to
                    keyable(
                        extensions = listOf(TestDer.extension("1.3.6.1.4.1.99999.3", bytes(0x04, 0x81, 0x01, 0x00))),
                    ),
                "OID arc 2^31 - 1" to
                    keyable(extensions = listOf(TestDer.extension("1.3.6.1.4.1.2147483647", ByteArray(0)))),
                "first subidentifier at the limit" to
                    keyable(extensions = listOf(TestDer.extension("2.2147483567", ByteArray(0)))),
                "* and & in a PrintableString" to keyable(subject = name(tlv(0x13, ascii("*.a&b.example")))),
                "UTF8String" to keyable(subject = name(tlv(0x0c, "é€😀".encodeToByteArray()))),
                "IA5String" to keyable(subject = name(tlv(0x16, ascii("a@b.example")))),
                "empty subject" to keyable(subject = seq()),
            ),
        )
    }

    @Test
    fun `K1 rejects a non-minimal or multi-octet header outside the opaque values`() {
        assertClause(
            KeyabilityClause.HEADER,
            mapOf(
                "non-minimal subject" to keyable(subject = tlvWithLength(0x30, bytes(0x81, 0x00), ByteArray(0))),
                "non-minimal attribute value" to
                    keyable(
                        subject =
                            seq(
                                tlv(0x31, seq(oid("2.5.4.3"), tlvWithLength(0x0c, bytes(0x81, 0x01), ascii("a")))),
                            ),
                    ),
                "non-minimal serial" to keyable(serial = tlvWithLength(0x02, bytes(0x81, 0x01), bytes(1))),
                "multi-octet tag in a name" to
                    keyable(subject = seq(tlv(0x31, seq(oid("2.5.4.3"), bytes(0x1f, 0x0c, 0x00))))),
                "non-minimal inside a K8-listed value" to
                    keyable(
                        extensions =
                            listOf(
                                TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, bytes(0x04, 0x81, 0x01, 0x00)),
                            ),
                    ),
                "junk after [3]" to keyable(tbsTrailing = bytes(0xff, 0xff)),
            ),
        )
    }

    @Test
    fun `K2 rejects the shapes outside the profile`() {
        val nul = tlv(0x05)
        assertClause(
            KeyabilityClause.TBS_SHAPE,
            mapOf(
                "[3] without [0]" to keyable(version = ByteArray(0)),
                "[3] with version 1" to keyable(version = tlv(0xa0, tlv(0x02, bytes(0)))),
                "version 3" to keyable(version = tlv(0xa0, tlv(0x02, bytes(3)))),
                "version in two octets" to keyable(version = tlv(0xa0, tlv(0x02, bytes(0, 2)))),
                "unique ids" to keyable(uniqueIds = tlv(0x81, bytes(0))),
                "constructed [1] then [3]" to keyable(uniqueIds = bytes(0xa1, 0)),
                "empty Extensions" to keyable(extensions = emptyList(), extensionsWrapper = { tlv(0xa3, seq()) }),
                "NULL after [3]" to keyable(tbsTrailing = nul),
                "NULL after extnValue" to keyable(extensions = listOf(seq(oid("1.3.6.1.4.1.99999.1"), tlv(0x04), nul))),
                "zero-length primitive [3]" to keyable(extensions = emptyList(), tbsTrailing = bytes(0x83, 0x00)),
                "two algorithm parameters" to keyable(tbsSignature = seq(oid("1.2.840.10045.4.3.2"), nul, nul)),
                "algorithm without an OID" to keyable(tbsSignature = seq(nul)),
                "RDN that is not a SET" to keyable(subject = seq(seq(oid("2.5.4.3"), tlv(0x0c, ascii("a"))))),
                "attribute with three elements" to
                    keyable(subject = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c), tlv(0x0c))))),
                "SPKI BIT STRING with a set padding bit" to
                    keyable(
                        spki = ecSpki(point = bytes(0x04) + p256X + p256Y.copyOf().also { it[31] = 0x01 }, unused = 1),
                    ),
                "SPKI BIT STRING with 8 unused bits" to keyable(spki = ecSpki(unused = 8)),
            ),
        )
    }

    @Test
    fun `K3 rejects a serial that is empty or not minimal`() {
        assertClause(
            KeyabilityClause.INTEGER,
            mapOf(
                "empty" to keyable(serial = tlv(0x02)),
                "redundant 00" to keyable(serial = tlv(0x02, bytes(0x00, 0x05))),
                "redundant FF" to keyable(serial = tlv(0x02, bytes(0xff, 0x80))),
            ),
        )
    }

    @Test
    fun `K4 rejects an OID that is empty, not minimal, too large or unterminated`() {
        fun ext(content: ByteArray) = keyable(extensions = listOf(seq(tlv(0x06, content), tlv(0x04))))
        assertClause(
            KeyabilityClause.OID,
            mapOf(
                "extension arc 2^31" to
                    keyable(extensions = listOf(TestDer.extension("1.3.6.1.4.1.2147483648", ByteArray(0)))),
                "first subidentifier 2^31" to
                    keyable(extensions = listOf(TestDer.extension("2.2147483568", ByteArray(0)))),
                "extension leading 80" to ext(bytes(0x2b, 0x80, 0x06)),
                "extension unterminated" to ext(bytes(0x2b, 0x86)),
                "empty extension OID" to ext(ByteArray(0)),
                "attribute type leading 80" to
                    keyable(subject = seq(tlv(0x31, seq(tlv(0x06, bytes(0x55, 0x80, 0x04, 0x03)), tlv(0x0c))))),
                "signature algorithm leading 80" to
                    keyable(tbsSignature = seq(tlv(0x06, bytes(0x2a, 0x80, 0x86, 0x48)))),
                "curve leading 80" to keyable(spki = ecSpki(curve = tlv(0x06, bytes(0x2a, 0x80, 0x86, 0x48)))),
            ),
        )
    }

    @Test
    fun `the first failing clause is reported in clause order`() {
        val many =
            keyable(
                serial = tlv(0x02, bytes(0, 5)),
                subject = name(tlv(0x14, ascii("x"))),
                spki = rsaSpki(e = bytes(0)),
            )
        assertEquals(KeyabilityClause.INTEGER, clause(many))
        assertEquals(
            KeyabilityClause.OID,
            clause(keyable(tbsSignature = seq(tlv(0x06)), subject = name(tlv(0x14, ascii("x"))))),
        )
    }
}
