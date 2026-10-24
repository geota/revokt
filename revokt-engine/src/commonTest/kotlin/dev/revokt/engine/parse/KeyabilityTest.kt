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

/** Spec §9.2 K1–K7 (revision 35) on both sides of each edge; K8 checks each listed extension's grammar. */
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
    fun `the reference leaf is inside the profile, and so are the honest edge cases`() {
        assertClause(
            null,
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
                "UTF8String U+0800, the smallest three-octet character" to
                    keyable(subject = name(tlv(0x0c, bytes(0xe0, 0xa0, 0x80)))),
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
    fun `K5 accepts only Go's PrintableString set, valid UTF-8 and ASCII IA5String`() {
        assertClause(
            KeyabilityClause.NAME,
            mapOf(
                "TeletexString" to keyable(subject = name(tlv(0x14, ascii("t61")))),
                "BMPString" to keyable(subject = name(tlv(0x1e, bytes(0, 0x41)))),
                "PrintableString @" to keyable(subject = name(tlv(0x13, ascii("a@b")))),
                "PrintableString _" to keyable(subject = name(tlv(0x13, ascii("a_b")))),
                "UTF-8 overlong" to keyable(subject = name(tlv(0x0c, bytes(0xc0, 0x80)))),
                "UTF-8 surrogate" to keyable(subject = name(tlv(0x0c, bytes(0xed, 0xa0, 0x80)))),
                "UTF-8 above U+10FFFF" to keyable(subject = name(tlv(0x0c, bytes(0xf4, 0x90, 0x80, 0x80)))),
                "UTF-8 truncated" to keyable(subject = name(tlv(0x0c, bytes(0xe2, 0x82)))),
                "IA5String 80" to keyable(issuer = name(tlv(0x16, bytes(0x80)))),
            ),
        )
    }

    @Test
    fun `K6 accepts only the exact forms and real dates from 1950 to 9999`() {
        fun utc(s: String) = keyable(validity = seq(tlv(0x17, ascii(s)), tlv(0x17, ascii("491231235959Z"))))

        fun gen(s: String) = keyable(validity = seq(tlv(0x17, ascii("500101000000Z")), tlv(0x18, ascii(s))))
        assertClause(
            null,
            mapOf(
                "UTCTime 1950" to utc("500101000000Z"),
                "UTCTime 2049" to utc("491231235959Z"),
                "UTCTime 52 leap day" to utc("520229000000Z"),
                "2000 leap day" to gen("20000229000000Z"),
                "2024 leap day" to gen("20240229000000Z"),
                "GeneralizedTime 2050" to gen("20500101000000Z"),
                "GeneralizedTime 9999" to gen("99991231235959Z"),
            ),
        )
        assertClause(
            KeyabilityClause.TIME,
            mapOf(
                "no seconds" to utc("5001010000Z"),
                "offset" to utc("500101000000+0100"),
                "fraction" to gen("20500101000000.5Z"),
                "no zone" to gen("20500101000000"),
                "GeneralizedTime 1949" to gen("19491231235959Z"),
                "2023 leap day" to gen("20230229000000Z"),
                "2100 leap day" to gen("21000229000000Z"),
                "day 31 in April" to gen("20260431000000Z"),
                "month 13" to gen("20261301000000Z"),
                "hour 24" to gen("20260101240000Z"),
                "second 60" to gen("20260101235960Z"),
                "non-digit" to gen("2026010123595AZ"),
            ),
        )
    }

    @Test
    fun `K7 keys RSA, EC on the curve and Ed25519 in the profile's form only`() {
        val p256P = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
        assertClause(
            null,
            mapOf(
                "RSA e = 65537" to keyable(spki = rsaSpki()),
                "RSA e = 2^31 - 1" to keyable(spki = rsaSpki(e = bytes(0x7f, 0xff, 0xff, 0xff))),
                "RSA e = 3" to keyable(spki = rsaSpki(e = bytes(3))),
                "Ed25519" to keyable(spki = seq(seq(oid("1.3.101.112")), tlv(0x03, bytes(0), ByteArray(32)))),
            ),
        )
        assertClause(
            KeyabilityClause.KEY,
            mapOf(
                "RSA e = 2^31" to keyable(spki = rsaSpki(e = bytes(0x00, 0x80, 0x00, 0x00, 0x00))),
                "RSA e = 0" to keyable(spki = rsaSpki(e = bytes(0))),
                "RSA e negative" to keyable(spki = rsaSpki(e = bytes(0xff))),
                "RSA n negative" to keyable(spki = rsaSpki(n = bytes(0xc1, 0x23))),
                "RSA n zero" to keyable(spki = rsaSpki(n = bytes(0))),
                "RSA n not minimal" to keyable(spki = rsaSpki(n = bytes(0x00, 0x01))),
                "RSA without NULL" to keyable(spki = rsaSpki(parameters = ByteArray(0))),
                "RSA with bytes after the key" to keyable(spki = rsaSpki(trailing = bytes(0))),
                "EC generator, one bit flipped" to
                    keyable(
                        spki =
                            ecSpki(
                                point =
                                    bytes(0x04) + p256X +
                                        p256Y.copyOf().also { it[31] = (it[31].toInt() xor 1).toByte() },
                            ),
                    ),
                "EC x = p" to keyable(spki = ecSpki(point = bytes(0x04) + p256P + p256Y)),
                "EC compressed" to keyable(spki = ecSpki(point = bytes(0x02) + p256X)),
                "EC point one octet short" to keyable(spki = ecSpki(point = bytes(0x04) + p256X + p256Y.copyOf(31))),
                "EC on an unknown curve" to keyable(spki = ecSpki(curve = oid("1.3.132.0.10"))),
                "EC with implicit parameters" to keyable(spki = ecSpki(curve = tlv(0x05))),
                "Ed25519 with parameters" to
                    keyable(spki = seq(seq(oid("1.3.101.112"), tlv(0x05)), tlv(0x03, bytes(0), ByteArray(32)))),
                "Ed25519 31 octets" to keyable(spki = seq(seq(oid("1.3.101.112")), tlv(0x03, bytes(0), ByteArray(31)))),
                "DSA" to keyable(spki = seq(seq(oid("1.2.840.10040.4.1")), tlv(0x03, bytes(0), tlv(0x02, bytes(1))))),
                "unused bits on the key" to
                    keyable(
                        spki =
                            ecSpki(
                                point = bytes(0x04) + p256X + p256Y.copyOf().also { it[31] = 0xf0.toByte() },
                                unused = 4,
                            ),
                    ),
            ),
        )
    }

    @Test
    fun `the first failing clause is reported in K1 to K8 order`() {
        val many =
            keyable(
                serial = tlv(0x02, bytes(0, 5)),
                subject = name(tlv(0x14, ascii("x"))),
                spki = rsaSpki(e = bytes(0)),
            )
        assertEquals(KeyabilityClause.INTEGER, clause(many))
        assertEquals(
            KeyabilityClause.NAME,
            clause(keyable(subject = name(tlv(0x14, ascii("x"))), spki = rsaSpki(e = bytes(0)))),
        )
    }

    @Test
    fun `K1 walks the value of every extension on K8's list, matched on canonical OID content`() {
        val listed =
            listOf(
                "2.5.29.15",
                "2.5.29.19",
                "2.5.29.17",
                "2.5.29.31",
                "2.5.29.35",
                "2.5.29.37",
                "2.5.29.14",
                "2.5.29.32",
                "1.3.6.1.5.5.7.1.1",
                "2.5.29.30",
                "1.3.6.1.5.5.7.1.11",
            )
        assertClause(
            KeyabilityClause.HEADER,
            listed.associateWith { keyable(extensions = listOf(TestDer.extension(it, bytes(0x04, 0x81, 0x01, 0x00)))) },
        )
        // keyUsage spelled with a non-minimal arc is opaque to K1 and fails K4.
        val spelled = seq(tlv(0x06, bytes(0x55, 0x1d, 0x80, 0x0f)), tlv(0x04, bytes(0x04, 0x81, 0x01, 0x00)))
        assertEquals(KeyabilityClause.OID, clause(keyable(extensions = listOf(spelled))))
    }

    @Test
    fun `K2 checks the version, both unique ids, the issuer and the SPKI padding on their own`() {
        fun spki(bits: ByteArray) = seq(seq(oid("1.2.840.10045.2.1"), p256), bits)
        assertClause(
            KeyabilityClause.TBS_SHAPE,
            mapOf(
                "version 3 without [3]" to keyable(version = tlv(0xa0, tlv(0x02, bytes(3))), extensions = emptyList()),
                "version 00 02 without [3]" to
                    keyable(version = tlv(0xa0, tlv(0x02, bytes(0, 2))), extensions = emptyList()),
                "version FF without [3]" to
                    keyable(version = tlv(0xa0, tlv(0x02, bytes(0xff))), extensions = emptyList()),
                "primitive [2]" to keyable(uniqueIds = bytes(0x82, 0x00)),
                "constructed [2]" to keyable(uniqueIds = bytes(0xa2, 0x00)),
                "issuer RDN that is not a SET" to keyable(issuer = seq(seq(oid("2.5.4.3"), tlv(0x0c, ascii("a"))))),
                "SPKI BIT STRING empty" to keyable(spki = spki(tlv(0x03))),
                "SPKI unused bits 1 and no octet" to keyable(spki = spki(tlv(0x03, bytes(0x01)))),
                "SPKI unused bits 8" to keyable(spki = spki(tlv(0x03, bytes(0x08, 0x00)))),
                "SPKI algorithm without an OID" to keyable(spki = seq(seq(tlv(0x05)), tlv(0x03, bytes(0)))),
                "constructed SPKI BIT STRING" to
                    keyable(spki = seq(seq(oid("1.2.840.10045.2.1"), p256), tlv(0x23, tlv(0x03, bytes(0))))),
                "SPKI BIT STRING empty as the last TBS bytes of a v1 leaf" to
                    keyable(version = ByteArray(0), extensions = emptyList(), spki = spki(tlv(0x03))),
            ),
        )
        assertClause(
            KeyabilityClause.KEY,
            mapOf(
                "SPKI with no key octets" to keyable(spki = spki(tlv(0x03, bytes(0x00)))),
                // The SPKI's own shape and a non-EC key's parameters are K7's to judge, not K2's or K4's.
                "SPKI with a third element" to
                    keyable(
                        spki =
                            seq(
                                seq(oid("1.2.840.10045.2.1"), p256),
                                tlv(0x03, bytes(0, 0x04), p256X, p256Y),
                                tlv(0x05),
                            ),
                    ),
                "RSA parameters holding an OID" to
                    keyable(spki = rsaSpki(parameters = tlv(0x06, bytes(0x2a, 0x80, 0x01)))),
            ),
        )
        assertClause(
            KeyabilityClause.OID,
            mapOf(
                "issuer attribute type leading 80" to
                    keyable(issuer = seq(tlv(0x31, seq(tlv(0x06, bytes(0x55, 0x80, 0x04, 0x03)), tlv(0x0c))))),
                "SPKI algorithm leading 80" to
                    keyable(spki = seq(seq(tlv(0x06, bytes(0x2a, 0x80, 0x86, 0x48)), p256), tlv(0x03, bytes(0)))),
            ),
        )
    }

    @Test
    fun `K2 before K3 before K4`() {
        assertEquals(
            KeyabilityClause.TBS_SHAPE,
            clause(keyable(uniqueIds = tlv(0x81, bytes(0)), serial = tlv(0x02, bytes(0, 5)))),
        )
        assertEquals(
            KeyabilityClause.INTEGER,
            clause(keyable(serial = tlv(0x02, bytes(0, 5)), tbsSignature = seq(tlv(0x06)))),
        )
    }

    @Test
    fun `K1 stays linear with many K8-listed extensions`() {
        // 22 000 repeated keyUsage extensions near the size cap: one hash lookup per TLV, not a scan of the values.
        val keyUsage = TestDer.extension("2.5.29.15", tlv(0x05))
        val cert = keyable(extensions = List(22_000) { keyUsage })
        assertEquals(true, cert.der.size <= dev.revokt.RevoktLimits.MAX_CERT_BYTES)
        assertEquals(KeyabilityClause.EXTENSION, clause(cert))
    }

    @Test
    fun `K5 and K6 reject the edges a looser check would let through`() {
        fun gen(t: String) = keyable(validity = seq(tlv(0x17, ascii("500101000000Z")), tlv(0x18, ascii(t))))
        assertClause(
            KeyabilityClause.NAME,
            mapOf(
                "UTF-8 lead C1" to keyable(subject = name(tlv(0x0c, bytes(0xc1, 0xbf)))),
                "UTF-8 overlong E0 80 80" to keyable(subject = name(tlv(0x0c, bytes(0xe0, 0x80, 0x80)))),
                "UTF-8 overlong F0 80 80 80" to keyable(subject = name(tlv(0x0c, bytes(0xf0, 0x80, 0x80, 0x80)))),
                "UTF-8 third octet not a continuation" to keyable(subject = name(tlv(0x0c, bytes(0xe2, 0x82, 0x41)))),
            ),
        )
        assertClause(
            KeyabilityClause.TIME,
            mapOf(
                "no Z" to gen("205001010000000"),
                "slash before Z" to gen("2026010100000/Z"),
                "month 00" to gen("20260001000000Z"),
                "day 00" to gen("20260100000000Z"),
                "minute 60" to gen("20260101006000Z"),
                "31 June" to gen("20260631000000Z"),
                "31 September" to gen("20260931000000Z"),
            ),
        )
    }

    @Test
    fun `PrintableString accepts exactly Go's set with star and ampersand`() {
        val allowed = ('a'..'z') + ('A'..'Z') + ('0'..'9') + " '()+,-./:=?*&".toList()
        for (c in 0..255) {
            val value = tlv(0x13, bytes(c))
            val expected = if (c.toChar() in allowed && c < 0x80) KeyabilityClause.TIME else KeyabilityClause.NAME
            // A PrintableString passing K5 reaches K6, failed here on purpose to keep the case cheap.
            val cert =
                keyable(
                    subject = name(value),
                    validity = seq(tlv(0x17, ascii("5001010000Z")), tlv(0x17, ascii("5001010000Z"))),
                )
            assertEquals(expected, clause(cert), "octet $c")
        }
    }

    @Test
    fun `K7 rejects the key forms ct-go rejects or the profile narrows`() {
        val curveBytes = TestDer.oidContent("1.2.840.10045.3.1.7")
        val point = bytes(0x04) + p256X + p256Y
        assertClause(
            KeyabilityClause.KEY,
            mapOf(
                "Ed25519 with unused bits" to
                    keyable(spki = seq(seq(oid("1.3.101.112")), tlv(0x03, bytes(4), ByteArray(32)))),
                "Ed25519 33 octets" to keyable(spki = seq(seq(oid("1.3.101.112")), tlv(0x03, bytes(0), ByteArray(33)))),
                "EC curve bytes under an OCTET STRING tag" to keyable(spki = ecSpki(curve = tlv(0x04, curveBytes))),
                "EC point prefix 03" to keyable(spki = ecSpki(point = bytes(0x03) + point.copyOfRange(1, point.size))),
                "EC point prefix 06" to keyable(spki = ecSpki(point = bytes(0x06) + point.copyOfRange(1, point.size))),
                "RSA parameters an empty OCTET STRING" to keyable(spki = rsaSpki(parameters = tlv(0x04))),
                "RSA parameters NULL with content" to keyable(spki = rsaSpki(parameters = tlv(0x05, bytes(0)))),
                "RSA with a third INTEGER" to
                    keyable(
                        spki =
                            seq(
                                seq(oid("1.2.840.113549.1.1.1"), tlv(0x05)),
                                tlv(
                                    0x03,
                                    bytes(0),
                                    seq(
                                        tlv(0x02, bytes(0x00, 0xc1, 0x23)),
                                        tlv(0x02, bytes(1, 0, 1)),
                                        tlv(0x02, bytes(1)),
                                    ),
                                ),
                            ),
                    ),
                "RSAPublicKey header non-minimal" to
                    keyable(
                        spki =
                            seq(
                                seq(oid("1.2.840.113549.1.1.1"), tlv(0x05)),
                                tlv(
                                    0x03,
                                    bytes(0),
                                    tlvWithLength(
                                        0x30,
                                        bytes(0x81, 0x0a),
                                        tlv(0x02, bytes(0x00, 0xc1, 0x23)) + tlv(0x02, bytes(1, 0, 1)),
                                    ),
                                ),
                            ),
                    ),
            ),
        )
        // KEY comes before EXTENSION.
        assertEquals(
            KeyabilityClause.KEY,
            clause(keyable(spki = rsaSpki(e = bytes(0)), extensions = listOf(TestDer.extension("2.5.29.19", seq())))),
        )
    }

    @Test
    fun `K8 accepts each listed extension in its grammar`() {
        fun ext(
            oid: String,
            value: ByteArray,
        ) = keyable(extensions = listOf(TestDer.extension(oid, value)))
        val uri = tlv(0x86, ascii("http://crl.example/x.crl"))
        assertClause(
            null,
            mapOf(
                "keyUsage digitalSignature" to ext("2.5.29.15", tlv(0x03, bytes(0x07, 0x80))),
                "keyUsage nine bits" to ext("2.5.29.15", tlv(0x03, bytes(0x07, 0xff, 0x80))),
                "basicConstraints empty" to ext("2.5.29.19", seq()),
                "basicConstraints explicit FALSE" to ext("2.5.29.19", seq(tlv(0x01, bytes(0x00)))),
                "basicConstraints CA, pathLen 0" to ext("2.5.29.19", seq(tlv(0x01, bytes(0xff)), tlv(0x02, bytes(0)))),
                "basicConstraints pathLen 2^31 - 1" to ext("2.5.29.19", seq(tlv(0x02, bytes(0x7f, 0xff, 0xff, 0xff)))),
                "SAN dNSName, rfc822Name, IPv4, IPv6" to
                    ext(
                        "2.5.29.17",
                        seq(
                            tlv(0x82, ascii("a.example")),
                            tlv(0x81, ascii("a@b.example")),
                            tlv(0x87, bytes(1, 2, 3, 4)),
                            tlv(0x87, ByteArray(16)),
                        ),
                    ),
                "CRLDP one URI" to ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa0, uri))))),
                "CRLDP none" to ext("2.5.29.31", seq()),
                "AKI keyIdentifier" to ext("2.5.29.35", seq(tlv(0x80, bytes(1, 2)))),
                "EKU serverAuth" to ext("2.5.29.37", seq(oid("1.3.6.1.5.5.7.3.1"))),
                "SKI" to ext(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x04, bytes(1, 2))),
                "certificatePolicies with a qualifier" to
                    ext(
                        "2.5.29.32",
                        seq(seq(oid("2.23.140.1.2.1"), seq(seq(oid("1.3.6.1.5.5.7.2.1"), tlv(0x16, ascii("x")))))),
                    ),
                "certificatePolicies none" to ext("2.5.29.32", seq()),
                "AIA OCSP and caIssuers" to
                    ext(
                        "1.3.6.1.5.5.7.1.1",
                        seq(
                            seq(oid("1.3.6.1.5.5.7.48.1"), tlv(0x86, ascii("http://o.example"))),
                            seq(oid("1.3.6.1.5.5.7.48.2"), tlv(0x86, ascii("http://i.example"))),
                        ),
                    ),
            ),
        )
    }

    @Test
    fun `K8 rejects each listed extension outside its grammar`() {
        fun ext(
            oid: String,
            value: ByteArray,
        ) = keyable(extensions = listOf(TestDer.extension(oid, value)))
        val uri = tlv(0x86, ascii("http://crl.example/x.crl"))
        assertClause(
            KeyabilityClause.EXTENSION,
            mapOf(
                "keyUsage 03 00, which only zcrypto keys" to ext("2.5.29.15", tlv(0x03)),
                "keyUsage 03 01 05, which only zcrypto keys" to ext("2.5.29.15", tlv(0x03, bytes(0x01, 0x05))),
                "keyUsage padding bit set" to ext("2.5.29.15", tlv(0x03, bytes(0x07, 0x81))),
                "keyUsage with trailing bytes" to ext("2.5.29.15", tlv(0x03, bytes(0x07, 0x80)) + tlv(0x05)),
                "keyUsage not a BIT STRING" to ext("2.5.29.15", tlv(0x04, bytes(0x80))),
                "basicConstraints cA 01" to ext("2.5.29.19", seq(tlv(0x01, bytes(0x01)))),
                "basicConstraints negative pathLen" to ext("2.5.29.19", seq(tlv(0x02, bytes(0xff)))),
                "basicConstraints pathLen 2^31" to
                    ext(
                        "2.5.29.19",
                        seq(tlv(0x02, bytes(0x00, 0x80, 0x00, 0x00, 0x00))),
                    ),
                "basicConstraints pathLen not minimal" to ext("2.5.29.19", seq(tlv(0x02, bytes(0x00, 0x01)))),
                "basicConstraints pathLen before cA" to
                    ext("2.5.29.19", seq(tlv(0x02, bytes(1)), tlv(0x01, bytes(0xff)))),
                "basicConstraints trailing element" to ext("2.5.29.19", seq(tlv(0x05))),
                "SAN empty" to ext("2.5.29.17", seq()),
                "SAN URI" to ext("2.5.29.17", seq(tlv(0x86, ascii("http://a.example")))),
                "SAN directoryName" to ext("2.5.29.17", seq(tlv(0xa4, TestCert.name("x")))),
                "SAN dNSName not ASCII" to ext("2.5.29.17", seq(tlv(0x82, bytes(0xc3, 0xa9)))),
                "SAN IP of 5 octets" to ext("2.5.29.17", seq(tlv(0x87, bytes(1, 2, 3, 4, 5)))),
                "CRLDP reasons" to ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa0, uri)), tlv(0x81, bytes(0x07, 0x80))))),
                "CRLDP cRLIssuer only" to ext("2.5.29.31", seq(seq(tlv(0xa2, tlv(0x82, ascii("a")))))),
                "CRLDP relative name" to ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa1, tlv(0x31)))))),
                "CRLDP dNSName in fullName" to ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa0, tlv(0x82, ascii("a"))))))),
                "CRLDP empty fullName" to ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa0))))),
                "AKI empty" to ext("2.5.29.35", seq()),
                "AKI with issuer and serial" to
                    ext(
                        "2.5.29.35",
                        seq(tlv(0x80, bytes(1)), tlv(0xa1, tlv(0xa4, TestCert.name("x"))), tlv(0x82, bytes(1))),
                    ),
                "AKI constructed [0]" to ext("2.5.29.35", seq(tlv(0xa0, tlv(0x04, bytes(1))))),
                "EKU empty" to ext("2.5.29.37", seq()),
                "EKU holding a non-OID" to ext("2.5.29.37", seq(tlv(0x05))),
                "SKI constructed" to ext(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x24, tlv(0x04, bytes(1)))),
                "certificatePolicies entry without an OID" to ext("2.5.29.32", seq(seq(tlv(0x05)))),
                "AIA empty" to ext("1.3.6.1.5.5.7.1.1", seq()),
                "AIA dNSName location" to
                    ext("1.3.6.1.5.5.7.1.1", seq(seq(oid("1.3.6.1.5.5.7.48.1"), tlv(0x82, ascii("a"))))),
                "AIA trailing element" to
                    ext("1.3.6.1.5.5.7.1.1", seq(seq(oid("1.3.6.1.5.5.7.48.1"), tlv(0x86, ascii("a")), tlv(0x05)))),
                "nameConstraints" to ext("2.5.29.30", seq()),
                "subjectInfoAccess" to
                    ext("1.3.6.1.5.5.7.1.11", seq(seq(oid("1.3.6.1.5.5.7.48.5"), tlv(0x86, ascii("a"))))),
                "CRLDP name with a second element" to
                    ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa0, uri), tlv(0xa1, tlv(0x86, ascii("a"))))))),
                "CRLDP name as [1] holding a URI" to
                    ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa1, tlv(0x86, ascii("a"))))))),
                "CRLDP reasons in place of the name" to
                    ext("2.5.29.31", seq(seq(tlv(0x81, tlv(0xa0, tlv(0x86, ascii("a"))))))),
                "CRLDP point as a SET" to ext("2.5.29.31", seq(tlv(0x31, tlv(0xa0, tlv(0xa0, uri))))),
                "CRLDP URI not ASCII" to ext("2.5.29.31", seq(seq(tlv(0xa0, tlv(0xa0, tlv(0x86, bytes(0xc3, 0xa9))))))),
                "certificatePolicies entry as a SET" to ext("2.5.29.32", seq(tlv(0x31, oid("2.23.140.1.2.1")))),
                "certificatePolicies entry as [0]" to ext("2.5.29.32", seq(tlv(0xa0, oid("2.23.140.1.2.1")))),
                "certificatePolicies qualifier holding BOOLEAN 05" to
                    ext(
                        "2.5.29.32",
                        seq(seq(oid("2.23.140.1.2.1"), seq(seq(oid("1.3.6.1.5.5.7.2.1"), tlv(0x01, bytes(0x05)))))),
                    ),
                "AIA entry as a SET" to
                    ext("1.3.6.1.5.5.7.1.1", seq(tlv(0x31, oid("1.3.6.1.5.5.7.48.1"), tlv(0x86, ascii("a"))))),
                "AIA method not an OID" to
                    ext("1.3.6.1.5.5.7.1.1", seq(seq(tlv(0x04, bytes(0)), tlv(0x86, ascii("a"))))),
                "AIA URI not ASCII" to
                    ext("1.3.6.1.5.5.7.1.1", seq(seq(oid("1.3.6.1.5.5.7.48.1"), tlv(0x86, bytes(0xc3, 0xa9))))),
                "keyUsage as an OCTET STRING of bit-string content" to ext("2.5.29.15", tlv(0x04, bytes(0x00, 0x80))),
                "basicConstraints as a SET" to ext("2.5.29.19", tlv(0x31)),
                "SAN as a SET" to ext("2.5.29.17", tlv(0x31, tlv(0x82, ascii("a")))),
                "AKI as a SET" to ext("2.5.29.35", tlv(0x31, tlv(0x80, bytes(1)))),
                "EKU as a SET" to ext("2.5.29.37", tlv(0x31, oid("1.3.6.1.5.5.7.3.1"))),
                "certificatePolicies as a SET" to ext("2.5.29.32", tlv(0x31)),
                "CRLDP as a SET" to ext("2.5.29.31", tlv(0x31)),
                "AIA as a SET" to
                    ext("1.3.6.1.5.5.7.1.1", tlv(0x31, seq(oid("1.3.6.1.5.5.7.48.1"), tlv(0x86, ascii("a"))))),
                "basicConstraints cA of two octets" to ext("2.5.29.19", seq(tlv(0x01, bytes(0xff, 0xff)))),
                "critical 01 on an opaque extension" to
                    keyable(extensions = listOf(seq(oid("1.3.6.1.4.1.99999.1"), tlv(0x01, bytes(1)), tlv(0x04)))),
            ),
        )
    }

    @Test
    fun `K4 reads the OIDs inside K8's values and K1 walks them`() {
        fun ext(
            oid: String,
            value: ByteArray,
        ) = keyable(extensions = listOf(TestDer.extension(oid, value)))
        val leading80 = tlv(0x06, bytes(0x2b, 0x80, 0x06))
        assertClause(
            KeyabilityClause.OID,
            mapOf(
                "EKU purpose" to ext("2.5.29.37", seq(leading80)),
                "policy identifier" to ext("2.5.29.32", seq(seq(leading80))),
                "access method" to ext("1.3.6.1.5.5.7.1.1", seq(seq(leading80, tlv(0x86, ascii("a"))))),
            ),
        )
        val deepQualifier =
            seq(
                seq(
                    oid("2.23.140.1.2.1"),
                    seq(seq(oid("1.3.6.1.5.5.7.2.1"), tlvWithLength(0x16, bytes(0x81, 0x01), ascii("x")))),
                ),
            )
        assertEquals(
            KeyabilityClause.HEADER,
            clause(ext("2.5.29.32", deepQualifier)),
            "a policy qualifier's header is walked by K1",
        )
    }
}
