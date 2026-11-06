// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.oid
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail

/** The x5u extension readers (spec §7.1, §4 `PresentedChain.dnsNames`) on the DER edges of each grammar. */
class ExtensionValuesTest {
    private val boolTrue = tlv(0x01, bytes(0xff))
    private val boolFalse = tlv(0x01, bytes(0x00))
    private val codeSigning = "1.3.6.1.5.5.7.3.3"
    private val basicConstraintsReader = { b: ByteArray, v: Span -> ExtensionValues.basicConstraints(b, v) }
    private val keyUsageReader = { b: ByteArray, v: Span -> ExtensionValues.keyUsage(b, v) }
    private val extendedKeyUsageReader = { b: ByteArray, v: Span -> ExtensionValues.extendedKeyUsage(b, v) }
    private val subjectAltNameReader = { b: ByteArray, v: Span -> ExtensionValues.subjectAltName(b, v) }

    private fun <T> value(
        value: ByteArray,
        reader: (ByteArray, Span) -> ExtensionRead<T>,
    ): T =
        when (val r = reader(value, Span(0, value.size))) {
            is ExtensionRead.Value -> r.value
            is ExtensionRead.Failed -> fail("${r.reason}: ${r.detail}")
            ExtensionRead.Absent -> fail("absent")
        }

    private fun <T> malformed(
        value: ByteArray,
        reader: (ByteArray, Span) -> ExtensionRead<T>,
    ) {
        val r = reader(value, Span(0, value.size))
        assertIs<ExtensionRead.Failed>(r, value.joinToString(" ") { (it.toInt() and 0xff).toString(16) })
        assertEquals(ExtensionFailure.MALFORMED, r.reason)
    }

    private fun bc(value: ByteArray) = value(value, basicConstraintsReader)

    private fun ku(vararg content: Int) = value(tlv(0x03, bytes(*content)), keyUsageReader)

    private fun cert(vararg extensions: ByteArray): ParsedCertificate =
        (CertificateParser.parse(TestCert(extensions = extensions.toList()).der) as CertificateParse.Parsed).certificate

    @Test
    fun `basicConstraints reads cA and pathLen, the BOOLEAN default omitted or encoded`() {
        assertEquals(false to null, bc(seq()).let { it.ca to it.pathLen })
        assertEquals(true to null, bc(seq(boolTrue)).let { it.ca to it.pathLen })
        // DER omits a DEFAULT value; cA FALSE explicitly encoded is accepted, as K8 and the JDK accept it.
        assertEquals(false to null, bc(seq(boolFalse)).let { it.ca to it.pathLen })
        assertEquals(true to 0, bc(seq(boolTrue, tlv(0x02, bytes(0)))).let { it.ca to it.pathLen })
        assertEquals(true to 0x7f, bc(seq(boolTrue, tlv(0x02, bytes(0x7f)))).let { it.ca to it.pathLen })
        assertEquals(true to 0x80, bc(seq(boolTrue, tlv(0x02, bytes(0x00, 0x80)))).let { it.ca to it.pathLen })
        assertEquals(Int.MAX_VALUE, bc(seq(boolTrue, tlv(0x02, bytes(0x7f, 0xff, 0xff, 0xff)))).pathLen)
        assertEquals(0x01020304, bc(seq(boolTrue, tlv(0x02, bytes(0x01, 0x02, 0x03, 0x04)))).pathLen)
        // pathLen without cA is read as encoded; whether it counts is the chain check's.
        assertEquals(false to 3, bc(seq(tlv(0x02, bytes(3)))).let { it.ca to it.pathLen })
    }

    @Test
    fun `basicConstraints rejects every value outside K8's grammar`() {
        val reader = basicConstraintsReader
        malformed(seq(tlv(0x01, bytes(0x01))), reader)
        malformed(seq(tlv(0x01, bytes(0xff, 0xff))), reader)
        malformed(seq(tlv(0x01, ByteArray(0))), reader)
        malformed(seq(boolTrue, tlv(0x02, ByteArray(0))), reader)
        malformed(seq(boolTrue, tlv(0x02, bytes(0x00, 0x01))), reader)
        malformed(seq(boolTrue, tlv(0x02, bytes(0xff, 0x80))), reader)
        malformed(seq(boolTrue, tlv(0x02, bytes(0x80))), reader)
        malformed(seq(boolTrue, tlv(0x02, bytes(0x00, 0x80, 0x00, 0x00, 0x00))), reader)
        malformed(seq(boolTrue, tlv(0x02, bytes(1)), tlv(0x05)), reader)
        malformed(seq(tlv(0x02, bytes(1)), boolTrue), reader)
        malformed(seq(boolTrue, boolTrue), reader)
        malformed(seq() + bytes(0x05, 0x00), reader)
        malformed(tlv(0x31), reader)
        malformed(ByteArray(0), reader)
        malformed(bytes(0x30, 0x05), reader)
    }

    @Test
    fun `keyUsage reads the significant bits under each unused-bits count`() {
        assertEquals(listOf(true), ku(0x07, 0x80).bits.toList())
        assertEquals(false, ku(0x07, 0x80).keyCertSign)
        // keyCertSign and cRLSign, 7 bits.
        assertEquals(listOf(false, false, false, false, false, true, true), ku(0x01, 0x06).bits.toList())
        assertEquals(true, ku(0x01, 0x06).keyCertSign)
        // keyCertSign is the last significant bit.
        assertEquals(true, ku(0x02, 0x04).keyCertSign)
        assertEquals(6, ku(0x02, 0x04).bits.size)
        // A string too short to hold bit 5 does not set it.
        assertEquals(false, ku(0x03, 0xf8).keyCertSign)
        assertEquals(false, ku(0x03, 0xf8)[5])
        assertEquals(true, ku(0x03, 0xf8)[4])
        assertEquals(0, ku(0x00).bits.size)
        assertEquals(false, ku(0x00).keyCertSign)
        // decipherOnly, bit 8, in a second octet.
        val nine = ku(0x07, 0x00, 0x80)
        assertEquals(9, nine.bits.size)
        assertEquals(true, nine[8])
        assertEquals(false, nine[9])
        assertEquals(16, ku(0x00, 0xff, 0xff).bits.count { it })
    }

    @Test
    fun `keyUsage rejects bad padding, a constructed or trailing element and a missing octet`() {
        val reader = keyUsageReader
        malformed(tlv(0x03, bytes(0x03, 0x04)), reader)
        malformed(tlv(0x03, bytes(0x01, 0x01)), reader)
        malformed(tlv(0x03, bytes(0x08, 0x00)), reader)
        malformed(tlv(0x03, bytes(0x01)), reader)
        malformed(tlv(0x03, ByteArray(0)), reader)
        malformed(tlv(0x23, tlv(0x03, bytes(0x00, 0x04))), reader)
        malformed(tlv(0x03, bytes(0x00, 0x04)) + bytes(0x05, 0x00), reader)
        malformed(seq(tlv(0x03, bytes(0x00, 0x04))), reader)
    }

    @Test
    fun `extKeyUsage reads each purpose and matches canonical content only`() {
        val eku = value(seq(oid(codeSigning), oid("1.3.6.1.5.5.7.3.1")), extendedKeyUsageReader)
        assertEquals(2, eku.purposes.size)
        assertTrue(eku.contains(TestDer.oidContent(codeSigning)))
        assertEquals(false, eku.contains(TestDer.oidContent("1.3.6.1.5.5.7.3.2")))
        assertEquals(false, eku.contains(TestDer.oidContent("1.3.6.1.5.5.7.3")))
        // A non-minimal arc spelling of codeSigning is read, never matched.
        val spelled =
            value(seq(tlv(0x06, bytes(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x80, 0x03))), extendedKeyUsageReader)
        assertEquals(false, spelled.contains(TestDer.oidContent(codeSigning)))
        val reader = extendedKeyUsageReader
        malformed(seq(), reader)
        malformed(seq(oid(codeSigning), tlv(0x02, bytes(1))), reader)
        malformed(oid(codeSigning), reader)
        malformed(seq(oid(codeSigning)) + bytes(0), reader)
        // Empty and truncated OID content: strict rejects it; K8 (strict = false) leaves it to K4.
        for (bad in listOf(tlv(0x06), tlv(0x06, bytes(0x2b, 0x86)))) {
            malformed(seq(oid(codeSigning), bad), reader)
            val lenient = ExtensionValues.extendedKeyUsage(seq(bad), Span(0, seq(bad).size), strict = false)
            assertIs<ExtensionRead.Value<ExtendedKeyUsage>>(lenient)
        }
    }

    @Test
    fun `subjectAltName reads every GeneralName form and lists the dNSNames in order`() {
        val one = value(seq(tlv(0x82, ascii("onecrl.content-signature.mozilla.org"))), subjectAltNameReader)
        assertEquals(listOf("onecrl.content-signature.mozilla.org"), one.dnsNames)
        val mixed =
            value(
                seq(
                    tlv(0x86, ascii("https://example.com/")),
                    tlv(0x82, ascii("a.example")),
                    tlv(0x87, bytes(192, 0, 2, 1)),
                    tlv(0xa4, TestCert.name("dir")),
                    tlv(0xa0, oid("1.2.3"), tlv(0xa0, tlv(0x0c, ascii("x")))),
                    tlv(0x82, ascii("b.example")),
                    tlv(0x88, TestDer.oidContent("1.2.3")),
                ),
                subjectAltNameReader,
            )
        assertEquals(listOf("a.example", "b.example"), mixed.dnsNames)
        assertEquals(listOf(0x86, 0x82, 0x87, 0xa4, 0xa0, 0x82, 0x88), mixed.names.map { it.tag })
        assertContentEquals(bytes(192, 0, 2, 1), mixed.names[2].content.toByteArray())
        assertEquals(listOf(""), value(seq(tlv(0x82)), subjectAltNameReader).dnsNames)
    }

    @Test
    fun `subjectAltName rejects an empty SAN, a tag outside GeneralName and a non-ASCII dNSName`() {
        val reader = subjectAltNameReader
        malformed(seq(), reader)
        malformed(seq(tlv(0x82, bytes(0x61, 0xc3, 0xa9))), reader)
        malformed(seq(tlv(0x82, ascii("a.example")), tlv(0x89, ascii("x"))), reader)
        malformed(seq(tlv(0x0c, ascii("a.example"))), reader)
        malformed(seq(tlv(0x42, ascii("a.example"))), reader)
        malformed(seq(tlv(0xc2, ascii("a.example"))), reader)
        malformed(seq(tlv(0x82, ascii("a.example"))) + bytes(0), reader)
        malformed(tlv(0x82, ascii("a.example")), reader)
        malformed(seq(bytes(0x82, 0x05, 0x61)), reader)
        // Each identifier in its one form: a constructed dNSName beside a valid one, a primitive otherName or
        // directoryName, a constructed URI.
        malformed(seq(tlv(0xa2, tlv(0x16, ascii("a.example"))), tlv(0x82, ascii("b.example"))), reader)
        malformed(seq(tlv(0x80, ascii("x"))), reader)
        malformed(seq(tlv(0x84, ascii("x"))), reader)
        malformed(seq(tlv(0xa6, tlv(0x16, ascii("https://a.example/")))), reader)
        malformed(seq(tlv(0xa1, ascii("x"))), reader)
        // As webpki, contents other than a dNSName's are not checked: any iPAddress length, an empty registeredID.
        for (n in listOf(0, 3, 5, 8, 15, 17, 32)) value(seq(tlv(0x87, ByteArray(n))), reader)
        value(seq(tlv(0x88)), reader)
        value(seq(tlv(0x88, bytes(0x2b, 0x86))), reader)
    }

    @Test
    fun `strict readers reject a non-minimal length that K8 leaves to K1`() {
        // basicConstraints SEQUENCE { TRUE } with its SEQUENCE length in long form.
        val bc = bytes(0x30, 0x81, 0x03, 0x01, 0x01, 0xff)
        malformed(bc, basicConstraintsReader)
        assertEquals(
            true,
            assertIs<ExtensionRead.Value<BasicConstraints>>(
                ExtensionValues.basicConstraints(bc, Span(0, bc.size), strict = false),
            ).value.ca,
        )
        val ku = bytes(0x03, 0x81, 0x02, 0x01, 0x06)
        malformed(ku, keyUsageReader)
        assertIs<ExtensionRead.Value<KeyUsage>>(ExtensionValues.keyUsage(ku, Span(0, ku.size), strict = false))
        val san = seq(bytes(0x82, 0x81, 0x01) + ascii("a"))
        malformed(san, subjectAltNameReader)
        assertIs<ExtensionRead.Value<SubjectAltNames>>(
            ExtensionValues.subjectAltName(san, Span(0, san.size), strict = false),
        )
        val eku = bytes(0x30, 0x0b, 0x06, 0x81, 0x08) + TestDer.oidContent(codeSigning)
        malformed(eku, extendedKeyUsageReader)
        val purposes = ExtensionValues.extendedKeyUsage(eku, Span(0, eku.size), strict = false)
        assertTrue(
            assertIs<ExtensionRead.Value<ExtendedKeyUsage>>(purposes).value.contains(TestDer.oidContent(codeSigning)),
        )
    }

    @Test
    fun `K8's SAN verdict is a function of the read names`() {
        fun k8(vararg names: ByteArray): Boolean {
            val c = cert(TestDer.extension(ExtensionValues.SUBJECT_ALT_NAME, seq(*names)))
            return ExtensionGrammars.valid(c.tbsBytes, c.tbs.extensions.single())
        }
        assertEquals(
            true,
            k8(tlv(0x82, ascii("a.example")), tlv(0x81, ascii("a@example")), tlv(0x87, bytes(1, 2, 3, 4))),
        )
        assertEquals(true, k8(tlv(0x87, ByteArray(16))))
        assertEquals(false, k8(tlv(0x87, bytes(1, 2, 3))))
        assertEquals(false, k8(tlv(0x81, bytes(0x61, 0xc3, 0xa9))))
        assertEquals(false, k8(tlv(0x82, ascii("a.example")), tlv(0x86, ascii("https://a.example/"))))
        assertEquals(false, k8(tlv(0x82, bytes(0xc3, 0xa9))))
        assertEquals(false, k8())
    }

    @Test
    fun `a certificate's extension is absent, read once, or failed when duplicated or spelled non-minimally`() {
        val bcExtension =
            TestDer.extension(
                ExtensionValues.BASIC_CONSTRAINTS,
                seq(boolTrue, tlv(0x02, bytes(1))),
                critical = true,
            )
        val leaf = cert(TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x04, bytes(1))))
        assertEquals(ExtensionRead.Absent, ExtensionValues.basicConstraints(leaf))
        assertEquals(ExtensionRead.Absent, ExtensionValues.keyUsage(leaf))
        assertEquals(ExtensionRead.Absent, ExtensionValues.extendedKeyUsage(leaf))
        assertEquals(ExtensionRead.Absent, ExtensionValues.subjectAltName(leaf))
        val ca =
            cert(
                bcExtension,
                TestDer.extension(ExtensionValues.KEY_USAGE, tlv(0x03, bytes(0x01, 0x06)), critical = true),
                TestDer.extension(ExtensionValues.EXT_KEY_USAGE, seq(oid(codeSigning))),
                TestDer.extension(ExtensionValues.SUBJECT_ALT_NAME, seq(tlv(0x82, ascii("a.example")))),
            )
        assertEquals(
            1,
            assertIs<ExtensionRead.Value<BasicConstraints>>(ExtensionValues.basicConstraints(ca)).value.pathLen,
        )
        assertTrue(assertIs<ExtensionRead.Value<KeyUsage>>(ExtensionValues.keyUsage(ca)).value.keyCertSign)
        assertTrue(
            assertIs<ExtensionRead.Value<ExtendedKeyUsage>>(ExtensionValues.extendedKeyUsage(ca)).value.contains(
                TestDer.oidContent(codeSigning),
            ),
        )
        assertEquals(
            listOf("a.example"),
            assertIs<ExtensionRead.Value<SubjectAltNames>>(ExtensionValues.subjectAltName(ca)).value.dnsNames,
        )
        val twice = ExtensionValues.basicConstraints(cert(bcExtension, bcExtension))
        assertEquals(ExtensionFailure.DUPLICATE, assertIs<ExtensionRead.Failed>(twice).reason)
        // 2.5.29.19 with its last arc spelled 80 13: the same OID to the dotted lookup, never to Oid.matches.
        val spelled = seq(tlv(0x06, bytes(0x55, 0x1d, 0x80, 0x13)), tlv(0x04, seq(boolTrue)))
        assertEquals(
            ExtensionFailure.MALFORMED,
            assertIs<ExtensionRead.Failed>(ExtensionValues.basicConstraints(cert(spelled))).reason,
        )
        assertEquals(
            ExtensionFailure.DUPLICATE,
            assertIs<ExtensionRead.Failed>(ExtensionValues.basicConstraints(cert(spelled, bcExtension))).reason,
        )
        val bad = cert(TestDer.extension(ExtensionValues.KEY_USAGE, tlv(0x03, bytes(0x03, 0x04))))
        assertEquals(ExtensionFailure.MALFORMED, assertIs<ExtensionRead.Failed>(ExtensionValues.keyUsage(bad)).reason)
    }
}
