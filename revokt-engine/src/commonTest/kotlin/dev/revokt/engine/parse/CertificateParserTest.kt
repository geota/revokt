// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.ParseReason
import dev.revokt.RevoktLimits
import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import dev.revokt.engine.parse.TestDer.tlvWithLength
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

class CertificateParserTest {
    private fun parsed(cert: TestCert): ParsedCertificate = parsed(cert.der)

    private fun parsed(der: ByteArray): ParsedCertificate =
        when (val r = CertificateParser.parse(der)) {
            is CertificateParse.Parsed -> r.certificate
            is CertificateParse.Failed -> fail("expected Parsed, got ${r.reason}: ${r.detail}")
        }

    private fun failed(der: ByteArray): CertificateParse.Failed =
        assertIs<CertificateParse.Failed>(CertificateParser.parse(der))

    /** The bytes after an element's tag and length: the content of a TLV the test wrote with a minimal header. */
    private fun content(tlv: ByteArray): ByteArray =
        tlv.copyOfRange(
            if (tlv[1].toInt() and 0x80 ==
                0
            ) {
                2
            } else {
                2 + (tlv[1].toInt() and 0x7f)
            },
            tlv.size,
        )

    @Test
    fun `parser extracts every field of a v3 certificate`() {
        val cert = TestCert()
        val p = parsed(cert)
        assertContentEquals(cert.tbs, p.tbs.tlv.bytes(p.der))
        assertContentEquals(bytes(0x00, 0x8f, 0x12, 0x34), p.rawSerial())
        assertContentEquals(cert.tbsSignature, p.tbs.signature.bytes(p.der))
        assertContentEquals(cert.issuer, p.rawIssuer())
        assertContentEquals(cert.subject, p.rawSubject())
        assertContentEquals(cert.spki, p.rawSpki())
        assertContentEquals(cert.outerAlgorithm, p.signatureAlgorithm.bytes(p.der))
        assertContentEquals(content(cert.signature), p.signatureValue.bytes(p.der))
        assertContentEquals(bytes(2), p.tbs.version!!.bytes(p.der))
        assertEquals(1_792_676_730_000, p.tbs.validity.notBeforeMillis)
        assertEquals(2_524_608_000_000, p.tbs.validity.notAfterMillis)
        assertEquals(listOf(Oid.SUBJECT_KEY_IDENTIFIER, "2.5.29.19"), p.tbs.extensions.map { it.oidDotted })
        assertEquals(listOf(false, true), p.tbs.extensions.map { it.critical })
        assertContentEquals(
            tlv(0x04, bytes(1, 2, 3, 4)),
            p
                .extensions(Oid.SUBJECT_KEY_IDENTIFIER)
                .single()
                .value
                .bytes(p.der),
        )
        assertEquals(emptyList(), p.nonMinimalHeaders.map { it.site })
    }

    @Test
    fun `parser accepts a v1 certificate without version, unique ids or extensions`() {
        val p = parsed(TestCert(version = ByteArray(0), extensions = emptyList()))
        assertNull(p.tbs.version)
        assertEquals(emptyList(), p.tbs.extensions)
    }

    @Test
    fun `parser accepts both unique ids before the extensions`() {
        val p = parsed(TestCert(uniqueIds = tlv(0x81, bytes(0, 1)) + tlv(0x82, bytes(0, 2))))
        assertEquals(2, p.tbs.extensions.size)
    }

    @Test
    fun `parser keeps the serial as encoded whatever its value`() {
        val serials =
            listOf(
                bytes(0xff, 0x01),
                bytes(0x00, 0x00, 0x7f),
                ByteArray(21) { (it + 1).toByte() },
                ByteArray(0),
                bytes(0),
            )
        for (s in serials) {
            assertContentEquals(s, parsed(TestCert(serial = tlv(0x02, s))).rawSerial(), s.toList().toString())
        }
    }

    @Test
    fun `parser accepts duplicate and unknown critical extensions and reports them`() {
        val dup = TestDer.extension("1.2.3.4", tlv(0x04, bytes(1)), critical = true)
        val p = parsed(TestCert(extensions = listOf(dup, dup, TestDer.extension(Oid.SCT_LIST, tlv(0x04)))))
        assertEquals(setOf("1.2.3.4"), p.duplicateExtensionOids())
        assertEquals(2, p.extensions("1.2.3.4").size)
        assertTrue(p.extensions("1.2.3.4").all { it.critical })
    }

    @Test
    fun `parser accepts an explicit FALSE critical flag and an empty extension list`() {
        val p = parsed(TestCert(extensions = listOf(TestDer.extension("1.2.3", ByteArray(0), critical = false))))
        assertEquals(
            false,
            p.tbs.extensions
                .single()
                .critical,
        )
        val empty = TestCert(extensions = emptyList(), extensionsWrapper = { tlv(0xa3, seq()) })
        assertEquals(emptyList(), parsed(empty).tbs.extensions)
    }

    @Test
    fun `parser accepts an empty subject and any name content`() {
        val odd =
            seq(
                tlv(0x31, seq(TestDer.oid("2.5.4.3"), tlv(0x1e, bytes(0, 0x41)))),
                tlv(0x31, seq(TestDer.oid("2.5.4.10"), tlv(0x14, ascii("t61")))),
            )
        val p = parsed(TestCert(subject = seq(), issuer = odd))
        assertContentEquals(seq(), p.rawSubject())
        assertContentEquals(odd, p.rawIssuer())
    }

    @Test
    fun `parser decodes UTCTime and GeneralizedTime leniently`() {
        fun times(
            nb: ByteArray,
            na: ByteArray,
        ) = parsed(TestCert(validity = seq(nb, na))).tbs.validity
        val utc = { s: String -> tlv(0x17, ascii(s)) }
        val gen = { s: String -> tlv(0x18, ascii(s)) }
        assertEquals(1_792_676_700_000, times(utc("2610221345Z"), utc("2610221345Z")).notBeforeMillis, "no seconds")
        assertEquals(1_792_676_730_000, times(utc("261022154530+0200"), utc("261022134530Z")).notBeforeMillis, "offset")
        assertEquals(
            -631_152_000_000,
            times(utc("500101000000Z"), utc("491231235959Z")).notBeforeMillis,
            "UTCTime 50 is 1950",
        )
        assertEquals(
            2_524_607_999_000,
            times(utc("500101000000Z"), utc("491231235959Z")).notAfterMillis,
            "UTCTime 49 is 2049",
        )
        assertEquals(
            1_792_676_730_123,
            times(gen("20261022134530.1234Z"), gen("20261022134530Z")).notBeforeMillis,
            "fraction",
        )
        assertEquals(1_792_676_730_000, times(gen("20261022134530"), gen("20261022134530Z")).notBeforeMillis, "no zone")
        val garbage = times(utc("not a time"), gen("2026130100Z"))
        assertNull(garbage.notBeforeMillis)
        assertNull(garbage.notAfterMillis)
    }

    @Test
    fun `parser rejects structural errors`() {
        val base = TestCert()
        val cases =
            mapOf(
                "length past the end" to tlvWithLength(0x30, bytes(0x82, 0x7f, 0xff), base.tbs),
                "reserved length byte" to tlvWithLength(0x30, bytes(0xff), ByteArray(0)),
                "bytes after Certificate" to TestCert(outerTrailing = bytes(0)).der,
                "element after signatureValue" to TestCert(certificateTrailing = tlv(0x05)).der,
                "serial that is not an INTEGER" to TestCert(serial = tlv(0x04, bytes(1))).der,
                "validity with one time" to TestCert(validity = seq(tlv(0x17, ascii("261022134530Z")))).der,
                "validity time of the wrong type" to
                    TestCert(validity = seq(tlv(0x13, ascii("x")), tlv(0x17, ascii("x")))).der,
                "extension value that is not an OCTET STRING" to
                    TestCert(extensions = listOf(seq(TestDer.oid("1.2.3"), tlv(0x30)))).der,
                "two-byte critical flag" to
                    TestCert(
                        extensions = listOf(seq(TestDer.oid("1.2.3"), tlv(0x01, bytes(0xff, 0xff)), tlv(0x04))),
                    ).der,
                "empty input" to ByteArray(0),
                "truncated header" to bytes(0x30),
            )
        for ((name, der) in cases) {
            assertEquals(ParseReason.STRUCTURE, failed(der).reason, name)
        }
    }

    @Test
    fun `parser rejects indefinite, five-byte and multi-byte headers at the element that carries them`() {
        val indefinite = failed(TestCert(serial = tlvWithLength(0x02, bytes(0x80), bytes(1, 0, 0))).der)
        assertContains(indefinite.detail, "indefinite length for SERIAL")
        val fiveByte = failed(TestCert(serial = tlvWithLength(0x02, bytes(0x85, 0, 0, 0, 0, 3), bytes(1, 2, 3))).der)
        assertContains(fiveByte.detail, "length of 5 bytes for SERIAL")
        val multiByte = failed(TestCert(uniqueIds = bytes(0x1f, 0x81, 0x01, 0x00)).der)
        assertContains(multiByte.detail, "multi-byte tag for TBS_STOP")
    }

    @Test
    fun `parser reads the TBS tail sequentially as the JDK does`() {
        val ext = TestCert().extensions
        val wrapper = tlv(0xa3, seq(*ext.toTypedArray()))
        val nul = tlv(0x05)

        fun tail(bytes: ByteArray) = parsed(TestCert(uniqueIds = bytes, extensions = emptyList()))
        // Each case: the TBS tail after the SPKI, the extensions the JDK reads, the ignored sites.
        val cases =
            listOf(
                Triple("trailing NULL after [3]", wrapper + nul, 2 to listOf(IgnoredSite.TBS_AFTER_EXTENSIONS)),
                Triple(
                    "non-TLV bytes after [3]",
                    wrapper + bytes(0xff, 0xff, 0xff),
                    2 to listOf(IgnoredSite.TBS_AFTER_EXTENSIONS),
                ),
                Triple(
                    "NULL before [3]",
                    nul + wrapper,
                    0 to listOf(IgnoredSite.TBS_AFTER_STOP, IgnoredSite.TBS_AFTER_STOP),
                ),
                Triple("constructed [1] then [3]", bytes(0xa1, 2, 0, 1) + wrapper, 2 to emptyList()),
                Triple("constructed [2] then [3]", bytes(0xa2, 2, 0, 1) + wrapper, 2 to emptyList()),
                Triple(
                    "[2] before [1]",
                    tlv(0x82, bytes(0)) + tlv(0x81, bytes(0)) + wrapper,
                    0 to listOf(IgnoredSite.TBS_AFTER_STOP, IgnoredSite.TBS_AFTER_STOP),
                ),
                Triple(
                    "[1] twice",
                    tlv(0x81, bytes(0)) + tlv(0x81, bytes(0)) + wrapper,
                    0 to listOf(IgnoredSite.TBS_AFTER_STOP, IgnoredSite.TBS_AFTER_STOP),
                ),
                Triple("primitive [3]", bytes(0x83, 0), 0 to listOf(IgnoredSite.TBS_AFTER_STOP)),
                Triple("two [3]", wrapper + wrapper, 2 to listOf(IgnoredSite.TBS_AFTER_EXTENSIONS)),
                Triple(
                    "NULL after the Extensions SEQUENCE",
                    tlv(0xa3, seq(*ext.toTypedArray()), nul),
                    2 to listOf(IgnoredSite.EXTENSIONS_WRAPPER_TRAILING),
                ),
            )
        for ((name, bytes, expected) in cases) {
            val p = tail(bytes)
            assertEquals(expected.first, p.tbs.extensions.size, name)
            assertEquals(expected.second, p.ignoredElements.map { it.site }, name)
            for (ignored in p.ignoredElements) {
                assertTrue(ignored.span.start < ignored.span.end && ignored.span.end <= p.tbs.tlv.end, name)
            }
        }
    }

    @Test
    fun `parser ignores trailing elements inside the version wrapper and after extnValue`() {
        val p =
            parsed(
                TestCert(
                    version = tlv(0xa0, tlv(0x02, bytes(2)), tlv(0x05)),
                    extensions = listOf(seq(TestDer.oid("1.2.3"), tlv(0x04, bytes(7)), tlv(0x05))),
                ),
            )
        assertContentEquals(bytes(2), p.tbs.version!!.bytes(p.der))
        assertContentEquals(
            bytes(7),
            p.tbs.extensions
                .single()
                .value
                .bytes(p.der),
        )
        assertEquals(
            listOf(IgnoredSite.VERSION_TRAILING, IgnoredSite.EXTENSION_TRAILING),
            p.ignoredElements.map { it.site },
        )
    }

    @Test
    fun `parser records a long-form length with a leading zero and not a minimal long form`() {
        val body = ByteArray(128) { 0x41 }
        val nonMinimal = parsed(TestCert(subject = tlvWithLength(0x30, bytes(0x82, 0x00, 0x80), body)))
        assertEquals(listOf(HeaderSite.SUBJECT), nonMinimal.nonMinimalHeaders.map { it.site })
        val minimal = parsed(TestCert(subject = tlvWithLength(0x30, bytes(0x81, 0x80), body)))
        assertEquals(emptyList(), minimal.nonMinimalHeaders.map { it.site })
        val shortInLong = parsed(TestCert(subject = tlvWithLength(0x30, bytes(0x81, 0x05), ByteArray(5))))
        assertEquals(listOf(HeaderSite.SUBJECT), shortInLong.nonMinimalHeaders.map { it.site })
    }

    @Test
    fun `parser step count is pinned for the reference certificate`() {
        // Headers, one per element, OID and time content: a change here is a change to what D5 measures.
        val p = parsed(TestCert())
        assertEquals(105, p.steps)
        assertTrue(p.steps <= 8L * p.der.size + 1024)
    }

    @Test
    fun `parser treats any non-zero critical byte as true and decodes year zero`() {
        val critical =
            parsed(TestCert(extensions = listOf(seq(TestDer.oid("1.2.3"), tlv(0x01, bytes(0x01)), tlv(0x04)))))
        assertTrue(
            critical.tbs.extensions
                .single()
                .critical,
        )
        val year0 =
            parsed(
                TestCert(validity = seq(tlv(0x18, ascii("00000101000000Z")), tlv(0x18, ascii("99991231235959.999Z")))),
            ).tbs.validity
        assertEquals(-62_167_219_200_000, year0.notBeforeMillis)
        assertEquals(253_402_300_799_999, year0.notAfterMillis)
    }

    @Test
    fun `parser accepts non-minimal lengths and records each with its site`() {
        val serial = tlvWithLength(0x02, bytes(0x81, 0x02), bytes(0x01, 0x02))
        val spkiContent = content(TestCert().spki)
        val spki = tlvWithLength(0x30, bytes(0x82, 0x00, spkiContent.size), spkiContent)
        val p = parsed(TestCert(serial = serial, spki = spki))
        assertContentEquals(bytes(0x01, 0x02), p.rawSerial())
        assertContentEquals(spki, p.rawSpki())
        assertEquals(listOf(HeaderSite.SERIAL, HeaderSite.SPKI), p.nonMinimalHeaders.map { it.site })
        assertEquals(p.tbs.spki.start, p.nonMinimalHeaders[1].offset)
    }

    @Test
    fun `parser answers OVERSIZE before parsing`() {
        assertEquals(ParseReason.OVERSIZE, failed(ByteArray(RevoktLimits.MAX_CERT_BYTES + 1)).reason)
        assertEquals(ParseReason.STRUCTURE, failed(ByteArray(RevoktLimits.MAX_CERT_BYTES)).reason)
        val padded = TestCert(subject = tlv(0x30, ByteArray(RevoktLimits.MAX_CERT_BYTES - 1000)))
        assertTrue(padded.der.size <= RevoktLimits.MAX_CERT_BYTES)
        parsed(padded)
    }

    @Test
    fun `parser decodes OIDs leniently and refuses unterminated arcs`() {
        val der = TestDer.oidContent("1.3.6.1.4.1.11129.2.4.2")
        assertEquals(Oid.SCT_LIST, Oid.dotted(der, Span(0, der.size)))
        assertEquals("2.999.3", Oid.dotted(TestDer.oidContent("2.999.3"), Span(0, TestDer.oidContent("2.999.3").size)))
        val nonMinimal = bytes(0x2a, 0x80, 0x03)
        assertEquals("1.2.3", Oid.dotted(nonMinimal, Span(0, 3)))
        assertNull(Oid.dotted(bytes(0x2a, 0x83), Span(0, 2)))
        assertNull(Oid.dotted(ByteArray(0), Span(0, 0)))
        assertNull(Oid.dotted(ByteArray(11) { 0xff.toByte() } + bytes(0x7f), Span(0, 12)))
    }

    @Test
    fun `parser is deterministic, within its step budget and its spans re-slice the input under mutation`() {
        val seeds = listOf(TestCert().der, TestCert(version = ByteArray(0), extensions = emptyList()).der)
        val random = Random(20261023)
        var parsedCount = 0
        repeat(5000) { n ->
            val base = seeds[n % seeds.size]
            val der = mutate(base, random)
            val first = CertificateParser.parse(der)
            val second = CertificateParser.parse(der)
            when (first) {
                is CertificateParse.Failed -> {
                    assertIs<CertificateParse.Failed>(second)
                    assertEquals(first.reason, second.reason)
                    assertEquals(first.detail, second.detail)
                }

                is CertificateParse.Parsed -> {
                    parsedCount++
                    val c = first.certificate
                    assertTrue(c.steps <= 8L * der.size + 1024, "steps ${c.steps} for ${der.size} bytes")
                    assertSameFields(c, assertIs<CertificateParse.Parsed>(second).certificate)
                    assertSpansReslice(c)
                }
            }
        }
        assertTrue(parsedCount > 100, "only $parsedCount of 5000 mutants parsed; the property is not exercised")
    }

    private fun mutate(
        base: ByteArray,
        random: Random,
    ): ByteArray {
        val b = base.copyOf()
        return when (random.nextInt(4)) {
            0 -> {
                b.also { it[random.nextInt(it.size)] = random.nextInt(256).toByte() }
            }

            1 -> {
                b.copyOf(random.nextInt(b.size))
            }

            2 -> {
                b.copyOfRange(0, random.nextInt(b.size)) + bytes(random.nextInt(256)) +
                    b.copyOfRange(random.nextInt(b.size), b.size)
            }

            else -> {
                b.also {
                    it[2 + random.nextInt(it.size - 2)] =
                        (it[2 + random.nextInt(it.size - 2)].toInt() xor (1 shl random.nextInt(8))).toByte()
                }
            }
        }
    }

    private fun assertSameFields(
        a: ParsedCertificate,
        b: ParsedCertificate,
    ) {
        assertEquals(a.tbs.serial, b.tbs.serial)
        assertEquals(a.tbs.spki, b.tbs.spki)
        assertEquals(a.tbs.subject, b.tbs.subject)
        assertEquals(a.tbs.issuer, b.tbs.issuer)
        assertEquals(a.tbs.extensions.map { it.tlv }, b.tbs.extensions.map { it.tlv })
        assertEquals(a.tbs.validity.notBeforeMillis, b.tbs.validity.notBeforeMillis)
        assertEquals(a.nonMinimalHeaders.map { it.offset }, b.nonMinimalHeaders.map { it.offset })
    }

    /** Spec §9.2 D6: every reported offset re-slices the input to the reported value. */
    private fun assertSpansReslice(c: ParsedCertificate) {
        val tlvSpans =
            listOf(c.tbs.tlv, c.tbs.signature, c.tbs.issuer, c.tbs.subject, c.tbs.spki, c.signatureAlgorithm) +
                c.tbs.extensions.map { it.tlv }
        for (span in tlvSpans) {
            assertTrue(span.start >= 0 && span.end <= c.der.size && span.start < span.end, "span $span")
            val again = DerReader(c.der, span.start, span.end, ParseContext()).readAny(HeaderSite.CERTIFICATE)
            assertEquals(span, again.tlv, "TLV at $span re-reads to ${again.tlv}")
        }
        for (e in c.tbs.extensions) {
            assertTrue(e.value.start >= e.tlv.start && e.value.end <= e.tlv.end, "extension value inside its TLV")
            assertEquals(e.oidDotted, Oid.dotted(c.der, e.oid))
        }
        assertTrue(c.tbs.serial.start > c.tbs.tlv.start && c.tbs.serial.end < c.tbs.tlv.end, "serial inside TBS")
    }
}
