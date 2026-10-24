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
        assertContentEquals(cert.tbs, p.tbsBytes)
        assertContentEquals(cert.tbs, p.tbs.tlv.bytes(p.tbsBytes))
        assertContentEquals(bytes(0x00, 0x8f, 0x12, 0x34), p.rawSerial())
        assertContentEquals(cert.tbsSignature, p.tbs.signature.bytes(p.tbsBytes))
        assertContentEquals(cert.issuer, p.rawIssuer())
        assertContentEquals(cert.subject, p.rawSubject())
        assertContentEquals(cert.spki, p.rawSpki())
        assertContentEquals(cert.outerAlgorithm, p.envelope.signatureAlgorithm.bytes(p.der))
        assertContentEquals(content(cert.signature), p.envelope.signatureValue.bytes(p.der))
        assertContentEquals(bytes(2), p.tbs.version!!.bytes(p.tbsBytes))
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
                .bytes(p.tbsBytes),
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
    fun `parser ignores trailing elements after extnValue and keeps the version wrapper strict`() {
        val p = parsed(TestCert(extensions = listOf(seq(TestDer.oid("1.2.3"), tlv(0x04, bytes(7)), tlv(0x05)))))
        assertContentEquals(
            bytes(7),
            p.tbs.extensions
                .single()
                .value
                .bytes(p.tbsBytes),
        )
        assertEquals(listOf(IgnoredSite.EXTENSION_TRAILING), p.ignoredElements.map { it.site })
        // ct-go flattens [0], so a trailing element there would make the producer key a different serial.
        val trailing = failed(TestCert(version = tlv(0xa0, tlv(0x02, bytes(2)), tlv(0x05))).der)
        assertContains(trailing.detail, "after version")
    }

    @Test
    fun `parser ignores non-TLV bytes where the JDK never reads them`() {
        // Spec §9.2 revision 33: the JDK accepts junk that is not a TLV after the Extensions SEQUENCE in [3] and
        // after extnValue, so revokt skips those bytes unparsed.
        val junk = bytes(0xff, 0xff)
        val ext = seq(TestDer.oid("1.2.3"), tlv(0x04, bytes(7)))
        val p =
            parsed(
                TestCert(
                    extensions = listOf(seq(TestDer.oid("1.2.4"), tlv(0x04, bytes(8)), junk), ext),
                    extensionsWrapper = { exts -> tlv(0xa3, seq(*exts.toTypedArray()), junk) },
                ),
            )
        assertEquals(listOf("1.2.4", "1.2.3"), p.tbs.extensions.map { it.oidDotted })
        // The wrapper's trailing bytes are recorded before the list inside it is walked.
        assertEquals(
            listOf(
                IgnoredSite.EXTENSIONS_WRAPPER_TRAILING,
                IgnoredSite.EXTENSION_TRAILING,
            ),
            p.ignoredElements.map {
                it.site
            },
        )
        assertTrue(p.ignoredElements.all { it.span.length == 2 })
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
        // Headers, one per element, OID and time content, and the SKI read, plus the TBS header read again on Cert.tbs:
        // a change here is a change to what D5 measures.
        val p = parsed(TestCert())
        assertEquals(112, p.steps)
        assertTrue(p.steps <= 8L * p.der.size + 1024)
    }

    @Test
    fun `parser rolls a day past the month's end into the next month as the JDK does`() {
        fun nb(text: String) =
            parsed(
                TestCert(validity = seq(tlv(0x17, ascii(text)), tlv(0x17, ascii("491231235959Z")))),
            ).tbs.validity.notBeforeMillis
        assertEquals(1_772_496_000_000, nb("260231000000Z"), "2026-02-31 is 2026-03-03")
        assertEquals(1_777_593_600_000, nb("260431000000Z"), "2026-04-31 is 2026-05-01")
        assertEquals(1_772_323_200_000, nb("260229000000Z"), "2026-02-29 is 2026-03-01")
        assertEquals(nb("261022134600Z"), nb("261022134560Z"), "second 60 is the first second of the next minute")
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
        val base = TestCert()
        val indefiniteTbs = bytes(0x30, 0x80) + content(base.tbs) + bytes(0, 0)
        val seeds =
            listOf(
                base.der,
                TestCert(version = ByteArray(0), extensions = emptyList()).der,
                seq(indefiniteTbs, base.outerAlgorithm, base.signature),
            )
        val random = Random(20261023)
        var parsedCount = 0
        repeat(5000) { n ->
            val der = mutate(seeds[n % seeds.size], random)
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
            listOf(c.tbs.tlv, c.tbs.signature, c.tbs.issuer, c.tbs.subject, c.tbs.spki) +
                c.tbs.extensions.map { it.tlv }
        // TBS offsets index Cert.tbs and, shifted by the TBS content's start, the input when the TBS header is definite.
        val shift = c.envelope.presentedTbs.content.start - (c.tbsBytes.size - (c.envelope.presentedTbs.content.length))
        for (span in tlvSpans) {
            assertTrue(span.start >= 0 && span.end <= c.tbsBytes.size && span.start < span.end, "span $span")
            val again = DerReader(c.tbsBytes, span.start, span.end, ParseContext()).readAny(HeaderSite.CERTIFICATE)
            assertEquals(span, again.tlv, "TLV at $span re-reads to ${again.tlv}")
            if (!c.envelope.tbsIndefinite && span != c.tbs.tlv) {
                assertContentEquals(span.bytes(c.tbsBytes), c.der.copyOfRange(span.start + shift, span.end + shift))
            }
        }
        val outer =
            DerReader(c.der, c.envelope.signatureAlgorithm.start, c.envelope.signatureAlgorithm.end, ParseContext())
        assertEquals(c.envelope.signatureAlgorithm, outer.readAny(HeaderSite.SIGNATURE_ALGORITHM).tlv)
        for (e in c.tbs.extensions) {
            assertTrue(e.value.start >= e.tlv.start && e.value.end <= e.tlv.end, "extension value inside its TLV")
            assertEquals(e.oidDotted, Oid.dotted(c.tbsBytes, e.oid))
        }
        assertTrue(c.tbs.serial.start > c.tbs.tlv.start && c.tbs.serial.end < c.tbs.tlv.end, "serial inside TBS")
    }
}
