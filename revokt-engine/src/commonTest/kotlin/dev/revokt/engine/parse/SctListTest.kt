// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.concat
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Spec §9.2 revision 33, the SCT-list rule. Every case of the `x509-parser` 0.18.1 probe recorded on #10 is here with
 * the outcome 3a gave, except the inner identifier, where revokt requires `0x04` and 3a is wider (`3A_HEADER_LAX`), plus
 * the boundary cases the PR #18 Independent review's differential (441,776 inputs, 0 disagreements) found unpinned.
 */
class SctListTest {
    private fun sct(
        version: Int,
        id: Int,
        timestamp: Long,
        extra: ByteArray = ByteArray(0),
        signature: ByteArray = bytes(0xaa, 0xbb),
    ): ByteArray {
        val ts = ByteArray(8) { (timestamp ushr (56 - 8 * it)).toByte() }
        val content =
            concat(
                bytes(version),
                ByteArray(32) { id.toByte() },
                ts,
                bytes(0, 0), // extensions
                bytes(4, 3), // hash and signature algorithm
                bytes(signature.size shr 8, signature.size and 0xff),
                signature,
                extra,
            )
        return bytes(content.size shr 8, content.size and 0xff) + content
    }

    private fun list(
        items: List<ByteArray>,
        after: ByteArray = ByteArray(0),
        declaredDelta: Int = 0,
    ): ByteArray {
        val body = concat(*items.toTypedArray())
        val declared = body.size + declaredDelta
        return bytes(declared shr 8, declared and 0xff) + body + after
    }

    private fun inner(content: ByteArray): ByteArray = tlv(0x04, content)

    private fun scts(vararg values: ByteArray): Set<Sct> {
        val exts = values.map { TestDer.extension(Oid.SCT_LIST, it) }
        val p = CertificateParser.parse(TestCert(extensions = exts).der) as CertificateParse.Parsed
        return p.certificate.fields.scts
    }

    private fun one(
        id: Int,
        ts: Long,
    ) = Sct(ByteArray(32) { id.toByte() }.toByteString(), ts)

    private val a = sct(0, 1, 100)
    private val b = sct(0, 2, 200)

    @Test
    fun `sct list reads every item of a well-formed list`() {
        assertEquals(setOf(one(1, 100), one(2, 200)), scts(inner(list(listOf(a, b)))))
    }

    @Test
    fun `sct list ignores bytes at the three levels the rule names`() {
        assertEquals(setOf(one(1, 100)), scts(inner(list(listOf(a))) + bytes(0x00)), "after the inner OCTET STRING")
        assertEquals(setOf(one(1, 100)), scts(inner(list(listOf(a), after = bytes(0xde, 0xad)))), "after the region")
        assertEquals(
            setOf(one(1, 100), one(2, 200)),
            scts(inner(list(listOf(sct(0, 1, 100, extra = bytes(9, 9, 9)), b)))),
            "inside an item",
        )
    }

    @Test
    fun `sct list keeps the items before the first failing one and fails on a failing first item`() {
        assertEquals(setOf(one(1, 100)), scts(inner(list(listOf(a, b.copyOf(10))))), "truncated last item")
        assertEquals(
            setOf(one(1, 100)),
            scts(inner(list(listOf(a, b), declaredDelta = -3))),
            "declared shorter than the data",
        )
        assertEquals(emptySet(), scts(inner(list(listOf(bytes(0, 3, 1, 2, 3), a)))), "bad first item")
        assertEquals(emptySet(), scts(inner(list(emptyList()))), "empty list")
        assertEquals(emptySet(), scts(inner(list(listOf(bytes(0, 0), a)))), "first item of length 0")
        assertEquals(
            setOf(one(1, 100)),
            scts(inner(list(listOf(a, bytes(0, 0), b)))),
            "a later length-0 item ends the list",
        )
        assertEquals(emptySet(), scts(inner(list(listOf(a), declaredDelta = 5))), "declared longer than the data")
    }

    @Test
    fun `sct list pins every boundary the x509-parser differential found unpinned`() {
        // From the PR #18 Independent review: each input fails in 3a; a mutant at the named check would extract a.
        val c = list(listOf(a))
        val n = c.size
        assertEquals(
            emptySet(),
            scts(bytes(0x04, n) + list(listOf(a), declaredDelta = -1)),
            "region one byte short of the item",
        )
        assertEquals(
            emptySet(),
            scts(bytes(0x04, n) + list(listOf(a), declaredDelta = 1).copyOf(n)),
            "declared one byte past the content",
        )
        assertEquals(
            emptySet(),
            scts(bytes(0x04, 0xff) + ByteArray(126) + bytes(n) + c),
            "0xFF with enough octets behind it",
        )
        assertEquals(emptySet(), scts(bytes(0x04, 0x88, 0x80, 0, 0, 0, 0, 0, 0, n) + c), "a length of 2^63 or more")
        assertEquals(
            emptySet(),
            scts(bytes(0x04, 0x88, 0xe4, 0, 0, 0, 0, 0xbf, 0, 0x05, 0xff, 0xfe, 0xf8, 0x1c, 0xd3)),
            "negative as a Long",
        )
        assertEquals(
            setOf(one(1, 100)),
            scts(inner(list(listOf(a, b), declaredDelta = -1))),
            "second item one byte short",
        )
    }

    @Test
    fun `sct list accepts any version byte and a zero-length signature`() {
        assertEquals(setOf(one(1, 100)), scts(inner(list(listOf(sct(1, 1, 100))))))
        assertEquals(setOf(one(1, 100)), scts(inner(list(listOf(sct(0, 1, 100, signature = ByteArray(0)))))))
    }

    @Test
    fun `sct list accepts every long-form inner length and rejects 0x80 and 0xFF`() {
        val content = list(listOf(a))
        val n = content.size
        assertEquals(setOf(one(1, 100)), scts(bytes(0x04, 0x81, n) + content), "81 nn with nn < 0x80")
        assertEquals(setOf(one(1, 100)), scts(bytes(0x04, 0x84, 0, 0, 0, n) + content), "84 00 00 00 nn")
        assertEquals(
            setOf(one(1, 100)),
            scts(bytes(0x04, 0x88, 0, 0, 0, 0, 0, 0, 0, n) + content),
            "eight length octets",
        )
        assertEquals(emptySet(), scts(bytes(0x04, 0x80) + content + bytes(0, 0)), "indefinite")
        assertEquals(emptySet(), scts(bytes(0x04, 0xff) + content), "reserved")
        assertEquals(emptySet(), scts(bytes(0x04, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, n) + content), "over 64 bits")
        assertEquals(emptySet(), scts(bytes(0x04, n + 1) + content), "past the end of the value")
    }

    @Test
    fun `sct list requires the inner identifier 0x04 where 3a is wider`() {
        // 3A_HEADER_LAX: tag number 4 in another class or in multi-octet form, which 3a accepts and revokt does not.
        val content = list(listOf(a))
        for (identifier in listOf(
            bytes(0x44),
            bytes(0x84),
            bytes(0xc4),
            bytes(0x1f, 0x04),
            bytes(0x1f, 0x90, 0x80, 0x80, 0x80, 0x04),
        )) {
            assertEquals(emptySet(), scts(identifier + bytes(content.size) + content), identifier.toList().toString())
        }
    }

    @Test
    fun `sct list fails on headers 3a rejects as well`() {
        // Not 3A_HEADER_LAX: x509-parser 0.18.1 fails on each of these too (PR #18 Independent review differential).
        val content = list(listOf(a))
        val primitive = inner(content)
        assertEquals(emptySet(), scts(bytes(0x30, content.size) + content), "SEQUENCE")
        assertEquals(emptySet(), scts(bytes(0x24, content.size) + content), "constructed tag 4 around the bare list")
        assertEquals(
            emptySet(),
            scts(bytes(0x24, primitive.size) + primitive),
            "constructed OCTET STRING around a primitive one",
        )
        assertEquals(emptySet(), scts(bytes(0x24, 0x80) + primitive + bytes(0, 0)), "constructed, indefinite length")
    }

    @Test
    fun `sct union spans every SCT extension and a failing list contributes nothing`() {
        val first = inner(list(emptyList()))
        val second = inner(list(listOf(a)))
        val third = inner(list(listOf(b, a)))
        assertEquals(setOf(one(1, 100)), scts(first, second), "empty list first, covered SCT second")
        assertEquals(setOf(one(1, 100)), scts(second, first), "a failing list after a good one")
        assertEquals(setOf(one(1, 100), one(2, 200)), scts(second, third), "duplicates count once")
    }

    @Test
    fun `sct extension matches only the canonical OID encoding`() {
        // 11129 spelled with a leading 0x80 arc octet: x509-parser reports the extension as unsupported, so no pairs.
        val nonCanonical = bytes(0x2b, 0x06, 0x01, 0x04, 0x01, 0x80, 0xd6, 0x79, 0x02, 0x04, 0x02)
        val ext = seq(tlv(0x06, nonCanonical), tlv(0x04, inner(list(listOf(a)))))
        val p = (CertificateParser.parse(TestCert(extensions = listOf(ext)).der) as CertificateParse.Parsed).certificate
        assertEquals(
            Oid.SCT_LIST,
            p.tbs.extensions
                .single()
                .oidDotted,
        )
        assertEquals(emptySet(), p.fields.scts)
    }

    @Test
    fun `key identifiers are read leniently from SKI and AKI`() {
        val ski = TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x04, bytes(1, 2, 3)))
        val aki = TestDer.extension(Oid.AUTHORITY_KEY_IDENTIFIER, seq(tlv(0x80, bytes(7, 8)), tlv(0xa1, seq())))
        val p =
            (
                CertificateParser.parse(
                    TestCert(extensions = listOf(ski, aki)).der,
                ) as CertificateParse.Parsed
            ).certificate
        assertEquals(
            listOf<Byte>(1, 2, 3),
            p.fields.ski!!
                .bytes(p.tbsBytes)
                .toList(),
        )
        assertEquals(
            listOf<Byte>(7, 8),
            p.fields.akiKeyId!!
                .bytes(p.tbsBytes)
                .toList(),
        )
        val malformed =
            listOf(
                TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x30)),
                TestDer.extension(Oid.AUTHORITY_KEY_IDENTIFIER, seq(tlv(0xa1, seq()))),
            )
        val m = (CertificateParser.parse(TestCert(extensions = malformed).der) as CertificateParse.Parsed).certificate
        assertNull(m.fields.ski)
        assertNull(m.fields.akiKeyId)
        // A truncated [0] inside the AKI reaches the reader that throws; the parse must still succeed.
        val truncated = listOf(TestDer.extension(Oid.AUTHORITY_KEY_IDENTIFIER, bytes(0x30, 0x02, 0x80, 0x05)))
        val t = (CertificateParser.parse(TestCert(extensions = truncated).der) as CertificateParse.Parsed).certificate
        assertNull(t.fields.akiKeyId)
        // Pinned leniency (KDoc): a SKI with trailing bytes and a constructed AKI [0] are null.
        val strict =
            listOf(
                TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, bytes(0x04, 0x02, 0x01, 0x02, 0x00)),
                TestDer.extension(Oid.AUTHORITY_KEY_IDENTIFIER, bytes(0x30, 0x06, 0xa0, 0x04, 0x04, 0x02, 0x07, 0x08)),
            )
        val st = (CertificateParser.parse(TestCert(extensions = strict).der) as CertificateParse.Parsed).certificate
        assertNull(st.fields.ski)
        assertNull(st.fields.akiKeyId)
        // A non-minimal SKI header is accepted and recorded for the producer-keyability table.
        val nonMinimal = listOf(TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, bytes(0x04, 0x81, 0x02, 0x01, 0x02)))
        val nm = (CertificateParser.parse(TestCert(extensions = nonMinimal).der) as CertificateParse.Parsed).certificate
        assertEquals(
            listOf<Byte>(1, 2),
            nm.fields.ski!!
                .bytes(nm.tbsBytes)
                .toList(),
        )
        assertEquals(listOf(HeaderSite.SKI), nm.nonMinimalHeaders.map { it.site })
        // The first copy that parses wins, as the JDK reports a later well-formed SKI after a malformed one.
        val twoSki =
            listOf(
                TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x30)),
                TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, tlv(0x04, bytes(2))),
            )
        val k = (CertificateParser.parse(TestCert(extensions = twoSki).der) as CertificateParse.Parsed).certificate
        assertEquals(
            listOf<Byte>(2),
            k.fields.ski!!
                .bytes(k.tbsBytes)
                .toList(),
        )
    }
}
