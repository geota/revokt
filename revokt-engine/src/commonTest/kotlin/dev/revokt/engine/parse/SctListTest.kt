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
 * the outcome 3a gave, except the inner identifier, where revokt requires `0x04` (`3A_HEADER_LAX`).
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
    fun `sct list requires the inner identifier 0x04`() {
        val content = list(listOf(a))
        for (identifier in listOf(bytes(0x44), bytes(0x84), bytes(0xc4), bytes(0x1f, 0x04), bytes(0x24), bytes(0x30))) {
            assertEquals(emptySet(), scts(identifier + bytes(content.size) + content), identifier.toList().toString())
        }
    }

    @Test
    fun `sct union spans every SCT extension and a failing list contributes nothing`() {
        val first = inner(list(emptyList()))
        val second = inner(list(listOf(a)))
        val third = inner(list(listOf(b, a)))
        assertEquals(setOf(one(1, 100)), scts(first, second), "empty list first, covered SCT second")
        assertEquals(setOf(one(1, 100), one(2, 200)), scts(second, third), "duplicates count once")
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
                .bytes(p.der)
                .toList(),
        )
        assertEquals(
            listOf<Byte>(7, 8),
            p.fields.akiKeyId!!
                .bytes(p.der)
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
    }
}
