// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.TestDer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * #237's name constraints ([NameConstraints], [DnsNameConstraint]) against webpki 0.104.0-alpha.7's rules, read in
 * `subject_name/mod.rs`, `dns_name.rs` and `ip_address.rs`. The cases are written from that code, not copied from its
 * tests.
 */
class NameConstraintsTest {
    private val unlimited = ComparisonBudget { true }

    private fun dns(
        presented: String,
        constraint: String,
        excluded: Boolean = false,
    ): Boolean? = DnsNameConstraint.matches(presented.encodeToByteArray(), constraint.encodeToByteArray(), excluded)

    @Test
    fun `walker a dNSName subtree matches on label boundaries, ignoring case`() {
        assertEquals(true, dns("www.example.com", "example.com"))
        assertEquals(true, dns("example.com", "example.com"))
        assertEquals(true, dns("WWW.Example.COM", "example.com"))
        assertEquals(false, dns("badexample.com", "example.com"))
        assertEquals(true, dns("www.example.com", ".example.com"), "a leading dot: subdomains")
        assertEquals(false, dns("example.com", ".example.com"), "a leading dot: not the name itself")
        assertEquals(false, dns("dexample.com", ".example.com"))
        assertEquals(true, dns("anything.example", ""), "an empty constraint covers every name")
        assertEquals(false, dns("example.com", "www.example.com"))
    }

    @Test
    fun `walker a wildcard is never inside a permitted subtree it could leave, and expands into an excluded one`() {
        assertEquals(true, dns("*.example.com", "example.com"), "every expansion stays within")
        assertEquals(false, dns("*.example.com", "a.example.com"), "permitted: not expanded")
        assertEquals(
            true,
            dns("*.example.com", "a.example.com", excluded = true),
            "excluded: expanded (CVE-2025-61727)",
        )
        assertEquals(false, dns("*.example.com", "a.other.com", excluded = true))
    }

    @Test
    fun `walker malformed dNSNames and constraints are errors, which fail closed`() {
        assertNull(dns("www.example.com.", "example.com"), "an absolute presented ID")
        assertNull(dns("-x.example.com", "example.com"))
        assertNull(dns("x.example.123", "example.123"), "an all-numeric last label")
        assertNull(dns("*.com", "com"), "a wildcard needs two labels after it")
        assertNull(dns("a.example.com", "*.example.com"), "no wildcard in a constraint")
        assertNull(dns("", "example.com"))
        assertNull(dns("a".repeat(64) + ".example.com", "example.com"), "a label over 63 octets")
    }

    private fun nc(
        permitted: List<ByteArray>? = null,
        excluded: List<ByteArray>? = null,
    ): NameConstraints? {
        val fields =
            listOfNotNull(
                permitted?.let { p ->
                    TestDer.tlv(
                        0xa0,
                        TestDer.bytes() + p.map { TestDer.seq(it) }.reduce(ByteArray::plus),
                    )
                },
                excluded?.let { e ->
                    TestDer.tlv(
                        0xa1,
                        TestDer.bytes() + e.map { TestDer.seq(it) }.reduce(ByteArray::plus),
                    )
                },
            )
        val value = TestDer.seq(*fields.toTypedArray())
        return NameConstraints.read(value, Span(0, value.size))
    }

    private fun dnsName(s: String) = TestDer.tlv(0x82, TestDer.ascii(s))

    private fun ip(vararg b: Int) = TestDer.tlv(0x87, TestDer.bytes(*b))

    private fun names(vararg n: PresentedName): List<PresentedName> = n.toList() + PresentedName.Directory

    private fun PresentedName.Companion.dns(s: String) = PresentedName.Dns(s.encodeToByteArray())

    @Test
    fun `walker a permitted list binds only its own forms, and an excluded match is a violation`() {
        val c = assertNotNull(nc(permitted = listOf(dnsName("example.com"))))
        assertEquals(NameConstraints.Result.CONFORMS, c.check(names(PresentedName.dns("a.example.com")), unlimited))
        assertEquals(NameConstraints.Result.VIOLATION, c.check(names(PresentedName.dns("a.other.com")), unlimited))
        assertEquals(
            NameConstraints.Result.CONFORMS,
            c.check(names(PresentedName.Ip(byteArrayOf(192.toByte(), 0, 2, 1))), unlimited),
            "an iPAddress is not bound by a dNSName list",
        )
        assertEquals(NameConstraints.Result.CONFORMS, c.check(names(), unlimited), "no SAN: only the subject")
        val x = assertNotNull(nc(excluded = listOf(dnsName("bad.example"))))
        assertEquals(NameConstraints.Result.VIOLATION, x.check(names(PresentedName.dns("x.bad.example")), unlimited))
        assertEquals(NameConstraints.Result.CONFORMS, x.check(names(PresentedName.dns("good.example")), unlimited))
    }

    @Test
    fun `walker an iPAddress subtree is an address and a mask of the same family`() {
        val v4 = assertNotNull(nc(permitted = listOf(ip(192, 0, 2, 0, 255, 255, 255, 0))))
        assertEquals(
            NameConstraints.Result.CONFORMS,
            v4.check(names(PresentedName.Ip(byteArrayOf(192.toByte(), 0, 2, 9))), unlimited),
        )
        assertEquals(
            NameConstraints.Result.VIOLATION,
            v4.check(names(PresentedName.Ip(byteArrayOf(198.toByte(), 51, 100, 1))), unlimited),
        )
        assertEquals(
            NameConstraints.Result.VIOLATION,
            v4.check(names(PresentedName.Ip(ByteArray(16))), unlimited),
            "IPv6 never matches",
        )
        // A mask octet that is not ones then zeros (0x0f), with no zero octet before it, is malformed on its own.
        val notContiguous = assertNotNull(nc(permitted = listOf(ip(192, 0, 2, 0, 255, 255, 255, 0x0f))))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            notContiguous.check(names(PresentedName.Ip(byteArrayOf(192.toByte(), 0, 2, 0))), unlimited),
        )
        val badMask = assertNotNull(nc(permitted = listOf(ip(192, 0, 2, 0, 255, 0, 255, 0))))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            badMask.check(names(PresentedName.Ip(byteArrayOf(192.toByte(), 0, 2, 9))), unlimited),
        )
    }

    @Test
    fun `walker directoryName and URI subtrees fail closed, and another shared form is a violation`() {
        val dir = assertNotNull(nc(permitted = listOf(TestDer.tlv(0xa4, TestDer.seq()))))
        assertEquals(NameConstraints.Result.VIOLATION, dir.check(names(), unlimited), "every certificate has a subject")
        val excludedDir = assertNotNull(nc(excluded = listOf(TestDer.tlv(0xa4, TestDer.seq()))))
        assertEquals(NameConstraints.Result.VIOLATION, excludedDir.check(names(), unlimited))
        val uri = assertNotNull(nc(permitted = listOf(TestDer.tlv(0x86, TestDer.ascii("https://x")))))
        assertEquals(NameConstraints.Result.CONFORMS, uri.check(names(), unlimited), "no URI presented")
        assertEquals(NameConstraints.Result.VIOLATION, uri.check(names(PresentedName.Uri), unlimited))
        val rfc822 = assertNotNull(nc(permitted = listOf(TestDer.tlv(0x81, TestDer.ascii("a@x")))))
        assertEquals(NameConstraints.Result.VIOLATION, rfc822.check(names(PresentedName.Unsupported(1)), unlimited))
        assertEquals(NameConstraints.Result.CONFORMS, rfc822.check(names(PresentedName.dns("a.x")), unlimited))
    }

    @Test
    fun `walker malformed nameConstraints are unreadable`() {
        assertNull(nc(), "neither field")
        val empty = TestDer.seq(TestDer.tlv(0xa0, TestDer.bytes()))
        assertNull(NameConstraints.read(empty, Span(0, empty.size)), "an empty GeneralSubtrees")
        val withMinimum =
            TestDer.seq(
                TestDer.tlv(0xa0, TestDer.seq(dnsName("x.example"), TestDer.tlv(0x80, TestDer.bytes(0)))),
            )
        assertNull(NameConstraints.read(withMinimum, Span(0, withMinimum.size)), "a minimum written")
        val unknownTag = TestDer.seq(TestDer.tlv(0xa0, TestDer.seq(TestDer.tlv(0x89, TestDer.bytes(1)))))
        assertNull(NameConstraints.read(unknownTag, Span(0, unknownTag.size)))
        assertEquals(NameConstraints.Result.VIOLATION, NameConstraints.UNREADABLE.check(names(), unlimited))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            assertNotNull(nc(excluded = listOf(dnsName("x")))).check(null, unlimited),
            "unreadable SAN",
        )
    }

    @Test
    fun `walker every comparison consumes the budget, and a spent one is EXHAUSTED`() {
        var left = 3
        val budget = ComparisonBudget { if (left == 0) false else true.also { left-- } }
        val c = assertNotNull(nc(permitted = listOf(dnsName("a.example"), dnsName("b.example"))))
        // Two subtrees per name: the first name uses two comparisons, the second one more, then the budget is spent.
        assertEquals(
            NameConstraints.Result.EXHAUSTED,
            c.check(names(PresentedName.dns("a.example"), PresentedName.dns("b.example")), budget),
        )
        assertEquals(0, left)
    }
}
