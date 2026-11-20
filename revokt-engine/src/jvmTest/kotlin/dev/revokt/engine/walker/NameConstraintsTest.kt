// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * #237's name constraints ([NameConstraints], [DnsNameConstraint]) against webpki 0.104.0-alpha.7's rules, read in
 * `subject_name/mod.rs`, `dns_name.rs` and `ip_address.rs`, and the forms that follow mozilla::pkix's `pkixnames.cpp`
 * at Firefox `cac25a6` (`PkixNamesTest`). The cases are written from that code, not copied from its tests.
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

    private fun names(vararg n: PresentedName): List<PresentedName> = n.toList() + PresentedName.Directory(SUBJECT)

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
    fun `walker URI subtrees fail closed, an excluded directoryName refuses all, another shared form is a violation`() {
        val dir = assertNotNull(nc(permitted = listOf(TestDer.tlv(0xa4, TestDer.seq()))))
        assertEquals(NameConstraints.Result.CONFORMS, dir.check(names(), unlimited), "an empty permitted Name: all")
        val excludedDir = assertNotNull(nc(excluded = listOf(TestDer.tlv(0xa4, TestDer.seq()))))
        assertEquals(NameConstraints.Result.VIOLATION, excludedDir.check(names(), unlimited))
        val uri = assertNotNull(nc(permitted = listOf(TestDer.tlv(0x86, TestDer.ascii("https://x")))))
        assertEquals(NameConstraints.Result.CONFORMS, uri.check(names(), unlimited), "no URI presented")
        assertEquals(NameConstraints.Result.VIOLATION, uri.check(names(PresentedName.Uri), unlimited))
        val excludedUri = assertNotNull(nc(excluded = listOf(TestDer.tlv(0x86, TestDer.ascii("https://x")))))
        assertEquals(NameConstraints.Result.VIOLATION, excludedUri.check(names(PresentedName.Uri), unlimited))
        val other = assertNotNull(nc(permitted = listOf(TestDer.tlv(0xa0, TestDer.seq(TestDer.oid("1.2.3"))))))
        assertEquals(NameConstraints.Result.VIOLATION, other.check(names(PresentedName.Unsupported(0)), unlimited))
        assertEquals(NameConstraints.Result.CONFORMS, other.check(names(PresentedName.dns("a.x")), unlimited))
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
    fun `walker the dNSName grammar at its edges`() {
        assertEquals(false, dns("a.example", "a.example.com"), "a presented ID shorter than the constraint")
        assertEquals(false, dns("*.b.c", "abcde", excluded = true), "a wildcard expansion that runs off the constraint")
        assertEquals(true, dns("My-Host_1.Example", "example"), "hyphens, underscores and capitals")
        assertNull(dns("a".repeat(250) + ".com", "com"), "over 253 octets")
        assertNull(dns("*x.example.com", "example.com"), "a wildcard label is * alone")
        assertNull(dns("*", "example.com"))
        assertNull(dns("a" + "1".repeat(63) + ".example", "example"), "a label over 63 octets of digits")
        assertNull(dns("a".repeat(63) + "-b.example", "example"), "a label over 63 octets at a hyphen")
        assertNull(dns("a..example", "example"), "an empty label")
        assertNull(dns("a.example", "a..example"), "an empty label in a constraint")
        assertNull(dns("a-.example", "example"), "a label ending in a hyphen")
        assertNull(dns("example.a-", "a-"), "a last label ending in a hyphen")
    }

    @Test
    fun `walker every GeneralName form maps as pkix's ReadGeneralName does`() {
        for ((tag, number) in listOf(0xa0 to 0, 0xa3 to 3, 0xa5 to 5, 0x88 to 8)) {
            assertEquals(PresentedName.Unsupported(number), PresentedName.general(tag, ByteArray(0)))
        }
        val content = TestDer.ascii("a@x")
        assertContentEquals(content, (PresentedName.general(0xa4, content) as PresentedName.Directory).name)
        assertContentEquals(content, (PresentedName.general(0x81, content) as PresentedName.Rfc822).address)
        assertEquals(PresentedName.Uri, PresentedName.general(0x86, ByteArray(0)))
        assertNull(PresentedName.general(0x89, ByteArray(0)))
    }

    @Test
    fun `walker the subjectAltName reader admits exactly the forms PresentedName maps`() {
        for (tag in 0..0xff) {
            val value = TestDer.seq(TestDer.tlv(tag, TestDer.ascii("a")))
            val read =
                dev.revokt.engine.parse.ExtensionValues
                    .subjectAltName(value, Span(0, value.size))
            assertEquals(
                PresentedName.general(tag, TestDer.ascii("a")) != null,
                read is dev.revokt.engine.parse.ExtensionRead.Value,
                "identifier octet 0x${tag.toString(16)}",
            )
        }
    }

    @Test
    fun `walker a mask that is not octet-aligned, and IPv4 against lists holding IPv6`() {
        val slash12 = assertNotNull(nc(permitted = listOf(ip(10, 16, 0, 0, 255, 240, 0, 0))))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            slash12.check(names(PresentedName.Ip(byteArrayOf(10, 0, 0, 1))), unlimited),
        )
        assertEquals(
            NameConstraints.Result.CONFORMS,
            slash12.check(names(PresentedName.Ip(byteArrayOf(10, 31, 0, 1))), unlimited),
        )
        val v6 = ip(*IntArray(16) { if (it == 0) 0x20 else 0 }, *IntArray(16) { if (it < 2) 0xff else 0 })
        val excludedV6 = assertNotNull(nc(excluded = listOf(v6)))
        assertEquals(
            NameConstraints.Result.CONFORMS,
            excludedV6.check(names(PresentedName.Ip(byteArrayOf(10, 0, 0, 1))), unlimited),
            "an IPv4 name is outside an IPv6 excluded subtree",
        )
        val both = assertNotNull(nc(permitted = listOf(ip(10, 0, 0, 0, 255, 0, 0, 0), v6)))
        assertEquals(
            NameConstraints.Result.CONFORMS,
            both.check(names(PresentedName.Ip(byteArrayOf(10, 0, 0, 1))), unlimited),
            "the IPv6 subtree beside a matching IPv4 one does not refuse the name",
        )
    }

    @Test
    fun `walker comparison errors and spent budgets in either list`() {
        val badPresented = PresentedName.dns("bad..name")
        val permitted = assertNotNull(nc(permitted = listOf(dnsName("example.com"))))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            permitted.check(names(badPresented), unlimited),
            "an error in a permitted list",
        )
        val excluded = assertNotNull(nc(excluded = listOf(dnsName("example.com"))))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            excluded.check(names(badPresented), unlimited),
            "an error in an excluded list",
        )
        assertEquals(
            NameConstraints.Result.EXHAUSTED,
            excluded.check(
                names(
                    PresentedName.dns("a.x"),
                ),
                ComparisonBudget {
                    false
                },
            ),
        )
        val uriOnly = assertNotNull(nc(permitted = listOf(dnsName("example.com"))))
        assertEquals(
            NameConstraints.Result.CONFORMS,
            uriOnly.check(names(PresentedName.Uri), unlimited),
            "a URI skips dNSName subtrees",
        )
    }

    @Test
    fun `walker iPAddress families, lengths and whole-octet masks`() {
        val v6 = ip(*IntArray(16) { if (it == 0) 0x20 else 0 }, *IntArray(16) { if (it < 2) 0xff else 0 })
        val c = assertNotNull(nc(permitted = listOf(v6)))
        assertEquals(
            NameConstraints.Result.CONFORMS,
            c.check(
                names(
                    PresentedName.Ip(
                        ByteArray(16) {
                            if (it ==
                                0
                            ) {
                                0x20
                            } else if (it == 1) {
                                0
                            } else {
                                7
                            }
                        },
                    ),
                ),
                unlimited,
            ),
        )
        assertEquals(
            NameConstraints.Result.VIOLATION,
            c.check(names(PresentedName.Ip(ByteArray(4))), unlimited),
            "IPv4 against IPv6",
        )
        assertEquals(
            NameConstraints.Result.VIOLATION,
            c.check(names(PresentedName.Ip(ByteArray(5))), unlimited),
            "a 5-octet address",
        )
        val odd = assertNotNull(nc(permitted = listOf(ip(10, 0, 0, 0, 255, 0, 0, 0, 0))))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            odd.check(names(PresentedName.Ip(byteArrayOf(10, 1, 2, 3))), unlimited),
            "9 octets",
        )
        val slash8 = assertNotNull(nc(permitted = listOf(ip(10, 0, 0, 0, 255, 0, 0, 0))))
        assertEquals(
            NameConstraints.Result.CONFORMS,
            slash8.check(names(PresentedName.Ip(byteArrayOf(10, 1, 2, 3))), unlimited),
        )
    }

    @Test
    fun `walker a certificate's nameConstraints, one, two, a non-minimal OID arc or an unreadable list`() {
        fun parsed(vararg extensions: ByteArray) = WalkerCerts.parse(TestCert(extensions = extensions.toList()).der)
        val one = WalkerFixturesAs.nameConstraints(permitted = listOf(dnsName("example.com")))
        assertNotNull(NameConstraints.of(parsed(one))).let { assertEquals(false, it === NameConstraints.UNREADABLE) }
        assertEquals(NameConstraints.UNREADABLE, NameConstraints.of(parsed(one, one)))
        val nonMinimal =
            TestDer.seq(
                TestDer.tlv(0x06, TestDer.bytes(0x55, 0x1d, 0x80, 0x1e)),
                TestDer.tlv(0x04, TestDer.seq()),
            )
        val read = NameConstraints.of(parsed(nonMinimal))
        assertEquals(true, read == null || read === NameConstraints.UNREADABLE, "never read as a constraint")
        val emptyExcluded = TestDer.seq(TestDer.tlv(0xa1, TestDer.bytes()))
        assertNull(NameConstraints.read(emptyExcluded, Span(0, emptyExcluded.size)))
        val inner = TestDer.tlv(0xa0, TestDer.seq(dnsName("x.example")))
        val longForm = byteArrayOf(0x30, 0x81.toByte(), inner.size.toByte()) + inner
        assertNull(NameConstraints.read(longForm, Span(0, longForm.size)), "a non-minimal length")
        assertEquals(
            NameConstraints.UNREADABLE,
            NameConstraints.of(parsed(TestDer.extension("2.5.29.30", TestDer.seq()))),
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

    private companion object {
        /** `CN=leaf.example`, a UTF8String. */
        val SUBJECT: ByteArray =
            TestDer.seq(
                TestDer.tlv(
                    0x31,
                    TestDer.seq(TestDer.oid("2.5.4.3"), TestDer.tlv(0x0c, TestDer.ascii("leaf.example"))),
                ),
            )
    }
}
