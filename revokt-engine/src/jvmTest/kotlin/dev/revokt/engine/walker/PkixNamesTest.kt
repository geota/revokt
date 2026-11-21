// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.FallbackReason
import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.PathStatus
import dev.revokt.RevoktTestingApi
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.engine.walker.FixtureWorld.Companion.PRINTABLE_STRING
import dev.revokt.engine.walker.FixtureWorld.Companion.TELETEX_STRING
import dev.revokt.engine.walker.FixtureWorld.Companion.UTF8_STRING
import dev.revokt.engine.walker.WalkerFixturesAs.dns
import dev.revokt.engine.walker.WalkerFixturesAs.nameConstraints
import dev.revokt.engine.walker.WalkerFixturesAs.san
import dev.revokt.engine.walker.WalkerFixturesAsPkix.dirName
import dev.revokt.engine.walker.WalkerFixturesAsPkix.email
import dev.revokt.engine.walker.WalkerFixturesAsPkix.name
import dev.revokt.engine.walker.WalkerFixturesAsPkix.rdn
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The name-constraint forms that follow mozilla::pkix ([DirectoryNameConstraint], [Rfc822NameConstraint],
 * [SubjectNames]), against `pkixnames.cpp` at Firefox `cac25a6`. The cases are written from that code, not copied from
 * its tests.
 */
class PkixNamesTest {
    private val unlimited = ComparisonBudget { true }

    private fun permits(
        presented: ByteArray,
        constraint: ByteArray,
        budget: ComparisonBudget = unlimited,
    ): NameMatch = DirectoryNameConstraint.permits(presented, constraint, budget)

    private fun ava(
        oid: String,
        tag: Int,
        value: String,
    ): ByteArray = TestDer.seq(TestDer.oid(oid), TestDer.tlv(tag, TestDer.ascii(value)))

    private fun set(vararg avas: ByteArray): ByteArray = TestDer.tlv(0x31, avas.reduce(ByteArray::plus))

    @Test
    fun `walker a permitted directoryName is an RDN prefix of the presented Name`() {
        val c = rdn(CN, "a")
        val o = rdn(O, "Example")
        assertEquals(NameMatch.YES, permits(name(o, c), name(o)), "a prefix")
        assertEquals(NameMatch.YES, permits(name(o, c), name(o, c)), "equal")
        assertEquals(NameMatch.NO, permits(name(o), name(o, c)), "longer than the presented Name")
        assertEquals(NameMatch.NO, permits(name(c, o), name(o)), "not at the front")
        assertEquals(NameMatch.YES, permits(name(), name()), "the empty Name is inside the empty Name")
        assertEquals(NameMatch.YES, permits(name(o), name()), "the empty Name holds every Name")
        assertEquals(NameMatch.NO, permits(name(), name(o)), "an empty subject is outside a non-empty Name")
    }

    @Test
    fun `walker AVAs are compared byte for byte, UTF8String and PrintableString alike`() {
        assertEquals(NameMatch.YES, permits(name(rdn(CN, "a", PRINTABLE_STRING)), name(rdn(CN, "a", UTF8_STRING))))
        assertEquals(NameMatch.YES, permits(name(rdn(CN, "a", UTF8_STRING)), name(rdn(CN, "a", PRINTABLE_STRING))))
        assertEquals(NameMatch.NO, permits(name(rdn(CN, "a", TELETEX_STRING)), name(rdn(CN, "a", UTF8_STRING))))
        assertEquals(NameMatch.NO, permits(name(rdn(CN, "a", UTF8_STRING)), name(rdn(CN, "a", TELETEX_STRING))))
        assertEquals(NameMatch.YES, permits(name(rdn(CN, "a", TELETEX_STRING)), name(rdn(CN, "a", TELETEX_STRING))))
        assertEquals(NameMatch.NO, permits(name(rdn(CN, "A")), name(rdn(CN, "a"))), "no case folding")
        assertEquals(NameMatch.NO, permits(name(rdn(CN, "a ")), name(rdn(CN, "a"))), "no whitespace folding")
        assertEquals(NameMatch.NO, permits(name(rdn(O, "a")), name(rdn(CN, "a"))), "another type")
    }

    @Test
    fun `walker a multi-valued RDN is compared in encoded order and must hold as many AVAs`() {
        val x = ava(CN, UTF8_STRING, "x")
        val y = ava(O, UTF8_STRING, "y")
        assertEquals(NameMatch.YES, permits(name(set(x, y)), name(set(x, y))))
        assertEquals(NameMatch.NO, permits(name(set(y, x)), name(set(x, y))), "not compared as a set")
        assertEquals(NameMatch.NO, permits(name(set(x, y)), name(set(x))), "fewer AVAs in the constraint")
        assertEquals(NameMatch.NO, permits(name(set(x)), name(set(x, y))), "more AVAs in the constraint")
    }

    @Test
    fun `walker a malformed Name is an error only where the comparison reads it`() {
        val good = name(rdn(CN, "a"))
        assertEquals(NameMatch.ERROR, permits(good, good + byteArrayOf(0)), "a constraint with trailing data")
        assertEquals(NameMatch.ERROR, permits(good + byteArrayOf(0), good), "a presented Name with trailing data")
        assertEquals(NameMatch.ERROR, permits(TestDer.tlv(0x31, ByteArray(0)), good), "not a SEQUENCE")
        assertEquals(NameMatch.ERROR, permits(good, TestDer.tlv(0x31, ByteArray(0))), "a constraint not a SEQUENCE")
        val notSet = TestDer.seq(TestDer.seq(ava(CN, UTF8_STRING, "a")))
        assertEquals(NameMatch.ERROR, permits(notSet, good), "an RDN that is not a SET")
        val noOid =
            TestDer.seq(
                set(TestDer.seq(TestDer.tlv(0x0c, TestDer.ascii("a")), TestDer.tlv(0x0c, TestDer.ascii("a")))),
            )
        assertEquals(NameMatch.ERROR, permits(noOid, good), "an AVA without an OID")
        val extra =
            TestDer.seq(
                set(TestDer.seq(TestDer.oid(CN), TestDer.tlv(0x0c, TestDer.ascii("a")), TestDer.bytes(5, 0))),
            )
        assertEquals(NameMatch.ERROR, permits(extra, good), "an AVA with a third element")
        // The tail after a matched prefix is never read, as pkix never reads it.
        val badTail = TestDer.seq(rdn(CN, "a"), TestDer.bytes(0x31, 0x05))
        assertEquals(NameMatch.YES, permits(badTail, name()), "the empty Name reads nothing of the presented RDNs")
        assertEquals(NameMatch.YES, permits(TestDer.seq(rdn(CN, "a"), TestDer.tlv(0x31, ByteArray(0))), good))
        val inner = rdn(CN, "a")
        val longForm = byteArrayOf(0x30, 0x81.toByte(), inner.size.toByte()) + inner
        assertEquals(NameMatch.ERROR, permits(longForm, good), "a non-minimal length")
        assertEquals(NameMatch.ERROR, permits(good, longForm), "a non-minimal length in the constraint")
    }

    @Test
    fun `walker every AVA pair compared costs one unit`() {
        var used = 0
        val counting = ComparisonBudget { true.also { used++ } }
        val three = name(rdn(O, "a"), rdn(O, "b"), rdn(CN, "c"))
        assertEquals(NameMatch.YES, permits(three, three, counting))
        assertEquals(3, used)
        var left = 2
        val two = ComparisonBudget { if (left == 0) false else true.also { left-- } }
        assertEquals(NameMatch.EXHAUSTED, permits(three, three, two))
        assertEquals(0, left)
        // Through NameConstraints: one unit for the subtree, then one per AVA pair.
        val c = assertNotNull(read(nameConstraints(listOf(dirName(rdn(O, "a"), rdn(O, "b"))))))
        used = 0
        assertEquals(NameConstraints.Result.CONFORMS, c.check(listOf(PresentedName.Directory(three)), counting))
        assertEquals(3, used)
        left = 2
        assertEquals(
            NameConstraints.Result.EXHAUSTED,
            c.check(listOf(PresentedName.Directory(three)), two),
            "spent on the second AVA pair",
        )
    }

    @Test
    fun `walker an excluded directoryName refuses every Name, an empty one included`() {
        for (subtree in listOf(dirName(), dirName(rdn(CN, "other")), TestDer.tlv(0xa4, TestDer.bytes(5, 0)))) {
            val c = assertNotNull(read(nameConstraints(excluded = listOf(subtree))))
            assertEquals(NameConstraints.Result.VIOLATION, c.check(listOf(PresentedName.Directory(name())), unlimited))
            assertEquals(
                NameConstraints.Result.VIOLATION,
                c.check(listOf(PresentedName.Directory(name(rdn(CN, "a")))), unlimited),
            )
        }
    }

    private fun mail(
        presented: String,
        constraint: String,
        excluded: Boolean = false,
    ): Boolean? = Rfc822NameConstraint.matches(presented.encodeToByteArray(), constraint.encodeToByteArray(), excluded)

    @Test
    fun `walker a mailbox constraint matches the whole address, ignoring ASCII case`() {
        assertEquals(true, mail("user@example.com", "user@example.com"))
        assertEquals(true, mail("User@Example.COM", "uSER@example.com"), "the local part too")
        assertEquals(false, mail("user@example.com", "other@example.com"))
        assertEquals(false, mail("user@example.com", "user@sub.example.com"))
        assertEquals(false, mail("user@sub.example.com", "user@example.com"))
        assertEquals(false, mail("us@example.com", "user@example.com"))
        assertEquals(false, mail("user@example.co", "user@example.com"), "a prefix of the mailbox")
        assertEquals(false, mail("user@example.com", "user@example.co"))
        assertEquals(true, mail("*@example.com", "*@example.com"), "* is a literal")
        assertEquals(false, mail("user@example.com", "*@example.com"))
        assertNull(mail("user@example.com", "invalid@invalid@example.com"), "an invalid mailbox constraint")
        assertNull(mail("user@example.com", "@example.com"))
    }

    @Test
    fun `walker a host constraint matches that host only, a leading dot its subdomains only`() {
        assertEquals(true, mail("user@example.com", "example.com"))
        assertEquals(true, mail("user@EXAMPLE.com", "example.COM"))
        assertEquals(false, mail("user@sub.example.com", "example.com"), "no dotless subdomain match")
        assertEquals(false, mail("user@badexample.com", "example.com"))
        assertEquals(true, mail("user@sub.example.com", ".example.com"))
        assertEquals(false, mail("user@example.com", ".example.com"), "a leading dot: not the host")
        assertEquals(true, mail("user@example.com", ""), "an empty constraint covers every mailbox")
        assertEquals(false, mail("user@example.com.au", "example.com"))
        assertNull(mail("user@example.com", "*.example.com"), "an invalid host constraint")
        assertNull(mail("user@example.com", "example..com"))
        assertEquals(false, mail("user@example.com", "user.example.com"))
    }

    @Test
    fun `walker a presented mailbox must be valid`() {
        for (bad in listOf(
            "user..x@example.com",
            ".user@example.com",
            "user.@example.com",
            "@example.com",
            "user",
            "user@",
            "user@@example.com",
            "\"user\"@example.com",
            "us er@example.com",
            "user@*.example.com",
            "user@example.com.",
            "user@-x.example.com",
            "user@example.123",
            "usér@example.com",
        )) {
            assertNull(mail(bad, "example.com"), bad)
            assertEquals(false, Rfc822NameConstraint.valid(bad.encodeToByteArray()), bad)
        }
        assertEquals(true, Rfc822NameConstraint.valid("a.b!#\$%&'*+-/=?^_`{|}~9Z@x_y.example".encodeToByteArray()))
        assertEquals(true, mail("user@example.com", "user@example.com", excluded = true))
    }

    @Test
    fun `walker the IPv4 reader takes four components of 0 to 255 without leading zeros`() {
        fun v4(s: String) = SubjectNames.ipv4(s.encodeToByteArray())?.map { it.toInt() and 0xff }
        assertEquals(listOf(192, 0, 2, 1), v4("192.0.2.1"))
        assertEquals(listOf(0, 0, 0, 0), v4("0.0.0.0"))
        assertEquals(listOf(255, 255, 255, 255), v4("255.255.255.255"))
        for (bad in listOf(
            "256.0.0.1",
            "01.2.3.4",
            "1.2.3.04",
            "00.1.2.3",
            "1.2.3",
            "1.2.3.4.5",
            "1..2.3",
            ".1.2.3",
            "1.2.3.",
            "1.2.3.a",
            "",
            "1.2.3.4 ",
        )) {
            assertNull(v4(bad), bad)
        }
    }

    private fun parsed(
        subject: ByteArray,
        vararg extensions: ByteArray,
    ) = WalkerCerts.parse(TestCert(subject = subject, extensions = extensions.toList()).der)

    @Test
    fun `walker the subject's emailAddress attributes are presented only without a subjectAltName`() {
        val subject = name(rdn(CN, "x"), rdn(EMAIL, "a@mail.example", IA5), rdn(EMAIL, "b@mail.example", IA5))
        val names = assertNotNull(PresentedName.of(parsed(subject), commonName = false))
        assertEquals(3, names.size)
        assertContentEquals(subject, assertIs<PresentedName.Directory>(names[0]).name)
        assertContentEquals(TestDer.ascii("a@mail.example"), assertIs<PresentedName.Rfc822>(names[1]).address)
        assertContentEquals(TestDer.ascii("b@mail.example"), assertIs<PresentedName.Rfc822>(names[2]).address)
        val withSan = assertNotNull(PresentedName.of(parsed(subject, san(dns("x.example"))), commonName = false))
        assertEquals(2, withSan.size, "a subjectAltName: the dNSName and the subject only")
        assertNull(
            PresentedName.of(parsed(name(rdn(EMAIL, "a@mail.example", UTF8_STRING))), commonName = false),
            "not an IA5String",
        )
        assertNotNull(
            PresentedName.of(
                parsed(name(rdn(EMAIL, "a@mail.example", UTF8_STRING)), san(dns("x.example"))),
                commonName = false,
            ),
        )
    }

    @Test
    fun `walker the CN-ID is the last CN, a host name or an IPv4 address, for the leaf of a serverAuth request`() {
        fun cnId(
            subject: ByteArray,
            vararg extensions: ByteArray,
        ): PresentedName? {
            val p = parsed(subject, *extensions)
            val plain = assertNotNull(PresentedName.of(p, commonName = false))
            val leaf = assertNotNull(PresentedName.of(p, commonName = true))
            return if (leaf.size == plain.size) null else leaf.last()
        }
        val host = assertIs<PresentedName.Dns>(cnId(name(rdn(CN, "a.example"), rdn(CN, "b.example"))))
        assertContentEquals(TestDer.ascii("b.example"), host.id, "the last CN")
        assertContentEquals(
            TestDer.ascii("a.example"),
            assertIs<PresentedName.Dns>(
                cnId(name(set(ava(CN, UTF8_STRING, "a.example"), ava(O, UTF8_STRING, "x")))),
            ).id,
        )
        assertIs<PresentedName.Dns>(
            cnId(name(rdn(CN, "*.leaf.example", TELETEX_STRING))),
            "a wildcard, a TeletexString",
        )
        assertIs<PresentedName.Dns>(cnId(name(rdn(CN, "a.example", PRINTABLE_STRING))))
        val v4 = assertIs<PresentedName.Ip>(cnId(name(rdn(CN, "192.0.2.1"))))
        assertContentEquals(byteArrayOf(192.toByte(), 0, 2, 1), v4.address)
        assertNull(cnId(name(rdn(CN, "a.example", 0x1e))), "a BMPString")
        assertNull(cnId(name(rdn(CN, "a.example", 0x1c))), "a UniversalString")
        assertNull(cnId(name(rdn(CN, "a.example"), rdn(CN, "a.example", 0x1e))), "the last CN is a BMPString")
        assertNull(cnId(name(rdn(CN, "2001:db8::1"))), "no IPv6 CN-ID")
        assertNull(cnId(name(rdn(CN, "Some Server"))))
        assertNull(cnId(name(rdn(O, "a.example"))), "no CN")
        assertNull(cnId(name(rdn(CN, "a.example")), san(dns("b.example"))), "beside a subjectAltName dNSName")
        assertNull(
            cnId(name(rdn(CN, "a.example")), san(TestDer.tlv(0x87, TestDer.bytes(192, 0, 2, 1)))),
            "an iPAddress",
        )
        assertIs<PresentedName.Dns>(cnId(name(rdn(CN, "a.example")), san(email("a@mail.example"))), "a mailbox only")
    }

    @Test
    fun `walker a subject that must be walked and does not read fails closed`() {
        val emptyRdn = TestDer.seq(rdn(CN, "a.example"), TestDer.tlv(0x31, ByteArray(0)))
        assertNull(PresentedName.of(parsed(emptyRdn), commonName = false), "an empty RDN, no subjectAltName")
        assertNull(PresentedName.of(parsed(emptyRdn, san(email("a@mail.example"))), commonName = true), "for the CN-ID")
        assertNotNull(PresentedName.of(parsed(emptyRdn, san(dns("a.example"))), commonName = true), "never walked")
        val notSet = TestDer.seq(TestDer.seq(ava(CN, UTF8_STRING, "a.example")))
        assertNull(PresentedName.of(parsed(notSet), commonName = false))
        assertNotNull(PresentedName.of(parsed(name()), commonName = false), "an empty subject reads")
        assertNull(SubjectNames.avas(byteArrayOf(0x30, 0x81.toByte(), 0x00)), "a non-minimal length")
        val atLimit = name(rdn(CN, "a"))
        assertNull(SubjectNames.avas(atLimit + byteArrayOf(0)), "trailing data")
        assertNull(SubjectNames.avas(TestDer.tlv(0x31, ByteArray(0))), "not a SEQUENCE")
    }

    @Test
    fun `walker the CN-ID binds a serverAuth leaf only, not a clientAuth one and not an intermediate`() {
        val other = nameConstraints(listOf(dns("other.example")))
        val f =
            with(Honest(intermediateExtensions = listOf(other))) {
                fixture(
                    "cn",
                    presented = listOf(leaf, intermediate),
                    walk = notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                )
            }
        val server = WalkerHarness.decide(f, null).path
        assertEquals(PathStatus.NO_ISSUER, server.status)
        assertEquals(NoIssuerReason.ALL_CANDIDATES_INVALID, server.noIssuerReason)
        assertEquals(PathStatus.FOUND, WalkerHarness.decide(f, null, requiredEku = RequiredEku.CLIENT_AUTH).path.status)
        // An intermediate named CN=leaf.example under a root permitting other.example presents no CN-ID.
        val w = FixtureWorld()
        val rootName = w.name("Root")
        val key = w.key()
        val root = w.cert("R", rootName, rootName, key, signer = key, extensions = listOf(other))
        val i = w.cert("I", w.name("ca.example"), rootName, signer = key)
        val leaf =
            w.cert(
                "L",
                w.name("l"),
                i.subject,
                signer = i.key,
                key = w.leafKey(),
                extensions = listOf(san(dns("x.other.example"))),
            )
        val g = w.fixture("cn-ca", "", listOf(leaf, i), listOf(root), notFound(NoIssuerReason.UNANCHORED))
        assertEquals(PathStatus.FOUND, WalkerHarness.decide(g, null).path.status)
    }

    @OptIn(RevoktTestingApi::class)
    @Test
    fun `walker a fallback path is checked with the same forms, the CN-ID included`() {
        fun notUsed(reason: FallbackReason) =
            Finding.FallbackNotUsed
                .Builder()
                .reason(reason)
                .build()
        for ((nc, leafExtensions, admitted) in listOf(
            Triple(nameConstraints(listOf(dns("other.example"))), emptyList<ByteArray>(), false),
            Triple(nameConstraints(listOf(dns("leaf.example"))), emptyList(), true),
            Triple(nameConstraints(listOf(dirName(rdn(CN, "other")))), listOf(san(dns("leaf.example"))), false),
            Triple(nameConstraints(listOf(dirName(rdn(CN, "leaf.example")))), listOf(san(dns("leaf.example"))), true),
            Triple(nameConstraints(listOf(email("other.example"))), listOf(san(email("a@mail.example"))), false),
        )) {
            with(Honest(leafExtensions = leafExtensions, intermediateExtensions = listOf(nc))) {
                val alone = fixture("fb-pkix", presented = listOf(leaf), walk = notFound(NoIssuerReason.NO_CANDIDATE))
                val d = WalkerHarness.decide(alone, FakeFallback.finds(leaf, intermediate, root))
                if (admitted) {
                    assertEquals(PathStatus.FOUND, d.path.status)
                } else {
                    assertEquals(PathStatus.NO_ISSUER, d.path.status)
                    assertEquals(listOf(notUsed(FallbackReason.FAILED)), d.findings)
                }
                val client =
                    WalkerHarness.decide(
                        alone,
                        FakeFallback.finds(leaf, intermediate, root),
                        requiredEku = RequiredEku.CLIENT_AUTH,
                    )
                if (leafExtensions.isEmpty()) {
                    assertEquals(
                        PathStatus.FOUND,
                        client.path.status,
                        "no CN-ID for clientAuth",
                    )
                }
            }
        }
        // An intermediate named CN=ca.example under an anchor permitting other.example presents no CN-ID.
        val w = FixtureWorld()
        val rootName = w.name("Root")
        val key = w.key()
        val other = nameConstraints(listOf(dns("other.example")))
        val root = w.cert("R", rootName, rootName, key, signer = key, extensions = listOf(other))
        val i = w.cert("I", w.name("ca.example"), rootName, signer = key)
        val leaf =
            w.cert(
                "L",
                w.name("l"),
                i.subject,
                signer = i.key,
                key = w.leafKey(),
                extensions = listOf(san(dns("x.other.example"))),
            )
        val alone = w.fixture("fb-cn-ca", "", listOf(leaf), listOf(root), notFound(NoIssuerReason.NO_CANDIDATE))
        assertEquals(PathStatus.FOUND, WalkerHarness.decide(alone, FakeFallback.finds(leaf, i, root)).path.status)
    }

    /** The nameConstraints [extension] as a certificate carries it; null when unreadable. */
    private fun read(extension: ByteArray): NameConstraints? {
        val p = WalkerCerts.parse(TestCert(extensions = listOf(extension)).der)
        return NameConstraints.of(p).takeIf { it !== NameConstraints.UNREADABLE }
    }

    @Test
    fun `walker a directoryName or rfc822Name base reads, and a malformed one fails only when compared`() {
        val v =
            TestDer.seq(
                TestDer.tlv(
                    0xa0,
                    TestDer.seq(TestDer.tlv(0xa4, TestDer.bytes(1, 2))) + TestDer.seq(email("@")),
                ),
            )
        val c = assertNotNull(NameConstraints.read(v, Span(0, v.size)))
        assertEquals(NameConstraints.Result.VIOLATION, c.check(listOf(PresentedName.Directory(name())), unlimited))
        assertEquals(
            NameConstraints.Result.VIOLATION,
            c.check(listOf(PresentedName.Rfc822(TestDer.ascii("a@x.example"))), unlimited),
        )
        assertEquals(
            NameConstraints.Result.CONFORMS,
            c.check(listOf(PresentedName.Dns(TestDer.ascii("x.example"))), unlimited),
        )
    }

    private companion object {
        const val CN = "2.5.4.3"
        const val O = "2.5.4.10"
        const val EMAIL = "1.2.840.113549.1.9.1"
        const val IA5 = 0x16
    }
}
