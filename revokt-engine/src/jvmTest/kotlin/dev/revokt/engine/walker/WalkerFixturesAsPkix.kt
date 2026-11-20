// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.NoIssuerReason
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.engine.walker.FixtureWorld.Companion.PRINTABLE_STRING
import dev.revokt.engine.walker.FixtureWorld.Companion.UTF8_STRING
import dev.revokt.engine.walker.WalkerFixturesAs.dns
import dev.revokt.engine.walker.WalkerFixturesAs.nameConstraints
import dev.revokt.engine.walker.WalkerFixturesAs.san

/**
 * Row (as), the forms that follow mozilla::pkix (`pkixnames.cpp` at Firefox `cac25a6`): directoryName subtrees
 * against the subject and any subjectAltName directoryName, rfc822Name subtrees against subjectAltName mailboxes and,
 * without a subjectAltName, the subject's emailAddress attributes, and the CN-ID of a serverAuth leaf whose
 * subjectAltName holds no dNSName or iPAddress. leaf → I → R with the constraints on I unless a case says otherwise.
 */
internal object WalkerFixturesAsPkix {
    private const val CN = "2.5.4.3"
    private const val O = "2.5.4.10"
    private const val EMAIL = "1.2.840.113549.1.9.1"
    private const val IA5_STRING = 0x16
    private const val BMP_STRING = 0x1e

    fun rdn(
        oid: String,
        value: String,
        tag: Int = UTF8_STRING,
    ): ByteArray = TestDer.tlv(0x31, TestDer.seq(TestDer.oid(oid), TestDer.tlv(tag, TestDer.ascii(value))))

    fun name(vararg rdns: ByteArray): ByteArray = TestDer.seq(*rdns)

    fun dirName(vararg rdns: ByteArray): ByteArray = TestDer.tlv(0xa4, name(*rdns))

    fun email(address: String): ByteArray = TestDer.tlv(0x81, TestDer.ascii(address))

    fun ip(vararg b: Int): ByteArray = TestDer.tlv(0x87, TestDer.bytes(*b))

    private val leafCn = rdn(CN, "leaf.example")

    fun all(): List<WalkerFixture> = directoryName() + rfc822Name() + emailFallback() + commonName() + anchorDn()

    /** One case: the leaf's [leafExtensions] and [leafSubject], I's nameConstraints [nc], and whether I is accepted. */
    private class Case(
        val variant: String,
        val nc: ByteArray,
        val passes: Boolean,
        val leafExtensions: List<ByteArray> = listOf(san(dns("leaf.example"))),
        val leafSubject: ByteArray? = null,
    )

    private fun fixtures(cases: List<Case>): List<WalkerFixture> =
        cases.map { c ->
            val h =
                Honest(
                    leafExtensions = c.leafExtensions,
                    intermediateExtensions = listOf(c.nc),
                    leafSubject = c.leafSubject,
                )
            h.fixture(
                "as",
                c.variant,
                presented = listOf(h.leaf, h.intermediate),
                walk =
                    if (c.passes) {
                        found(h.path).copy(verifications = 2, candidatesExplored = 2)
                    } else {
                        notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 0, candidatesExplored = 1)
                    },
            )
        }

    /** The leaf's subject is `CN=leaf.example`, a UTF8String; a permitted Name must be a prefix of it, AVA by AVA. */
    private fun directoryName(): List<WalkerFixture> =
        fixtures(
            listOf(
                Case("permitted directoryName, the leaf's subject", nameConstraints(listOf(dirName(leafCn))), true),
                Case(
                    "permitted directoryName, the subject as a PrintableString",
                    nameConstraints(listOf(dirName(rdn(CN, "leaf.example", PRINTABLE_STRING)))),
                    true,
                ),
                Case("permitted directoryName, the empty Name", nameConstraints(listOf(dirName())), true),
                Case(
                    "permitted directoryName, another case",
                    nameConstraints(listOf(dirName(rdn(CN, "LEAF.EXAMPLE")))),
                    false,
                ),
                Case(
                    "permitted directoryName, longer than the subject",
                    nameConstraints(listOf(dirName(leafCn, rdn(O, "Example")))),
                    false,
                ),
                Case(
                    "permitted directoryName, one of two",
                    nameConstraints(listOf(dirName(rdn(CN, "other.example")), dirName(leafCn))),
                    true,
                ),
                Case(
                    "excluded directoryName, another Name",
                    nameConstraints(excluded = listOf(dirName(rdn(CN, "other.example")))),
                    false,
                ),
                Case("excluded directoryName, the empty Name", nameConstraints(excluded = listOf(dirName())), false),
                Case(
                    "a subjectAltName directoryName outside the permitted Name",
                    nameConstraints(listOf(dirName(leafCn))),
                    false,
                    leafExtensions = listOf(san(dns("leaf.example"), dirName(rdn(CN, "other.example")))),
                ),
            ),
        )

    /** The leaf's subjectAltName holds `leaf.example` and the mailbox `user@mail.example`. */
    private fun rfc822Name(): List<WalkerFixture> {
        val mailbox = listOf(san(dns("leaf.example"), email("user@mail.example")))
        return fixtures(
            listOf(
                Case("permitted rfc822Name, the host", nameConstraints(listOf(email("mail.example"))), true, mailbox),
                Case("permitted rfc822Name, a domain", nameConstraints(listOf(email(".example"))), true, mailbox),
                Case(
                    "permitted rfc822Name, the parent host",
                    nameConstraints(listOf(email("example"))),
                    false,
                    mailbox,
                ),
                Case(
                    "permitted rfc822Name, the mailbox in another case",
                    nameConstraints(listOf(email("USER@Mail.Example"))),
                    true,
                    mailbox,
                ),
                Case(
                    "permitted rfc822Name, another mailbox",
                    nameConstraints(listOf(email("other@mail.example"))),
                    false,
                    mailbox,
                ),
                Case(
                    "excluded rfc822Name, the host",
                    nameConstraints(excluded = listOf(email("mail.example"))),
                    false,
                    mailbox,
                ),
                Case(
                    "permitted rfc822Name, an invalid presented mailbox",
                    nameConstraints(listOf(email("mail.example"))),
                    false,
                    listOf(san(dns("leaf.example"), email("user..x@mail.example"))),
                ),
            ),
        )
    }

    /** No subjectAltName: the subject's emailAddress attributes are the rfc822Names (its CN-ID binds no rfc822Name). */
    private fun emailFallback(): List<WalkerFixture> {
        fun subject(tag: Int) = name(leafCn, rdn(EMAIL, "user@mail.example", tag))
        return fixtures(
            listOf(
                Case(
                    "no subjectAltName, the subject's emailAddress inside",
                    nameConstraints(listOf(email("mail.example"))),
                    true,
                    emptyList(),
                    subject(IA5_STRING),
                ),
                Case(
                    "no subjectAltName, the subject's emailAddress outside",
                    nameConstraints(listOf(email("other.example"))),
                    false,
                    emptyList(),
                    subject(IA5_STRING),
                ),
                Case(
                    "no subjectAltName, an emailAddress that is not an IA5String",
                    nameConstraints(listOf(email("mail.example"))),
                    false,
                    emptyList(),
                    subject(UTF8_STRING),
                ),
                Case(
                    "a subjectAltName: the subject's emailAddress is not presented",
                    nameConstraints(listOf(email("other.example"))),
                    true,
                    leafSubject = subject(IA5_STRING),
                ),
            ),
        )
    }

    /** A serverAuth leaf whose subjectAltName has no dNSName or iPAddress presents its last CN as a CN-ID. */
    private fun commonName(): List<WalkerFixture> {
        val other = nameConstraints(listOf(dns("other.example")))
        return fixtures(
            listOf(
                Case("no subjectAltName, the CN-ID outside", other, false, emptyList()),
                Case(
                    "no subjectAltName, the CN-ID inside",
                    nameConstraints(listOf(dns("leaf.example"))),
                    true,
                    emptyList(),
                ),
                Case(
                    "a subjectAltName of a mailbox only, the CN-ID outside",
                    other,
                    false,
                    listOf(san(email("user@mail.example"))),
                ),
                Case(
                    "an IPv4 CN-ID outside",
                    nameConstraints(listOf(ip(198, 51, 100, 0, 255, 255, 255, 0))),
                    false,
                    emptyList(),
                    name(rdn(CN, "192.0.2.1", PRINTABLE_STRING)),
                ),
                Case(
                    "an IPv4 CN-ID inside",
                    nameConstraints(listOf(ip(192, 0, 2, 0, 255, 255, 255, 0))),
                    true,
                    emptyList(),
                    name(rdn(CN, "192.0.2.1", PRINTABLE_STRING)),
                ),
                Case(
                    "the last of two CNs inside",
                    nameConstraints(listOf(dns("leaf.example"))),
                    true,
                    emptyList(),
                    name(rdn(CN, "other.example"), leafCn),
                ),
                Case(
                    "the last of two CNs outside",
                    nameConstraints(listOf(dns("leaf.example"))),
                    false,
                    emptyList(),
                    name(leafCn, rdn(CN, "other.example")),
                ),
                Case("a BMPString CN is no CN-ID", other, true, emptyList(), name(rdn(CN, "leaf.example", BMP_STRING))),
                Case("a CN that is no host name", other, true, emptyList(), name(rdn(CN, "Leaf Server"))),
            ),
        )
    }

    /**
     * An anchor R permitting the Name `O=Example` binds I and the leaf below it: both inside → `Found`; the leaf or I
     * outside → `UNANCHORED` after the leaf's link.
     */
    private fun anchorDn(): List<WalkerFixture> =
        listOf(
            Triple("an anchor's directoryName, both inside", "Example", "Example"),
            Triple("an anchor's directoryName, the leaf outside", "Other", "Example"),
            Triple("an anchor's directoryName, the intermediate outside", "Example", "Other"),
        ).map { (variant, leafO, intermediateO) ->
            val w = FixtureWorld()
            val rootName = name(rdn(O, "Example"), rdn(CN, "Root"))
            val key = w.key()
            val root =
                w.cert(
                    "R",
                    rootName,
                    rootName,
                    key,
                    signer = key,
                    extensions = listOf(nameConstraints(listOf(dirName(rdn(O, "Example"))))),
                )
            val i = w.cert("I", name(rdn(O, intermediateO), rdn(CN, "Intermediate")), rootName, signer = key)
            val leaf =
                w.cert(
                    "L",
                    name(rdn(O, leafO), leafCn),
                    i.subject,
                    signer = i.key,
                    key = w.leafKey(),
                    extensions = listOf(san(dns("leaf.example"))),
                )
            val passes = leafO == "Example" && intermediateO == "Example"
            w.fixture(
                "as",
                variant,
                listOf(leaf, i),
                listOf(root),
                if (passes) {
                    found(listOf(leaf, i, root)).copy(verifications = 2, candidatesExplored = 2)
                } else {
                    notFound(NoIssuerReason.UNANCHORED).copy(verifications = 1, candidatesExplored = 2)
                },
            )
        }
}
