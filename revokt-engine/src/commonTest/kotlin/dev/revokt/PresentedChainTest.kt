// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * `PresentedChain` as spec §4 declares it (#120): fields from revokt's own parse, every presented certificate at its
 * presented index (the maintainer's reading A), value semantics and fresh copies.
 */
@OptIn(RevoktTestingApi::class)
class PresentedChainTest {
    private val san = "2.5.29.17"

    private fun sanOf(vararg names: ByteArray) = TestDer.extension(san, seq(*names))

    private val leaf =
        TestCert(
            serial = tlv(0x02, bytes(0x00, 0x8f, 0x12, 0x34)),
            subject = TestCert.name("leaf.example"),
            issuer = TestCert.name("Test CA"),
            extensions =
                listOf(
                    sanOf(
                        tlv(0x82, ascii("a.example")),
                        tlv(0x86, ascii("https://a.example/")),
                        tlv(0x82, ascii("B.Example.")),
                    ),
                ),
        )
    private val ca = TestCert(serial = tlv(0x02, bytes(0x01)), subject = TestCert.name("Test CA"))

    private fun chain(vararg certs: TestCert): PresentedChain =
        PresentedChain
            .Builder()
            .certificates(certs.map { it.der })
            .build()

    @Test
    fun `the fields are revokt's parse of each certificate, leaf first`() {
        val c = chain(leaf, ca)
        assertEquals(2, c.size)
        assertContentEquals(leaf.der, c.der(0))
        assertContentEquals(ca.der, c.der(1))
        assertContentEquals(leaf.subject, c.subject(0))
        assertContentEquals(leaf.issuer, c.issuer(0))
        assertContentEquals(ca.subject, c.subject(1))
        assertContentEquals(
            leaf.spki
                .toByteString()
                .sha256()
                .toByteArray(),
            c.spkiSha256(0),
        )
        // rawSerial: the INTEGER content as encoded, the leading zero kept.
        assertContentEquals(bytes(0x00, 0x8f, 0x12, 0x34), c.serial(0))
        assertContentEquals(bytes(0x01), c.serial(1))
    }

    @Test
    fun `dnsNames are the raw dNSName entries in order, empty without a SAN`() {
        val c = chain(leaf, ca)
        // Raw: not normalised (case and the trailing dot kept), the URI left out.
        assertEquals(listOf("a.example", "B.Example."), c.dnsNames(0))
        assertEquals(emptyList(), c.dnsNames(1))
        // Not checked as DNS syntax: a space or an empty name is reported as encoded.
        val odd = TestCert(extensions = listOf(sanOf(tlv(0x82, ascii("a b")), tlv(0x82, ByteArray(0)))))
        assertEquals(listOf("a b", ""), chain(odd).dnsNames(0))
        // A NUL is kept as encoded, so a suffix match on the raw name would be fooled; match exactly.
        val nul = TestCert(extensions = listOf(sanOf(tlv(0x82, ascii("a\u0000b")))))
        assertEquals(listOf("a\u0000b"), chain(nul).dnsNames(0))
        // A non-ASCII octet (UTF-8 "é") makes the SAN unreadable, so no names, not a decoded or partial list.
        val nonAscii =
            TestCert(extensions = listOf(sanOf(tlv(0x82, ascii("a.example")), tlv(0x82, bytes(0xc3, 0xa9)))))
        assertEquals(emptyList(), chain(nonAscii).dnsNames(0))
        assertTrue(chain(nonAscii).parsed(0))
    }

    @Test
    fun `a SAN that does not read gives no names`() {
        val name = tlv(0x82, ascii("a.example"))
        val duplicate = TestCert(extensions = listOf(sanOf(name), sanOf(name)))
        val malformed = TestCert(extensions = listOf(TestDer.extension(san, seq())))
        val badTag = TestCert(extensions = listOf(TestDer.extension(san, seq(tlv(0x89, ascii("x"))))))
        for (cert in listOf(duplicate, malformed, badTag)) assertEquals(emptyList(), chain(cert).dnsNames(0))
    }

    @Test
    fun `a chain built from equal certificates is equal, and newBuilder round-trips`() {
        val c = chain(leaf, ca)
        for (same in listOf(chain(leaf, ca), c.newBuilder().build())) {
            assertEquals(c, same)
            assertEquals(c.hashCode(), same.hashCode())
            assertEquals(c.toString(), same.toString())
        }
        assertNotEquals(c, chain(ca, leaf))
        assertNotEquals(c, chain(leaf))
        assertNotEquals<Any>(c, "chain")
        val leafHash =
            leaf.der
                .toByteString()
                .sha256()
                .hex()
        assertTrue(c.toString().startsWith("PresentedChain(certificates=[$leafHash, "), c.toString())
        assertEquals(0, PresentedChain.Builder().build().size)
    }

    @Test
    fun `the builder copies what it is given and the getters hand out copies`() {
        val der = leaf.der.copyOf()
        val c =
            PresentedChain
                .Builder()
                .certificates(listOf(der))
                .build()
        der[der.size - 1] = 9
        for (getter in listOf(c::der, c::subject, c::issuer, c::spkiSha256, c::serial)) {
            val first = getter(0)
            first[0] = (first[0] + 1).toByte()
            assertNotEquals(first.toList(), getter(0).toList())
        }
        assertContentEquals(leaf.der, c.der(0))
        assertEquals(chain(leaf), c)
    }

    @Test
    fun `an unparseable middle certificate keeps its index and its bytes, and nothing else`() {
        val garbage = bytes(0x30, 0x03, 0x02, 0x01, 0x05)
        val c =
            PresentedChain
                .Builder()
                .certificates(listOf(leaf.der, garbage, ca.der))
                .build()
        assertEquals(3, c.size)
        assertEquals(listOf(true, false, true), (0 until c.size).map(c::parsed))
        assertContentEquals(garbage, c.der(1))
        for (empty in listOf(c.subject(1), c.issuer(1), c.spkiSha256(1), c.serial(1))) assertEquals(0, empty.size)
        assertEquals(emptyList(), c.dnsNames(1))
        // The certificates either side read as they would alone, at their presented indices.
        assertContentEquals(leaf.subject, c.subject(0))
        assertEquals(listOf("a.example", "B.Example."), c.dnsNames(0))
        assertContentEquals(ca.subject, c.subject(2))
        assertContentEquals(bytes(0x01), c.serial(2))
        assertTrue("(not parsed)" in c.toString(), c.toString())
        assertEquals(c, c.newBuilder().build())
        // An unparsed leaf too.
        val noLeaf =
            PresentedChain
                .Builder()
                .certificates(listOf(garbage, ca.der))
                .build()
        assertEquals(listOf(false, true), listOf(noLeaf.parsed(0), noLeaf.parsed(1)))
    }

    @Test
    fun `the engine's chain takes the evaluation's parses, a certificate it did not read included`() {
        val leafParse = (CertificateParser.parse(leaf.der) as CertificateParse.Parsed).certificate
        // The CA's bytes would parse, but the evaluation stopped before reading them.
        val c = PresentedChain.of(listOf(leaf.der, ca.der), listOf(leafParse, null))
        assertEquals(listOf(true, false), listOf(c.parsed(0), c.parsed(1)))
        assertContentEquals(leaf.subject, c.subject(0))
        assertContentEquals(ca.der, c.der(1))
        assertEquals(0, c.subject(1).size)
        // The parsed flag is part of equality, and newBuilder keeps it.
        assertNotEquals(chain(leaf, ca), c)
        assertEquals(c, c.newBuilder().build())
        assertEquals(chain(leaf, ca), c.newBuilder().certificates(listOf(leaf.der, ca.der)).build())
        assertTrue(
            "one parse result per certificate" in
                assertFailsWith<IllegalArgumentException> {
                    PresentedChain.of(
                        listOf(leaf.der),
                        emptyList(),
                    )
                }.message!!,
        )
        assertTrue(
            "of other bytes" in
                assertFailsWith<IllegalArgumentException> {
                    PresentedChain.of(listOf(ca.der), listOf(leafParse))
                }.message!!,
        )
    }

    @Test
    fun `an index out of range throws`() {
        val c = chain(leaf)
        assertFailsWith<IndexOutOfBoundsException> { c.der(1) }
        assertFailsWith<IndexOutOfBoundsException> { c.parsed(1) }
        assertFailsWith<IndexOutOfBoundsException> { c.dnsNames(-1) }
    }
}
