// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.PkixPki.Issued
import dev.revokt.engine.parse.TestDer
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §5.1 "PKIX fallback contract" on the JVM's [PkixPathBuilderFallback] over really signed chains: the path lists
 * the presented leaf's exact bytes first and the snapshot's bytes read for the anchor last; no path, a malformed leaf
 * and an anchor set the factory cannot read are null, never a throw; the anchors are parsed once per snapshot id and
 * digest; the path links by name from the leaf to the anchor; the date is the caller's; and the AIA property is left
 * alone (§10 item 13).
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class PkixPathBuilderFallbackTest {
    private val root = PkixPki.root("Fallback Root")
    private val intermediate = PkixPki.issue("Fallback Intermediate", root, ca = true)
    private val leaf = PkixPki.issue("leaf.fallback.example", intermediate, ca = false)

    private var ids = 1_000L

    private fun snapshot(
        vararg anchors: Issued,
        read: List<ByteArray> = anchors.map { it.der },
        id: Long = ids++,
        sha256: ByteArray = ByteArray(32),
    ): AnchorSnapshot =
        AnchorSnapshot
            .Builder()
            .id(id)
            .sha256(sha256)
            .anchors(read)
            .platformEncodings(anchors.map { it.der })
            .createdMillis(0)
            .build()

    private fun hex(ders: List<ByteArray>?) = ders?.map { it.toByteString().hex() }

    @Test
    fun `fallback a reachable anchor gives the path leaf first and the anchor appended`() {
        val path = PkixPathBuilderFallback().build(listOf(leaf.der, intermediate.der), snapshot(root), PkixPki.NOW)
        assertEquals(hex(listOf(leaf.der, intermediate.der, root.der)), hex(path))
    }

    @Test
    fun `fallback a leaf issued by the anchor gives the leaf and the anchor`() {
        val direct = PkixPki.issue("direct.fallback.example", root, ca = false)
        val path = PkixPathBuilderFallback().build(listOf(direct.der), snapshot(root), PkixPki.NOW)
        assertEquals(hex(listOf(direct.der, root.der)), hex(path))
    }

    @Test
    fun `fallback returns the presented bytes, not the JDK's re-encoding`() {
        // An indefinite outer SEQUENCE: the JDK's factory converts it, so getEncoded() differs from what was presented.
        fun indefinite(der: ByteArray): ByteArray {
            val header = if (der[1].toInt() and 0x80 == 0) 2 else 2 + (der[1].toInt() and 0x7f)
            return TestDer.bytes(0x30, 0x80) + der.copyOfRange(header, der.size) + TestDer.bytes(0, 0)
        }
        val presentedLeaf = indefinite(leaf.der)
        val presentedIntermediate = indefinite(intermediate.der)
        assertFalse(PkixPki.x509(presentedLeaf).encoded.contentEquals(presentedLeaf), "the JDK re-encodes the leaf")
        val path =
            PkixPathBuilderFallback().build(listOf(presentedLeaf, presentedIntermediate), snapshot(root), PkixPki.NOW)
        assertNotNull(path)
        assertTrue(path[0].contentEquals(presentedLeaf), "element 0 is the presented leaf's exact bytes")
        assertTrue(path[1].contentEquals(presentedIntermediate), "an intermediate is the bytes presented for it")
        assertContentEquals(root.der, path[2])
    }

    @Test
    fun `fallback the anchor is the snapshot's bytes read, not its platform encoding`() {
        val read = TestDer.bytes(0x30, 0x03, 0x02, 0x01, 0x07)
        val path =
            PkixPathBuilderFallback().build(
                listOf(leaf.der, intermediate.der),
                snapshot(root, read = listOf(read)),
                PkixPki.NOW,
            )
        assertNotNull(path)
        assertContentEquals(read, path.last(), "the anchor as revokt reads it, which decide matches by bytes")
    }

    @Test
    fun `fallback an unreachable anchor is null`() {
        val other = PkixPki.root("Unrelated Root")
        assertNull(PkixPathBuilderFallback().build(listOf(leaf.der, intermediate.der), snapshot(other), PkixPki.NOW))
        assertNull(PkixPathBuilderFallback().build(listOf(leaf.der), snapshot(root), PkixPki.NOW), "no intermediate")
    }

    @Test
    fun `fallback a malformed leaf is null and a malformed intermediate is skipped`() {
        val garbage = TestDer.bytes(0x30, 0x03, 0x02, 0x01, 0x07)
        val fallback = PkixPathBuilderFallback()
        assertNull(fallback.build(listOf(garbage, intermediate.der), snapshot(root), PkixPki.NOW))
        assertNull(fallback.build(listOf(TestDer.bytes(0xff)), snapshot(root), PkixPki.NOW))
        assertNull(fallback.build(emptyList(), snapshot(root), PkixPki.NOW))
        val path = fallback.build(listOf(leaf.der, garbage, intermediate.der), snapshot(root), PkixPki.NOW)
        assertEquals(hex(listOf(leaf.der, intermediate.der, root.der)), hex(path))
    }

    @Test
    fun `fallback an anchor set the factory cannot read is null, memoised, never a throw`() {
        val fallback = PkixPathBuilderFallback()
        val broken =
            AnchorSnapshot
                .Builder()
                .id(ids++)
                .sha256(ByteArray(32))
                .anchors(listOf(TestDer.bytes(0x30, 0x00)))
                .createdMillis(0)
                .build()
        assertNull(fallback.build(listOf(leaf.der, intermediate.der), broken, PkixPki.NOW))
        assertNull(fallback.build(listOf(leaf.der, intermediate.der), broken, PkixPki.NOW))
        assertEquals(1, fallback.anchorParses)
    }

    @Test
    fun `fallback anchors are parsed once per snapshot id and again for a new id`() {
        val fallback = PkixPathBuilderFallback()
        val first = snapshot(root)
        repeat(3) { assertNotNull(fallback.build(listOf(leaf.der, intermediate.der), first, PkixPki.NOW)) }
        assertEquals(1, fallback.anchorParses)
        assertNotNull(fallback.build(listOf(leaf.der, intermediate.der), snapshot(root), PkixPki.NOW))
        assertEquals(2, fallback.anchorParses)
    }

    @Test
    fun `fallback a snapshot that reuses an id with another sha256 is parsed again`() {
        // A hand-built snapshot can reuse an id (the builder takes any): the memo answers only for the same digest.
        val fallback = PkixPathBuilderFallback()
        val chain = listOf(leaf.der, intermediate.der)
        val id = ids++
        val first = snapshot(root, id = id, sha256 = ByteArray(32) { 1 })
        val reused = snapshot(PkixPki.root("Unrelated Root"), id = id, sha256 = ByteArray(32) { 2 })
        assertNotNull(fallback.build(chain, first, PkixPki.NOW))
        assertNull(fallback.build(chain, reused, PkixPki.NOW), "the reused id's own anchors, not the first's")
        assertEquals(2, fallback.anchorParses)
        assertNotNull(fallback.build(chain, first, PkixPki.NOW), "the first digest again is a miss after the reuse")
        assertEquals(3, fallback.anchorParses)
        assertNotNull(fallback.build(chain, snapshot(root, id = id, sha256 = ByteArray(32) { 1 }), PkixPki.NOW))
        assertEquals(3, fallback.anchorParses, "the same id and digest is a hit")
    }

    @Test
    fun `fallback a leaf that is itself the anchor is null`() {
        // The JDK returns an empty path for a target that is a trust anchor; decide never asks (step 2), and the
        // result would list the anchor twice.
        assertNull(PkixPathBuilderFallback().build(listOf(root.der), snapshot(root), PkixPki.NOW))
        assertNull(PkixPathBuilderFallback().build(listOf(root.der, intermediate.der), snapshot(root), PkixPki.NOW))
    }

    @Test
    fun `fallback a path links by name from the leaf to the anchor`() {
        val certs = listOf(leaf, intermediate, root).map { PkixPki.x509(it.der) }
        assertTrue(linksByName(certs))
        assertTrue(linksByName(certs.take(1)), "one element has no link to break")
        assertFalse(linksByName(listOf(certs[0], certs[2])), "the leaf is not issued by the root")
        assertFalse(linksByName(listOf(certs[1], certs[0], certs[2])), "out of order")
        assertFalse(linksByName(listOf(certs[0], certs[1], PkixPki.x509(PkixPki.root("Unrelated Root").der))))
    }

    @Test
    fun `fallback the memo keeps the last eight ids`() {
        val fallback = PkixPathBuilderFallback()
        val snapshots = (0 until 9).map { snapshot(root) }
        snapshots.forEach { fallback.build(listOf(leaf.der), it, PkixPki.NOW) }
        assertEquals(9, fallback.anchorParses)
        fallback.build(listOf(leaf.der), snapshots[8], PkixPki.NOW)
        assertEquals(9, fallback.anchorParses, "the newest is kept")
        fallback.build(listOf(leaf.der), snapshots[0], PkixPki.NOW)
        assertEquals(10, fallback.anchorParses, "the oldest was evicted")
    }

    @Test
    fun `fallback validity is checked at nowMillis`() {
        val expiring =
            PkixPki.issue(
                "Expiring Intermediate",
                root,
                ca = true,
                validity = PkixPki.validity("261022134530Z", "261231000000Z"),
            )
        val under = PkixPki.issue("leaf.expiring.example", expiring, ca = false)
        val fallback = PkixPathBuilderFallback()
        val snapshot = snapshot(root)
        assertNull(fallback.build(listOf(under.der, expiring.der), snapshot, PkixPki.NOW), "expired at nowMillis")
        val before = PkixPki.NOW - 30L * 24 * 3600 * 1000
        assertNotNull(fallback.build(listOf(under.der, expiring.der), snapshot, before), "valid a month earlier")
    }

    @Test
    fun `fallback a non-CA intermediate gives no path`() {
        val notCa = PkixPki.issue("Not A CA", root, ca = false)
        val under = PkixPki.issue("leaf.notca.example", notCa, ca = false)
        assertNull(PkixPathBuilderFallback().build(listOf(under.der, notCa.der), snapshot(root), PkixPki.NOW))
    }

    @Test
    fun `fallback maps each of two intermediates to its own presented bytes, whatever the order`() {
        // Step 6 does not re-check linkage, so a path that repeats one intermediate's bytes in both positions would
        // change the CRLite issuer key: each intermediate must come back as its own presented bytes.
        val upper = PkixPki.issue("Upper Intermediate", root, ca = true)
        val lower = PkixPki.issue("Lower Intermediate", upper, ca = true)
        val under = PkixPki.issue("leaf.two.example", lower, ca = false)
        val fallback = PkixPathBuilderFallback()
        val anchors = snapshot(root)
        val expected = hex(listOf(under.der, lower.der, upper.der, root.der))
        assertEquals(expected, hex(fallback.build(listOf(under.der, lower.der, upper.der), anchors, PkixPki.NOW)))
        assertEquals(expected, hex(fallback.build(listOf(under.der, upper.der, lower.der), anchors, PkixPki.NOW)))
    }

    @Test
    fun `fallback finds the path the raw issuer bytes hide`() {
        // The issuer field spells the intermediate's name as a PrintableString: raw bytes differ, the JDK's
        // X500Principal equality does not (spec §10 residual 1).
        val respelled =
            PkixPki.issue(
                "leaf.respelled.example",
                intermediate,
                ca = false,
                issuerName = PkixPki.name("Fallback Intermediate", printable = true),
            )
        val path = PkixPathBuilderFallback().build(listOf(respelled.der, intermediate.der), snapshot(root), PkixPki.NOW)
        assertEquals(hex(listOf(respelled.der, intermediate.der, root.der)), hex(path))
    }

    @Test
    fun `fallback a critical policy qualifier does not fail the build`() {
        // setPolicyQualifiersRejected(false): the JDK's default would reject a critical certificatePolicies that carries
        // a qualifier, as CA/B certificates may.
        val cps = TestDer.tlv(0x16, TestDer.ascii("https://cps.example"))
        val policy =
            TestDer.seq(
                TestDer.seq(
                    TestDer.oid("2.23.140.1.2.1"),
                    TestDer.seq(TestDer.seq(TestDer.oid("1.3.6.1.5.5.7.2.1"), cps)),
                ),
            )
        val qualified =
            PkixPki.issue(
                "Qualified Intermediate",
                root,
                ca = true,
                extensions = listOf(TestDer.extension("2.5.29.32", policy, critical = true)),
            )
        val under = PkixPki.issue("leaf.qualified.example", qualified, ca = false)
        val path = PkixPathBuilderFallback().build(listOf(under.der, qualified.der), snapshot(root), PkixPki.NOW)
        assertEquals(hex(listOf(under.der, qualified.der, root.der)), hex(path))
    }

    @Test
    fun `fallback neither sets nor clears the AIA property`() {
        val key = "com.sun.security.enableAIAcaIssuers"
        val before = System.getProperty(key)
        PkixPathBuilderFallback().build(listOf(leaf.der, intermediate.der), snapshot(root), PkixPki.NOW)
        assertEquals(before, System.getProperty(key))
    }
}
