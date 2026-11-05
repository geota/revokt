// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.RevoktLimits
import dev.revokt.canonicalSubject
import dev.revokt.engine.walker.WalkerCerts.ECDSA_SHA256
import dev.revokt.engine.walker.WalkerCerts.SHA256_RSA
import dev.revokt.engine.walker.WalkerCerts.akiIssuerAndSerial
import dev.revokt.engine.walker.WalkerCerts.akiKeyId
import dev.revokt.engine.walker.WalkerCerts.der
import dev.revokt.engine.walker.WalkerCerts.ecKey
import dev.revokt.engine.walker.WalkerCerts.rsaKey
import dev.revokt.testing.SymKey
import dev.revokt.testing.SymName
import okio.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Spec §5.1 deferral rule and declarations: relatedness, the per-node order and the exact-byte duplicate rule. */
class CandidateIndexTest {
    private val root = SymName("Root")
    private val other = SymName("Other")
    private val leafName = SymName("leaf.example")

    private fun index(
        vararg anchors: ByteArray,
        canonicaliser: (ByteArray) -> String? = ::canonicalSubject,
    ) = CandidateIndex(anchors.toList(), canonicaliser = canonicaliser)

    private fun CandidateIndex.relatedList(
        presented: List<Cert>,
        child: Cert,
        belowLeaf: Boolean,
        seen: Set<ByteString> = setOf(child.bytesHash),
    ) = related(presented, child, seen, belowLeaf).toList()

    private fun CandidateIndex.unrelatedList(
        presented: List<Cert>,
        child: Cert,
        seen: Set<ByteString> = setOf(child.bytesHash),
    ) = unrelated(presented, child, seen).toList()

    private fun hashes(certs: List<Cert>) = certs.map { it.bytesHash }

    @Test
    fun `candidate index orders presented by index before the store at the leaf`() {
        val anchor = der(root, root)
        val index = index(anchor)
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        val p1 = index.cert(WalkerCerts.parse(der(root, other)))
        val p2 = index.cert(WalkerCerts.parse(der(root, other)))
        val presented = listOf(leaf, p2, p1)
        assertEquals(
            hashes(listOf(p2, p1, index.store[0])),
            hashes(index.relatedList(presented, leaf, belowLeaf = false)),
        )
    }

    @Test
    fun `candidate index orders the store before presented below the leaf`() {
        val anchor = der(root, root)
        val index = index(anchor)
        val intermediate = index.cert(WalkerCerts.parse(der(SymName("I"), root)))
        val cross = index.cert(WalkerCerts.parse(der(root, other)))
        val leaf = index.cert(WalkerCerts.parse(der(leafName, SymName("I"))))
        val presented = listOf(leaf, cross, intermediate)
        assertEquals(
            hashes(listOf(index.store[0], cross)),
            hashes(
                index.relatedList(
                    presented,
                    intermediate,
                    belowLeaf = true,
                    seen = hashes(listOf(leaf, intermediate)).toSet(),
                ),
            ),
        )
    }

    @Test
    fun `candidate index orders store groups raw then canonical then SKI, each by bytesHash`() {
        val keyId = ByteArray(20) { 9 }
        val rawA = der(root, root)
        val rawB = der(root, root)
        val canonicalA = der(SymName("Root", printable = true), SymName("Root", printable = true))
        val canonicalB = der(SymName("Root", printable = true), SymName("Root", printable = true))
        val skiA = der(SymName("Elsewhere A"), SymName("Elsewhere A"), ski = keyId)
        val skiB = der(SymName("Elsewhere B"), SymName("Elsewhere B"), ski = keyId)
        val unrelatedAnchor = der(other, other)
        val index = index(skiB, canonicalB, unrelatedAnchor, rawB, skiA, canonicalA, rawA)
        val child = index.cert(WalkerCerts.parse(der(leafName, root, aki = akiKeyId(keyId))))
        val byHash = { ders: List<ByteArray> -> ders.map { WalkerCerts.cert(it).bytesHash }.sorted() }
        val expected = byHash(listOf(rawA, rawB)) + byHash(listOf(canonicalA, canonicalB)) + byHash(listOf(skiA, skiB))
        for (belowLeaf in listOf(false, true)) {
            assertEquals(expected, hashes(index.relatedList(listOf(child), child, belowLeaf)), "belowLeaf=$belowLeaf")
        }
    }

    @Test
    fun `candidate index puts key-family compatible candidates first within a group`() {
        val rsa = List(3) { der(root, root, key = rsaKey()) }
        val ec = List(3) { der(root, root, key = ecKey(), sigOid = ECDSA_SHA256) }
        val index = index(*(rsa + ec).toTypedArray())
        val byHash = { ders: List<ByteArray> -> ders.map { WalkerCerts.cert(it).bytesHash }.sorted() }
        val rsaSigned = index.cert(WalkerCerts.parse(der(leafName, root, sigOid = SHA256_RSA)))
        val ecSigned = index.cert(WalkerCerts.parse(der(leafName, root, sigOid = ECDSA_SHA256)))
        val unknownSigned = index.cert(WalkerCerts.parse(der(leafName, root, sigOid = "1.3.6.1.4.1.99999.91.2")))
        assertEquals(byHash(rsa) + byHash(ec), hashes(index.relatedList(listOf(rsaSigned), rsaSigned, false)))
        assertEquals(byHash(ec) + byHash(rsa), hashes(index.relatedList(listOf(ecSigned), ecSigned, false)))
        // An unknown signature OID is compatible with every key: bytesHash alone.
        assertEquals(byHash(rsa + ec), hashes(index.relatedList(listOf(unknownSigned), unknownSigned, true)))
    }

    @Test
    fun `candidate index yields a presented and store byte duplicate once, presented at the leaf, store below it`() {
        val anchorDer = der(root, root)
        val index = index(anchorDer, der(root, root))
        val storeCopy = index.store.single { it.der.contentEquals(anchorDer) }
        val presentedCopy = index.cert(WalkerCerts.parse(anchorDer.copyOf()))
        val decoy = index.cert(WalkerCerts.parse(der(root, other)))
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        val presented = listOf(leaf, decoy, presentedCopy)

        val atLeaf = index.relatedList(presented, leaf, belowLeaf = false)
        assertEquals(3, atLeaf.size)
        assertEquals(listOf(decoy.bytesHash, presentedCopy.bytesHash), hashes(atLeaf.take(2)))
        assertSame(presentedCopy, atLeaf[1], "at the leaf the duplicate is the presented certificate")
        assertTrue(atLeaf[2] in index.store && atLeaf[2].bytesHash != presentedCopy.bytesHash)

        val intermediate = index.cert(WalkerCerts.parse(der(SymName("I"), root)))
        val below = index.relatedList(listOf(leaf, decoy, presentedCopy), intermediate, belowLeaf = true)
        val storeOrder = index.store.map { it.bytesHash }.sorted()
        assertEquals(storeOrder + decoy.bytesHash, hashes(below))
        assertSame(storeCopy, below.single { it.bytesHash == storeCopy.bytesHash }, "below the leaf it is the store's")
    }

    @Test
    fun `candidate index yields presented byte duplicates once at the earliest index`() {
        val index = index(der(other, other))
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        val issuerDer = der(root, other)
        val first = index.cert(WalkerCerts.parse(issuerDer))
        val second = index.cert(WalkerCerts.parse(issuerDer.copyOf()))
        val junk = index.cert(WalkerCerts.parse(der(other, root)))
        val junkAgain = index.cert(WalkerCerts.parse(junk.der.copyOf()))
        val presented = listOf(leaf, junk, first, junkAgain, second)
        val related = index.relatedList(presented, leaf, belowLeaf = false)
        assertEquals(1, related.size)
        assertSame(first, related[0])
        val unrelated = index.unrelatedList(presented, leaf)
        assertEquals(1, unrelated.size)
        assertSame(junk, unrelated[0])
    }

    @Test
    fun `candidate index excludes seen certificates from presented and store`() {
        val anchorDer = der(root, root)
        val index = index(anchorDer)
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        val related = index.cert(WalkerCerts.parse(der(root, other)))
        val unrelated = index.cert(WalkerCerts.parse(der(other, other)))
        val presented = listOf(leaf, related, unrelated)
        val seen = setOf(leaf.bytesHash, related.bytesHash, index.store[0].bytesHash, unrelated.bytesHash)
        assertEquals(emptyList(), index.relatedList(presented, leaf, false, seen))
        assertEquals(emptyList(), index.relatedList(presented, leaf, true, seen))
        assertEquals(emptyList(), index.unrelatedList(presented, leaf, seen))
        // The child itself is excluded through seen, as the walker passes it.
        assertEquals(
            listOf(related.bytesHash),
            hashes(
                index.relatedList(
                    presented,
                    leaf,
                    false,
                    seen - related.bytesHash,
                ),
            ),
        )
    }

    @Test
    fun `candidate index yields a store candidate in several groups once, at its first group`() {
        val keyId = ByteArray(20) { 4 }
        val both = der(root, root, ski = keyId)
        val skiOnly = der(other, other, ski = keyId)
        val index = index(skiOnly, both)
        val child = index.cert(WalkerCerts.parse(der(leafName, root, aki = akiKeyId(keyId))))
        val expected = listOf(both, skiOnly).map { WalkerCerts.cert(it).bytesHash }
        assertEquals(expected, hashes(index.relatedList(listOf(child), child, true)))
    }

    @Test
    fun `candidate index unrelated is the presented certificates not related, by index, never the store`() {
        val index = index(der(root, root), der(other, other))
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        val related = index.cert(WalkerCerts.parse(der(root, other)))
        val u1 = index.cert(WalkerCerts.parse(der(SymName("U1"), other)))
        val u2 = index.cert(WalkerCerts.parse(der(SymName("U2"), other)))
        val presented = listOf(leaf, u2, related, u1)
        assertEquals(hashes(listOf(u2, u1)), hashes(index.unrelatedList(presented, leaf)))
        assertEquals(
            hashes(listOf(related, index.store.single { it.subjectRaw.contentEquals(root.der()) })),
            hashes(index.relatedList(presented, leaf, false)),
        )
    }

    @Test
    fun `candidate index matches an issuer-and-serial-only AKI by name only`() {
        val keyId = ByteArray(20) { 3 }
        val sameName = der(root, root, ski = keyId)
        val sameKeyIdOtherName = der(other, other, ski = keyId)
        val index = index(sameName, sameKeyIdOtherName)
        val child = index.cert(WalkerCerts.parse(der(leafName, root, aki = akiIssuerAndSerial(root))))
        assertEquals(null, child.akiKeyId)
        assertEquals(
            listOf(WalkerCerts.cert(sameName).bytesHash),
            hashes(index.relatedList(listOf(child), child, true)),
        )
        val presentedOtherName = index.cert(WalkerCerts.parse(der(other, other, ski = keyId)))
        assertEquals(
            listOf(presentedOtherName.bytesHash),
            hashes(index.unrelatedList(listOf(child, presentedOtherName), child)),
        )
    }

    @Test
    fun `candidate index matches a candidate without SKI by name only`() {
        val keyId = ByteArray(20) { 5 }
        val noSkiOtherName = der(other, other)
        val noSkiSameName = der(root, root)
        val index = index(noSkiOtherName, noSkiSameName)
        val child = index.cert(WalkerCerts.parse(der(leafName, root, aki = akiKeyId(keyId))))
        assertEquals(
            listOf(WalkerCerts.cert(noSkiSameName).bytesHash),
            hashes(index.relatedList(listOf(child), child, false)),
        )
    }

    @Test
    fun `candidate index never treats a presented candidate without SKI as an SKI match`() {
        val keyId = ByteArray(20) { 8 }
        val index = index(der(other, other))
        val child = index.cert(WalkerCerts.parse(der(leafName, root, aki = akiKeyId(keyId))))
        val noSki = index.cert(WalkerCerts.parse(der(SymName("No SKI"), other)))
        val otherSki = index.cert(WalkerCerts.parse(der(SymName("Other SKI"), other, ski = ByteArray(20) { 1 })))
        val matching = index.cert(WalkerCerts.parse(der(SymName("Matching SKI"), other, ski = keyId)))
        val presented = listOf(child, noSki, otherSki, matching)
        assertEquals(listOf(matching.bytesHash), hashes(index.relatedList(presented, child, false)))
        assertEquals(listOf(matching.bytesHash), hashes(index.relatedList(presented, child, true)))
        assertEquals(hashes(listOf(noSki, otherSki)), hashes(index.unrelatedList(presented, child)))
    }

    @Test
    fun `candidate index keeps presented candidates in index order whatever their key family`() {
        val index = index(der(root, root, key = rsaKey()))
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root, sigOid = SHA256_RSA)))
        val ecFirst = index.cert(WalkerCerts.parse(der(root, other, key = ecKey(), sigOid = ECDSA_SHA256)))
        val rsaSecond = index.cert(WalkerCerts.parse(der(root, other, key = rsaKey())))
        val presented = listOf(leaf, ecFirst, rsaSecond)
        assertEquals(KeyFamily.EC, ecFirst.keyFamily)
        assertEquals(
            hashes(listOf(ecFirst, rsaSecond, index.store[0])),
            hashes(index.relatedList(presented, leaf, belowLeaf = false)),
        )
        val intermediate = index.cert(WalkerCerts.parse(der(SymName("I"), root, sigOid = SHA256_RSA)))
        assertEquals(
            hashes(listOf(index.store[0], ecFirst, rsaSecond)),
            hashes(index.relatedList(presented, intermediate, belowLeaf = true)),
        )
    }

    @Test
    fun `candidate index orders same-OID families by exact key OID, unknown keys compatible`() {
        val ed25519 = "1.3.101.112"
        val ed448 = "1.3.101.113"
        val mlDsa65 = "2.16.840.1.101.3.4.3.18"
        val keys =
            listOf(ed25519, ed25519, ed448, ed448, "1.3.6.1.4.1.99999.91.1", WalkerCerts.RSA_KEY).mapIndexed { i, oid ->
                der(root, root, key = SymKey(13, i, oid))
            }
        val index = index(*keys.toTypedArray())
        val byOid = index.store.groupBy { it.keyOid }.mapValues { (_, v) -> v.map { it.bytesHash }.sorted() }
        val unknown = byOid.getValue("1.3.6.1.4.1.99999.91.1")

        fun orderUnder(sigOid: String): List<ByteString> {
            val child = index.cert(WalkerCerts.parse(der(leafName, root, sigOid = sigOid)))
            return hashes(index.relatedList(listOf(child), child, true))
        }

        fun rest(vararg first: List<ByteString>): List<ByteString> {
            val head = first.toList().flatten()
            return head +
                index.store
                    .map { it.bytesHash }
                    .filter { it !in head }
                    .sorted()
        }
        assertEquals(rest((byOid.getValue(ed25519) + unknown).sorted()), orderUnder(ed25519))
        assertEquals(rest((byOid.getValue(ed448) + unknown).sorted()), orderUnder(ed448))
        // No key in the group is ML-DSA-65: only the unknown key is compatible.
        assertEquals(rest(unknown), orderUnder(mlDsa65))
        assertEquals(rest((byOid.getValue(WalkerCerts.RSA_KEY) + unknown).sorted()), orderUnder(SHA256_RSA))
        assertEquals(rest(unknown), orderUnder(ECDSA_SHA256))
        assertEquals(index.store.map { it.bytesHash }.sorted(), orderUnder("1.3.6.1.4.1.99999.91.2"))
    }

    @Test
    fun `candidate index related is lazy and yields the same sequence on every iteration`() {
        val index = index(*Array(3) { der(root, root) })
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        val p = index.cert(WalkerCerts.parse(der(root, other)))
        val s = index.related(listOf(leaf, p, p), leaf, setOf(leaf.bytesHash), belowLeaf = false)
        assertEquals(s.toList().map { it.bytesHash }, s.toList().map { it.bytesHash })
        assertEquals(4, s.count())
        assertEquals(listOf(p.bytesHash), s.take(1).map { it.bytesHash }.toList())
        val u = index.unrelated(listOf(leaf, p), leaf, emptySet())
        assertEquals(u.toList(), u.toList())
    }

    @Test
    fun `candidate index relates a PrintableString and UTF8String issuer-name pair canonically only`() {
        val printableRoot = SymName("Root", printable = true)
        val anchorDer = der(printableRoot, printableRoot)
        val child = der(leafName, SymName("Root"))
        val presentedDer = der(printableRoot, other)

        val platform = index(anchorDer)
        val leaf = platform.cert(WalkerCerts.parse(child))
        val presented = platform.cert(WalkerCerts.parse(presentedDer))
        assertFalse(platform.store[0].subjectRaw.contentEquals(leaf.issuerRaw), "raw bytes differ")
        assertEquals(platform.store[0].canonicalSubject, leaf.canonicalIssuer)
        assertEquals(
            hashes(listOf(presented, platform.store[0])),
            hashes(platform.relatedList(listOf(leaf, presented), leaf, false)),
        )
        assertEquals(emptyList(), platform.unrelatedList(listOf(leaf, presented), leaf))

        for ((name, canonicaliser) in listOf<Pair<String, (ByteArray) -> String?>>(
            "null" to { null },
            "throwing" to { error("x") },
        )) {
            val raw = index(anchorDer, canonicaliser = canonicaliser)
            val rawLeaf = raw.cert(WalkerCerts.parse(child))
            val rawPresented = raw.cert(WalkerCerts.parse(presentedDer))
            assertEquals(emptyList(), raw.relatedList(listOf(rawLeaf, rawPresented), rawLeaf, false), name)
            assertEquals(
                listOf(rawPresented.bytesHash),
                hashes(raw.unrelatedList(listOf(rawLeaf, rawPresented), rawLeaf)),
                name,
            )
        }
    }

    @Test
    fun `candidate index keeps raw and SKI matching under a null or throwing canonicaliser`() {
        val keyId = ByteArray(20) { 6 }
        val rawMatch = der(root, root)
        val skiMatch = der(other, other, ski = keyId)
        val canonicalisers = listOf<(ByteArray) -> String?>({ null }, { throw IllegalStateException("custom") })
        for (canonicaliser in canonicalisers) {
            val index = index(rawMatch, skiMatch, canonicaliser = canonicaliser)
            assertTrue(index.store.all { it.canonicalSubject == null })
            val child = index.cert(WalkerCerts.parse(der(leafName, root, aki = akiKeyId(keyId))))
            val presentedRaw = index.cert(WalkerCerts.parse(der(root, other)))
            val presentedSki = index.cert(WalkerCerts.parse(der(SymName("P"), other, ski = keyId)))
            assertEquals(null, child.canonicalIssuer)
            assertEquals(
                hashes(listOf(presentedRaw, presentedSki)) +
                    listOf(rawMatch, skiMatch).map { WalkerCerts.cert(it).bytesHash },
                hashes(index.relatedList(listOf(child, presentedRaw, presentedSki), child, false)),
            )
        }
    }

    @Test
    fun `candidate index never matches an anchor the parser drops and removes store byte duplicates`() {
        val good = der(root, root)
        val oversize = ByteArray(RevoktLimits.MAX_CERT_BYTES + 1)
        val garbage = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)
        val index = index(garbage, good, oversize, good.copyOf())
        assertEquals(1, index.store.size)
        assertTrue(index.isAnchorBytes(WalkerCerts.cert(good)))
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        assertFalse(index.isAnchorBytes(leaf))
        assertFalse(index.isPreloadBytes(index.store[0]))
        assertFalse(index.isPreloadBytes(leaf))
        assertEquals(0, CandidateIndex(listOf(garbage)).store.size)
    }

    @Test
    fun `candidate index carries the custom canonicaliser flag and canonicalises presented certificates`() {
        assertFalse(CandidateIndex(emptyList()).customCanonicaliser)
        val calls = mutableListOf<String>()
        val index =
            CandidateIndex(listOf(der(root, root)), customCanonicaliser = true) { name ->
                canonicalSubject(name)?.also { calls += it }
            }
        assertTrue(index.customCanonicaliser)
        assertEquals(1, calls.size, "an anchor's issuer equals its subject: one call")
        val leaf = index.cert(WalkerCerts.parse(der(leafName, root)))
        val presented = listOf(leaf, index.cert(WalkerCerts.parse(der(root, other))))
        repeat(3) {
            index.relatedList(presented, leaf, false)
            index.relatedList(presented, leaf, true)
            index.unrelatedList(presented, leaf)
        }
        // The leaf's subject and issuer, the presented certificate's subject; its issuer is never needed here.
        assertEquals(listOf("cn=root", "cn=leaf.example", "cn=root", "cn=root"), calls)
    }
}
