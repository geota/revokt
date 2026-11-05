// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.Oid
import dev.revokt.testing.ChainGenerator
import dev.revokt.testing.Mutation
import dev.revokt.testing.ReferenceWalker
import dev.revokt.testing.SplitMix64
import dev.revokt.testing.World
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Spec §5.1 deferral rule over §9.1 generator worlds (honest worlds with random world and attacker mutations): at every
 * presented node, `related` and `unrelated` against an oracle built on the JDK's view of the same certificates, and the
 * node order as an invariant. The seed is in every message.
 */
class CandidateIndexWorldTest {
    private val factory = CertificateFactory.getInstance("X.509")

    /** The JDK's reading of one certificate: the §5.1 relatedness inputs. */
    private inner class Jdk(
        der: ByteArray,
    ) {
        private val x = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        val bytesHash: ByteString = der.toByteString().sha256()
        val subject: ByteString = x.subjectX500Principal.encoded.toByteString()
        val issuer: ByteString = x.issuerX500Principal.encoded.toByteString()
        val ski: ByteString? =
            x
                .getExtensionValue(
                    Oid.SUBJECT_KEY_IDENTIFIER,
                )?.let { unwrap(unwrap(it)).toByteString() }
        val akiKeyId: ByteString? =
            x.getExtensionValue(Oid.AUTHORITY_KEY_IDENTIFIER)?.let { unwrap(it) }?.let { b ->
                // SEQUENCE { [0] keyIdentifier OPTIONAL, … } with short lengths, as the generator writes it.
                if (b.size > 2 && b[2].toInt() and 0xff == 0x80) b.copyOfRange(4, 4 + b[3]).toByteString() else null
            }

        fun canonical(
            name: ByteString,
            canonicaliser: (ByteArray) -> String?,
        ): String? = canonicaliser(name.toByteArray())

        /** The content of a short-form TLV. */
        private fun unwrap(tlv: ByteArray): ByteArray = tlv.copyOfRange(2, 2 + tlv[1])
    }

    private fun related(
        candidate: Jdk,
        child: Jdk,
        canonicaliser: (ByteArray) -> String?,
    ): Boolean {
        val cs = candidate.canonical(candidate.subject, canonicaliser)
        return candidate.subject == child.issuer ||
            (cs != null && cs == child.canonical(child.issuer, canonicaliser)) ||
            (candidate.ski != null && candidate.ski == child.akiKeyId)
    }

    @Test
    fun `candidate index related and unrelated match the relatedness oracle and the node order on generated worlds`() {
        // The index runs revokt's canonicaliser, the oracle the reference walker's X500Principal call.
        val canonicalisers =
            listOf<Triple<String, (ByteArray) -> String?, (ByteArray) -> String?>>(
                Triple("platform", ::canonicalSubject, ReferenceWalker::platformCanonicalSubject),
                Triple("null", { null }, { null }),
            )
        var nodes = 0
        var canonicalOnly = 0
        var duplicates = 0
        for (seed in 1L..300L) {
            val rng = SplitMix64(seed * 7919)
            val world = ChainGenerator.generate(seed, List(rng.nextInt(0, 6)) { Mutation.random(rng) })
            for ((name, canonicaliser, oracle) in canonicalisers) {
                val stats = check(world, canonicaliser, oracle, "seed $seed $name ${world.mutations.map { it.name }}")
                nodes += stats.first
                canonicalOnly += stats.second
                duplicates += stats.third
            }
        }
        assertTrue(nodes > 1000, "nodes $nodes")
        assertTrue(canonicalOnly > 0, "no world related a candidate by canonical name only")
        assertTrue(duplicates > 0, "no world presented an exact-byte duplicate")
    }

    /** Checks every presented node of [world]; returns (nodes, canonical-only relations, duplicate candidates). */
    private fun check(
        world: World,
        canonicaliser: (ByteArray) -> String?,
        oracle: (ByteArray) -> String?,
        label: String,
    ): Triple<Int, Int, Int> {
        val index = CandidateIndex(world.anchors, canonicaliser = canonicaliser)
        val presented =
            world.presented.map {
                val parsed = CertificateParser.parse(it) as? CertificateParse.Parsed ?: fail("$label: unparseable")
                index.cert(parsed.certificate)
            }
        val jdk = HashMap<ByteString, Jdk>()
        (world.presented + world.anchors).forEach { der -> Jdk(der).let { jdk.putIfAbsent(it.bytesHash, it) } }
        var canonicalOnly = 0
        for ((position, child) in presented.withIndex()) {
            val belowLeaf = position > 0
            val seen = setOf(presented[0].bytesHash, child.bytesHash)
            val related = index.related(presented, child, seen, belowLeaf).toList()
            val at = "$label node $position"
            val c = jdk.getValue(child.bytesHash)
            checkMembership(
                index,
                presented,
                child,
                seen,
                related,
                { related(jdk.getValue(it.bytesHash), c, oracle) },
                at,
            )
            checkOrder(index, presented, child, belowLeaf, related, at)
            canonicalOnly +=
                related.count {
                    val j = jdk.getValue(it.bytesHash)
                    j.subject != c.issuer && (j.ski == null || j.ski != c.akiKeyId)
                }
        }
        return Triple(presented.size, canonicalOnly, presented.size - presented.distinctBy { it.bytesHash }.size)
    }

    /** `related` is the oracle-related candidates, each once; `unrelated` the other presented ones, by index. */
    private fun checkMembership(
        index: CandidateIndex,
        presented: List<Cert>,
        child: Cert,
        seen: Set<ByteString>,
        related: List<Cert>,
        isRelated: (Cert) -> Boolean,
        at: String,
    ) {
        val distinctPresented = presented.distinctBy { it.bytesHash }.filter { it.bytesHash !in seen }
        val expectedRelated =
            (distinctPresented + index.store).filter(isRelated).map { it.bytesHash }.filter {
                it !in
                    seen
            }
        assertEquals(related.size, related.map { it.bytesHash }.toSet().size, "$at: related repeats a certificate")
        assertEquals(expectedRelated.toSet(), related.map { it.bytesHash }.toSet(), "$at: related")
        assertEquals(
            distinctPresented.filterNot(isRelated).map { it.bytesHash },
            index.unrelated(presented, child, seen).map { it.bytesHash }.toList(),
            "$at: unrelated, by index",
        )
    }

    /** One source, then the other; presented by first index, the earliest copy; the store by (group, family, hash). */
    private fun checkOrder(
        index: CandidateIndex,
        presented: List<Cert>,
        child: Cert,
        belowLeaf: Boolean,
        related: List<Cert>,
        at: String,
    ) {
        val fromPresented = { cert: Cert -> presented.any { it === cert } }
        val (first, second) = related.partition { fromPresented(it) != belowLeaf }
        assertEquals(first, related.take(first.size), "$at: sources interleave")
        val presentedPart = if (belowLeaf) second else first
        val storePart = if (belowLeaf) first else second
        val positions = presentedPart.map { p -> presented.indexOfFirst { it.bytesHash == p.bytesHash } }
        assertEquals(positions.sorted(), positions, "$at: presented by index")
        presentedPart.zip(positions).forEach { (p, i) -> assertSame(presented[i], p, "$at: earliest copy") }
        val laterPart = if (belowLeaf) presentedPart else storePart
        val earlierHashes = (if (belowLeaf) index.store else presented).map { it.bytesHash }.toSet()
        assertTrue(laterPart.none { it.bytesHash in earlierHashes }, "$at: a duplicate at its later position")
        assertTrue(storePart.all { s -> index.store.any { it === s } }, "$at: store instances")
        val family = KeyFamily.ofSignature(child.tbsSigOid)
        val ranks =
            storePart.map { s ->
                val group =
                    when {
                        s.subjectRaw.contentEquals(child.issuerRaw) -> 0
                        s.canonicalSubject != null && s.canonicalSubject == child.canonicalIssuer -> 1
                        else -> 2
                    }
                Triple(group, if (KeyFamily.compatible(s, child.tbsSigOid, family)) 0 else 1, s.bytesHash)
            }
        assertEquals(ranks.sortedWith(compareBy({ it.first }, { it.second }, { it.third })), ranks, "$at: store order")
    }
}
