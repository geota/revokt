// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.testing

import dev.revokt.RevoktLimits
import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString
import javax.security.auth.x500.X500Principal

/**
 * The §9.1 oracle: a relation-aware, uncapped reference walker. [walk] takes a presented chain (leaf first) and returns
 * the lowercase-hex SHA-256 of every leaf-issuer SPKI on a sound path, so the fuzzer's P2 compares by value.
 *
 * - A **sound path** is leaf → … → terminal where every link is [VerifyResult.VERIFIED] by [verifier] under the next
 *   certificate's key and the terminal is in [anchors] by exact bytes; an anchor ends the path (its own signature is
 *   never verified). It holds at most `MAX_DEPTH + 1` certificates including the terminal; a longer one is a dead end
 *   (spec §5.1 Limits, "same convention in the reference walker"). There is no other limit.
 * - **Candidates** of a node are the anchors related to it and every presented certificate other than the node; a
 *   presented certificate is related or unrelated, an anchor that is not related is never a candidate (§5.1 deferral
 *   rule). **Related** is spec §5.1's test: subject equal to the node's issuer as raw bytes or under
 *   [canonicalSubject] (null, or a throw, is no canonical match), or SKI equal to the node's AKI keyIdentifier.
 * - **At every node, related candidates, plus unrelated presented certificates only when no related path exists**: the
 *   keys returned are those of the related candidates with a sound path through them, or, when there is none, those
 *   of the unrelated ones. All of each group, so the result does not depend on the presented order.
 * - Below the leaf only whether a sound path exists matters, and there "related first, unrelated when none" admits a
 *   path exactly when some candidate does; certificates already on the path (the leaf above all) are never candidates.
 *   A shortest path never repeats a certificate, so an exhaustive depth-first walk over paths without repeats finds
 *   one within the depth bound exactly when the shortest one is within it. The walker therefore computes each
 *   reachable certificate's distance to an anchor in the graph without the leaf instead of enumerating paths: the
 *   same answer, in polynomial time on stuffed chains.
 * - Exact-byte duplicates are one certificate. A certificate revokt's parser rejects is no candidate; an unparseable
 *   leaf has no keys. A leaf that is an anchor by bytes returns its own key (decision step 2).
 *
 * Key families (§5.1 `CandidateIndex.related()`) only order candidates, so they do not change the result and are not
 * modelled.
 */
internal class ReferenceWalker(
    anchors: List<ByteArray>,
    private val verifier: SignatureVerifier,
    private val canonicalSubject: (ByteArray) -> String? = ::platformCanonicalSubject,
) {
    private val anchors: Map<ByteString, Node> = anchors.mapNotNull { node(it) }.associateBy { it.bytesHash }

    fun walk(presented: List<ByteArray>): Set<String> {
        if (presented.isEmpty()) return emptySet()
        val leaf = node(presented[0]) ?: return emptySet()
        if (leaf.bytesHash in anchors) return setOf(leaf.spkiHash.hex())
        val others = LinkedHashMap<ByteString, Node>()
        for (der in presented.drop(1)) {
            val n = node(der) ?: continue
            if (n.bytesHash != leaf.bytesHash) others.putIfAbsent(n.bytesHash, anchors[n.bytesHash] ?: n)
        }
        val graph = Graph(others.values.toList())
        val maxDistance = RevoktLimits.MAX_DEPTH - 1 // [leaf, candidate, …, anchor] holds distance + 2 certificates
        val issuers = graph.candidates(leaf).filter { graph.verified(leaf, it) }
        val (related, unrelated) = issuers.partition { it.isRelatedTo(leaf) }
        val distances = graph.distances(issuers)

        fun keys(group: List<Node>) =
            group.filter { (distances[it.bytesHash] ?: Int.MAX_VALUE) <= maxDistance }.map { it.spkiHash.hex() }.toSet()
        return keys(related).ifEmpty { keys(unrelated) }
    }

    /** The certificates of one walk: [presented] (without the leaf) and the anchors, with verified edges memoised. */
    private inner class Graph(
        private val presented: List<Node>,
    ) {
        private val memo = HashMap<Pair<ByteString, ByteString>, Boolean>()
        private val edges = HashMap<ByteString, List<Node>>()

        fun candidates(child: Node): List<Node> {
            val store =
                anchors.values.filter {
                    it.isRelatedTo(child) &&
                        presented.none { p -> p.bytesHash == it.bytesHash }
                }
            return (presented + store).filter { it.bytesHash != child.bytesHash }
        }

        fun verified(
            child: Node,
            candidate: Node,
        ): Boolean =
            memo.getOrPut(child.bytesHash to candidate.spkiHash) {
                verifier.verify(child.tbsSigAlg, candidate.spki, child.tbs, child.signature) == VerifyResult.VERIFIED
            }

        private fun issuers(child: Node): List<Node> =
            edges.getOrPut(child.bytesHash) {
                candidates(child).filter { verified(child, it) }
            }

        /** Each certificate reachable from [start]'s distance (in links) to an anchor; unreachable ones are absent. */
        fun distances(start: List<Node>): Map<ByteString, Int> {
            val reachable = LinkedHashMap<ByteString, Node>()
            val queue = ArrayDeque(start)
            while (queue.isNotEmpty()) {
                val n = queue.removeFirst()
                if (reachable.putIfAbsent(n.bytesHash, n) != null || n.bytesHash in anchors) continue
                queue.addAll(issuers(n))
            }
            val children = HashMap<ByteString, MutableList<Node>>()
            for (n in reachable.values) {
                if (n.bytesHash !in anchors) issuers(n).forEach { children.getOrPut(it.bytesHash) { ArrayList() } += n }
            }
            val distance = HashMap<ByteString, Int>()
            val frontier = ArrayDeque(reachable.values.filter { it.bytesHash in anchors })
            frontier.forEach { distance[it.bytesHash] = 0 }
            while (frontier.isNotEmpty()) {
                val n = frontier.removeFirst()
                for (c in children[n.bytesHash].orEmpty()) {
                    if (c.bytesHash !in distance) {
                        distance[c.bytesHash] = distance.getValue(n.bytesHash) + 1
                        frontier.addLast(c)
                    }
                }
            }
            return distance
        }
    }

    private fun node(der: ByteArray): Node? =
        (CertificateParser.parse(der) as? CertificateParse.Parsed)?.let { Node(der, it.certificate, ::canonical) }

    private fun canonical(name: ByteArray): String? =
        try {
            canonicalSubject(name)
        } catch (_: Exception) {
            null
        }

    /** One parsed certificate and the fields the walk reads, sliced by revokt's parser. */
    private class Node(
        der: ByteArray,
        p: ParsedCertificate,
        canonical: (ByteArray) -> String?,
    ) {
        val tbs: ByteArray = p.tbsBytes
        val tbsSigAlg: ByteArray = p.tbs.signature.bytes(p.tbsBytes)
        val signature: ByteArray = p.envelope.signature
        val spki: ByteArray = p.rawSpki()
        val bytesHash: ByteString = der.toByteString().sha256()
        val spkiHash: ByteString = spki.toByteString().sha256()
        private val subjectRaw = p.rawSubject().toByteString()
        private val issuerRaw = p.rawIssuer().toByteString()
        private val subjectCanonical = canonical(p.rawSubject())
        private val issuerCanonical = canonical(p.rawIssuer())
        private val ski =
            p.fields.ski
                ?.bytes(p.tbsBytes)
                ?.toByteString()
        private val akiKeyId =
            p.fields.akiKeyId
                ?.bytes(p.tbsBytes)
                ?.toByteString()

        fun isRelatedTo(child: Node): Boolean =
            subjectRaw == child.issuerRaw ||
                (subjectCanonical != null && subjectCanonical == child.issuerCanonical) ||
                (ski != null && ski == child.akiKeyId)
    }

    companion object {
        /** Spec §3's JVM and Android canonicaliser: `X500Principal(der).getName(CANONICAL)`, null when it fails. */
        fun platformCanonicalSubject(name: ByteArray): String? =
            try {
                X500Principal(name).getName(X500Principal.CANONICAL)
            } catch (_: IllegalArgumentException) {
                null
            }
    }
}
