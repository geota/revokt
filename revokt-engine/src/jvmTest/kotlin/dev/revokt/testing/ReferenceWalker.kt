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
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * The §9.1 oracle: a relation-aware, uncapped reference walker. [walk] takes a presented chain (leaf first) and returns
 * the lowercase-hex SHA-256 of every leaf-issuer SPKI on a sound path, so the fuzzer's P2 compares by value;
 * [walkByName] the same over name-related links only. The walker stops at its first path, so P2 reads them as a
 * bracket: its one key is in [walk]'s set, and when [walkByName]'s is not empty it finds a path.
 *
 * - A **sound path** is leaf → … → terminal where every link is [VerifyResult.VERIFIED] by [verifier] under the next
 *   certificate's key and the terminal is in [anchors] by exact bytes; an anchor ends the path (its own signature is
 *   never verified). It holds at most `MAX_DEPTH + 1` certificates including the terminal; a longer one is a dead end
 *   (spec §5.1 Limits, "same convention in the reference walker"). There is no other limit.
 * - **Candidates** of a node are the anchors and presented certificates related to it, other than the node; a
 *   certificate that is not related is never a candidate (§5.1). **Related** is spec §5.1's test: subject equal to the
 *   node's issuer as raw bytes or under [canonicalSubject] (null, or a throw, is no canonical match), or SKI equal to
 *   the node's AKI keyIdentifier; [walkByName] drops the SKI clause.
 * - **Loops:** a certificate with the leaf's raw subject and raw SPKI is never a candidate, as the walker skips a
 *   candidate repeating a certificate on its path and the leaf is on every path. A repeat higher up is not modelled:
 *   on name-related links it can always be cut out (the repeated certificate is related and verifies where its first
 *   copy did), so [walkByName] is exact for the walker; only a first copy related by SKI alone can make the walker
 *   miss a path [walk] counts, which neither reference builds (both chain by name).
 * - All keys with a path, so the result does not depend on the presented order. Below the leaf only whether a sound
 *   path exists matters; certificates already on the path are never candidates. A shortest path never repeats a
 *   certificate, so an exhaustive depth-first walk over paths without repeats finds one within the depth bound exactly
 *   when the shortest one is within it. The walker therefore computes each reachable certificate's distance to an
 *   anchor in the graph without the leaf instead of enumerating paths: the same answer, in polynomial time on stuffed
 *   chains.
 * - A candidate that is not an anchor must be a CA: the JDK reads its basicConstraints with `cA = TRUE`
 *   (`X509Certificate.getBasicConstraints() >= 0`; a certificate the JDK cannot parse is not one). The JDK, not
 *   revokt's extension reader, so the oracle checks the walker's [dev.revokt.engine.walker.Cert.isCa] rather than
 *   sharing it. #237's other issuer rules (`pathLenConstraint`, keyUsage, extKeyUsage, nameConstraints) are not
 *   modelled: the generator writes none of those extensions, and `pathLenConstraint` and nameConstraints depend on
 *   the path below a certificate, which this distance computation does not track. Fixtures (ar) and (as) cover them.
 * - A link is verified only when [verifier] answers `VERIFIED`; a throw counts as not verified, as §5.1 treats a
 *   verifier throw as `INVALID` "for any verifier" (P7 runs a throwing verifier). It catches [Exception], never an
 *   [Error], and must match what the 0.2 walker treats as a verifier throw.
 * - Exact-byte duplicates are one certificate. A certificate revokt's parser rejects is no candidate; an unparseable
 *   leaf has no keys. A leaf that is an anchor by bytes returns its own key (decision step 2).
 *
 * Key families (§5.1 `CandidateIndex.related()`) only order candidates, so they do not change the result and are not
 * modelled.
 *
 * [canonicalSubject] exists for relatedness tests only; the fuzzer runs both walkers with the platform canonicaliser
 * (§9.1).
 */
internal class ReferenceWalker(
    anchors: List<ByteArray>,
    private val verifier: SignatureVerifier,
    private val canonicalSubject: (ByteArray) -> String? = ::platformCanonicalSubject,
) {
    private val anchors: Map<ByteString, Node> = anchors.mapNotNull { node(it) }.associateBy { it.bytesHash }

    fun walk(presented: List<ByteArray>): Set<String> = walk(presented, byName = false)

    fun walkByName(presented: List<ByteArray>): Set<String> = walk(presented, byName = true)

    private fun walk(
        presented: List<ByteArray>,
        byName: Boolean,
    ): Set<String> {
        if (presented.isEmpty()) return emptySet()
        val leaf = node(presented[0]) ?: return emptySet()
        if (leaf.bytesHash in anchors) return setOf(leaf.spkiHash.hex())
        val others = LinkedHashMap<ByteString, Node>()
        for (der in presented.drop(1)) {
            val n = node(der) ?: continue
            if (n.bytesHash != leaf.bytesHash) others.putIfAbsent(n.bytesHash, anchors[n.bytesHash] ?: n)
        }
        val graph = Graph(others.values.toList(), leaf, byName)
        val maxDistance = RevoktLimits.MAX_DEPTH - 1 // [leaf, candidate, …, anchor] holds distance + 2 certificates
        val issuers = graph.candidates(leaf).filter { graph.verified(leaf, it) }
        val distances = graph.distances(issuers)
        return issuers
            .filter { (distances[it.bytesHash] ?: Int.MAX_VALUE) <= maxDistance }
            .map { it.spkiHash.hex() }
            .toSet()
    }

    /**
     * The certificates of one walk: [presented] (without the leaf) and the anchors, minus those that repeat [leaf]'s
     * raw subject and SPKI, with verified edges memoised; [byName] relates by name only.
     */
    private inner class Graph(
        private val presented: List<Node>,
        private val leaf: Node,
        private val byName: Boolean,
    ) {
        private val memo = HashMap<Pair<ByteString, ByteString>, Boolean>()
        private val edges = HashMap<ByteString, List<Node>>()

        fun candidates(child: Node): List<Node> {
            val store = anchors.values.filter { a -> presented.none { p -> p.bytesHash == a.bytesHash } }
            return (presented + store).filter {
                it.bytesHash != child.bytesHash &&
                    it.isRelatedTo(child, byName) &&
                    !it.repeats(leaf) &&
                    (it.isCa || it.bytesHash in anchors)
            }
        }

        fun verified(
            child: Node,
            candidate: Node,
        ): Boolean =
            memo.getOrPut(child.bytesHash to candidate.spkiHash) {
                try {
                    verifier.verify(child.tbsSigAlg, candidate.spki, child.tbs, child.signature) ==
                        VerifyResult.VERIFIED
                } catch (_: Exception) {
                    false
                }
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
        val isCa: Boolean = jdkIsCa(der)
        private val spkiRaw = spki.toByteString()
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

        fun isRelatedTo(
            child: Node,
            byName: Boolean,
        ): Boolean =
            subjectRaw == child.issuerRaw ||
                (subjectCanonical != null && subjectCanonical == child.issuerCanonical) ||
                (!byName && ski != null && ski == child.akiKeyId)

        /** The same raw subject and raw SPKI as [other]: the walker's loop (RFC 4158 §5.2). */
        fun repeats(other: Node): Boolean = subjectRaw == other.subjectRaw && spkiRaw == other.spkiRaw
    }

    companion object {
        /** The JDK's reading of [der]'s basicConstraints: `cA = TRUE`; false when absent or the JDK rejects [der]. */
        private fun jdkIsCa(der: ByteArray): Boolean =
            try {
                val x509 = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream())
                (x509 as X509Certificate).basicConstraints >= 0
            } catch (_: CertificateException) {
                false
            }

        /** Spec §3's JVM and Android canonicaliser: `X500Principal(der).getName(CANONICAL)`, null when it fails. */
        fun platformCanonicalSubject(name: ByteArray): String? =
            try {
                X500Principal(name).getName(X500Principal.CANONICAL)
            } catch (_: IllegalArgumentException) {
                null
            }
    }
}
