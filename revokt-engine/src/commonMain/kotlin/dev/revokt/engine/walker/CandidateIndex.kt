// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * The walker's candidate source for one anchor snapshot (spec §5.1 declarations and deferral rule), built once and
 * shared by every handshake on it. The store is [store]: the snapshot's certificates that revokt's parser reads, exact
 * byte duplicates removed, so an anchor the parser drops never matches (decision step 2). It is indexed by raw subject,
 * canonical subject and SKI; the presented chain (at most `MAX_PRESENTED` certificates) is an argument, scanned linearly.
 *
 * A candidate is **related** to a child when its subject equals the child's issuer as raw bytes or under the
 * canonicaliser, or its SKI equals the child's AKI `keyIdentifier`; a child whose AKI has no `keyIdentifier` (the
 * issuer-and-serial form) or a candidate without an SKI is matched by name only. Nothing is excluded for a property it
 * shares with another candidate: only certificates in `seen` and exact byte duplicates are skipped.
 *
 * [customCanonicaliser] is §3's class check, decided by the caller: the walker's leaf rule reads it. [canonicaliser]
 * defaults to §3's [canonicalSubject]; a `PlatformTrust` override is passed here, and [cert] applies it to presented
 * certificates so both sides of the canonical test use the same function.
 */
internal class CandidateIndex(
    anchors: List<ByteArray>,
    val customCanonicaliser: Boolean = false,
    private val canonicaliser: (ByteArray) -> String? = ::canonicalSubject,
) {
    /** The parsed anchors in snapshot order, each exact-byte duplicate after the first removed. */
    val store: List<Cert>

    private val anchorBytes: Set<ByteString>

    // Each list sorted by bytesHash, the tie-break of related()'s store order.
    private val bySubjectRaw: Map<ByteString, List<Cert>>
    private val bySubjectCanonical: Map<String, List<Cert>>
    private val bySki: Map<ByteString, List<Cert>>

    init {
        val unique = LinkedHashMap<ByteString, Cert>()
        for (der in anchors) {
            val parsed = CertificateParser.parse(der) as? CertificateParse.Parsed ?: continue
            val c = cert(parsed.certificate)
            unique.getOrPut(c.bytesHash) { c }
        }
        store = unique.values.toList()
        anchorBytes = unique.keys
        val sorted = store.sortedBy { it.bytesHash }
        bySubjectRaw = sorted.groupBy { it.subjectRaw.toByteString() }
        bySubjectCanonical = sorted.groupByNotNull { it.canonicalSubject }
        bySki = sorted.groupByNotNull { it.ski?.toByteString() }
    }

    /** [p] as a [Cert] under this index's canonicaliser. */
    fun cert(p: ParsedCertificate): Cert = Cert.of(p, canonicaliser)

    /**
     * The candidates related to [child], minus [seen] (bytes hashes), each exact-byte duplicate once at its earliest
     * position. At the leaf (`belowLeaf == false`) the presented ones come first, by index, then the store; below it
     * the store comes first (its certificates are terminals in M1), then the presented ones. Within the store: raw-name
     * matches, then canonical-name matches, then SKI matches; within each group the candidates whose key family is
     * compatible with `child.tbsSigOid` first, each part by bytesHash.
     */
    fun related(
        presented: List<Cert>,
        child: Cert,
        seen: Set<ByteString>,
        belowLeaf: Boolean,
    ): Sequence<Cert> {
        val out = Distinct(seen)
        if (belowLeaf) {
            out.addAll(store(child))
            out.addAll(presented.filter { isRelated(it, child) })
        } else {
            out.addAll(presented.filter { isRelated(it, child) })
            out.addAll(store(child))
        }
        return out.list.asSequence()
    }

    /** The presented certificates not related to [child], by index, minus [seen], exact-byte duplicates once. */
    fun unrelated(
        presented: List<Cert>,
        child: Cert,
        seen: Set<ByteString>,
    ): Sequence<Cert> = Distinct(seen).apply { addAll(presented.filterNot { isRelated(it, child) }) }.list.asSequence()

    fun isAnchorBytes(c: Cert): Boolean = c.bytesHash in anchorBytes

    /** M2's preload set (spec §7.4); M1 has none. */
    @Suppress("UNUSED_PARAMETER", "FunctionOnlyReturningConstant") // §5.1's declared member, filled in M2
    fun isPreloadBytes(c: Cert): Boolean = false

    private fun store(child: Cert): List<Cert> {
        val family = KeyFamily.ofSignature(child.tbsSigOid)
        val groups =
            listOfNotNull(
                bySubjectRaw[child.issuerRaw.toByteString()],
                child.canonicalIssuer?.let { bySubjectCanonical[it] },
                child.akiKeyId?.let { bySki[it.toByteString()] },
            )
        return groups.flatMap { group ->
            val (compatible, incompatible) = group.partition { KeyFamily.compatible(it, child.tbsSigOid, family) }
            compatible + incompatible
        }
    }

    private fun isRelated(
        candidate: Cert,
        child: Cert,
    ): Boolean =
        candidate.subjectRaw.contentEquals(child.issuerRaw) ||
            (candidate.canonicalSubject != null && candidate.canonicalSubject == child.canonicalIssuer) ||
            (candidate.ski != null && child.akiKeyId != null && candidate.ski.contentEquals(child.akiKeyId))

    private fun <K> List<Cert>.groupByNotNull(key: (Cert) -> K?): Map<K, List<Cert>> =
        mapNotNull { c -> key(c)?.let { it to c } }.groupBy({ it.first }, { it.second })

    /** Candidates in order, skipping [seen] and any bytes already added. */
    private class Distinct(
        private val seen: Set<ByteString>,
    ) {
        private val added = HashSet<ByteString>()
        val list = ArrayList<Cert>()

        fun addAll(candidates: List<Cert>) {
            for (c in candidates) if (c.bytesHash !in seen && added.add(c.bytesHash)) list += c
        }
    }
}
