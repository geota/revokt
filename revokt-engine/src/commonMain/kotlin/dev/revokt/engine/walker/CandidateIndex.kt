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

    private val bySubjectRaw: Map<ByteString, Group>
    private val bySubjectCanonical: Map<String, Group>
    private val bySki: Map<ByteString, Group>

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
        bySubjectRaw = sorted.groupByNotNull { it.subjectRaw.toByteString() }
        bySubjectCanonical = sorted.groupByNotNull { it.canonicalSubject }
        bySki = sorted.groupByNotNull { it.ski?.toByteString() }
    }

    /** [p] as a [Cert] under this index's canonicaliser. */
    fun cert(p: ParsedCertificate): Cert = Cert.of(p, canonicaliser)

    /**
     * The candidates related to [child], minus [seen] (bytes hashes), each exact-byte duplicate once at its earliest
     * position. At every depth the store's anchors come first, then the presented certificates by index, then (M2) the
     * store's non-anchors: Firefox's order (NSSCertDBTrustDomain::FindIssuer offers root-store candidates before the
     * others), so the reported path, the first found, does not depend on the order the server presents. Within the
     * store: raw-name matches, then canonical-name matches, then SKI matches; within each group the candidates whose
     * key family is compatible with `child.tbsSigOid` first, each part by bytesHash. Lazy: a walker that stops early (a
     * found path below the leaf, `MAX_RELATED_PER_LEVEL`) never pays for the rest of a large group. The sequence reads
     * [presented] and [seen] as it is iterated, so the caller must not mutate either while iterating it.
     */
    fun related(
        presented: List<Cert>,
        child: Cert,
        seen: Set<ByteString>,
    ): Sequence<Cert> {
        val fromPresented = presented.asSequence().filter { isRelated(it, child) }
        return distinct(storeRelated(child) + fromPresented, seen)
    }

    /**
     * The presented certificates not related to [child], by index, minus [seen], exact-byte duplicates once. Lazy, as
     * [related]: the caller must not mutate [presented] or [seen] while iterating it.
     */
    fun unrelated(
        presented: List<Cert>,
        child: Cert,
        seen: Set<ByteString>,
    ): Sequence<Cert> = distinct(presented.asSequence().filterNot { isRelated(it, child) }, seen)

    fun isAnchorBytes(c: Cert): Boolean = c.bytesHash in anchorBytes

    /** M2's preload set (spec §7.4); M1 has none. */
    @Suppress("UNUSED_PARAMETER", "FunctionOnlyReturningConstant") // §5.1's declared member, filled in M2
    fun isPreloadBytes(c: Cert): Boolean = false

    private fun storeRelated(child: Cert): Sequence<Cert> =
        sequence {
            val family = KeyFamily.ofSignature(child.tbsSigOid)
            val groups =
                listOf(
                    bySubjectRaw[child.issuerRaw.toByteString()],
                    child.canonicalIssuer?.let { bySubjectCanonical[it] },
                    child.akiKeyId?.let { bySki[it.toByteString()] },
                )
            for (group in groups) if (group != null) yieldAll(group.ordered(child.tbsSigOid, family))
        }

    private fun isRelated(
        candidate: Cert,
        child: Cert,
    ): Boolean =
        candidate.subjectRaw.contentEquals(child.issuerRaw) ||
            (candidate.canonicalSubject != null && candidate.canonicalSubject == child.canonicalIssuer) ||
            (candidate.ski != null && child.akiKeyId != null && candidate.ski.contentEquals(child.akiKeyId))

    private fun <K> List<Cert>.groupByNotNull(key: (Cert) -> K?): Map<K, Group> =
        mapNotNull { c -> key(c)?.let { it to c } }.groupBy({ it.first }, { it.second }).mapValues { Group(it.value) }

    /** [candidates] without [seen] and without bytes already yielded; a fresh filter per iteration. */
    private fun distinct(
        candidates: Sequence<Cert>,
        seen: Set<ByteString>,
    ): Sequence<Cert> =
        Sequence {
            val yielded = HashSet<ByteString>()
            candidates.filter { it.bytesHash !in seen && yielded.add(it.bytesHash) }.iterator()
        }

    /**
     * One store group (certificates sharing a raw subject, a canonical subject or an SKI), sorted by bytesHash, with its
     * family-compatible-first order precomputed at build for every signature class it can meet: an unknown signature
     * (the group as it is), RSA, EC, and for EdDSA, ML-DSA and SLH-DSA each key OID in the group plus "none matches".
     */
    private class Group(
        private val all: List<Cert>,
    ) {
        private val rsa = order("", KeyFamily.RSA)
        private val ec = order("", KeyFamily.EC)

        // For a same-OID family only the key OID decides, and a signature OID no key here carries leaves the UNKNOWN keys.
        private val noSameOid = order("", KeyFamily.EDDSA)
        private val bySameOid: Map<String, List<Cert>> =
            all
                .filter {
                    it.keyFamily != KeyFamily.UNKNOWN && it.keyFamily != KeyFamily.RSA &&
                        it.keyFamily != KeyFamily.EC
                }.map { it.keyOid }
                .distinct()
                .associateWith { order(it, KeyFamily.ofSignature(it)) }

        fun ordered(
            signatureOid: String,
            family: KeyFamily,
        ): List<Cert> =
            when (family) {
                KeyFamily.UNKNOWN -> all
                KeyFamily.RSA -> rsa
                KeyFamily.EC -> ec
                else -> bySameOid[signatureOid] ?: noSameOid
            }

        private fun order(
            signatureOid: String,
            family: KeyFamily,
        ): List<Cert> {
            val (compatible, incompatible) = all.partition { KeyFamily.compatible(it, signatureOid, family) }
            return compatible + incompatible
        }
    }
}
