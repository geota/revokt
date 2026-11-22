<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The `reconstruct` pseudocode

Not normative. Moved out of the spec's §5.1 at revision 59 (#216), as it stood at revision 58, with revision 59's CA check on issuers and #226's one work budget, first-path stop and loop skip; milestone: 0.2 (explanatory). A note is promoted into the spec when its milestone starts, and edited there.

```kotlin
// Declarations the walker and the §9.1 harness compile against. Walk, WalkPath, Cert, CandidateIndex and reconstruct are `internal`
// to revokt-engine; the walker-only harness and the Jazzer walker fuzzer live in revokt-engine's own test source set; revokt-testing's
// reference walker takes List<ByteArray> and returns the Set<String> of lowercase-hex leaf-issuer SPKI hashes (value equality), so it needs no internal type.
internal class Cert(val der: ByteArray, val bytesHash: ByteString, val tbs: ByteArray /* the TBS re-encoded by the §9.2 unsigned-header rule: the verified message and the input of every TBS field */, val sig: ByteArray /* signatureValue content after the unused-bits octet, padding bits cleared (§9.2) */, val tbsSigAlg: ByteArray, val tbsSigOid: String, val issuer: IssuerProfile /* cA (pathLen ≤ 127), pathLen, keyCertSign, extKeyUsage; each failing closed (#237) */, val nameConstraints: NameConstraints? /* read on first use */, val presentedNames: List<PresentedName>? /* subjectAltName names, then the subject, then without a subjectAltName its emailAddress attributes; null when unreadable */, val presentedNamesAsServerLeaf: List<PresentedName>? /* the same plus the CN-ID, for the leaf of a serverAuth request */, val spki: ByteArray /* rawSpki TLV */, val spkiHash: ByteString, val keyOid: String, val curveOid: String?, val keyFamily: KeyFamily, val subjectRaw: ByteArray, val issuerRaw: ByteArray, val canonicalSubject: String?, val ski: ByteArray?, val akiKeyId: ByteArray?, val serial: ByteArray, val scts: List<CrliteSct>, val notBefore: Long? /* null when the time does not decode (§9.2; every JDK-accepted form decodes) */, val notAfter: Long?, val producerKeyable: Boolean, val keyabilityClause: KeyabilityClause? /* null ⇔ producerKeyable (§9.2 K1–K8); evaluated for the leaf at decision step 3 only */, val findings: List<Finding>)   // the §5.5/§9.2 parser's output; one object per certificate
internal class WalkPath(val certs: List<Cert>, val terminal: TerminalKind)   // leaf → … → terminal; distinct from Finding.Path
internal sealed interface Walk {                          // every variant carries unsupportedOids (the probe-listed own signature OIDs of explored non-anchor candidates, and the leaf once it had a candidate; revision 57), findings and stats: WalkStats (verifications, candidatesExplored), built at the three return sites
    class Found(val path: WalkPath, val leafKey: ByteString, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk   // the first sound path
    class NotFound(val reason: NoIssuerReason, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk
    class Budget(val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk   // the work budget spent before a path; never a path
}
/** Built once per snapshot, synchronously at wiring or inside start() (§5.1 "Anchor snapshot"), rebuilt on the loader by refreshAnchors() (~10 ms for 140 anchors on ART; ~150–200 ms for M2's 2,500 preload certificates):
 *  bySubjectRaw, bySubjectCanonical, bySki over store certificates, with canonicalSubject, keyFamily and spkiHash precomputed and exact-byte duplicates removed.
 *  The presented chain (≤ ~10 certificates) is scanned linearly per call; no maps are built for it. */
internal class CandidateIndex {
    fun related(presented: List<Cert>, child: Cert, seen: Set<ByteString>): Sequence<Cert>   // the only candidates, at every depth (revision 57, the maintainer's decision on #196, Firefox's order): the store's anchors, then the presented certificates by index, then (M2) the store's preload certificates (NSSCertDBTrustDomain FindIssuer: roots first, then intermediates). Within store, in order: raw-name matches, canonical-name matches, SKI matches; within each group candidates whose keyFamily is compatible with child.tbsSigOid's family first, incompatible last; ties by bytesHash. Byte-duplicates yielded once at the earliest position: the store's for an anchor; M2: the presented one for a preload certificate. The index is per snapshot and shared across calls, so the presented chain is an argument.
    fun isAnchorBytes(c: Cert): Boolean
    fun isPreloadBytes(c: Cert): Boolean                                                   // M2: the store's second candidate set (Mozilla's bytes), yielded by related() after the anchors and the presented certificates
}
internal class LruMap<K, V>(capacity: Int) { /* synchronized, access-ordered; put/get */ }

/** One walk's work budget, as webpki's Budget: explorations against MAX_EXPLORED, and name-constraint comparisons against 250,000, a separate unit. */
class WalkBudget { var explored = 0; fun explore(): Boolean; val comparisons: ComparisonBudget }

internal fun reconstruct(presented: List<Cert>, index: CandidateIndex, verifier: SignatureVerifier, probe: Set<String>, crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>, requiredEku: RequiredEku = SERVER_AUTH): Walk {
    val leaf = presented[0]
    val budget = WalkBudget(); val unsupported = mutableSetOf<String>(); val findings = mutableListOf<Finding>()
    var verifications = 0; var relatedAtLeaf = false; var verifiedAtLeaf = false   // leaf-level flags decide NoIssuerReason; deeper nodes never change it
    val memo = HashMap<Pair<ByteString, ByteString>, VerifyResult>()        // (child bytesHash, candidate spkiHash) → result

    fun verifyOnce(child: Cert, cand: Cert): VerifyResult {
        memo[child.bytesHash to cand.spkiHash]?.let { return it }
        crossCallMemo[child.bytesHash to cand.spkiHash]?.let { return it }   // per Revokt, VERIFIED only, CROSS_CALL_MEMO_ENTRIES, synchronized
        verifications++
        return verifier.verify(child.tbsSigAlg, cand.spki, child.tbs, child.sig).also { memo[child.bytesHash to cand.spkiHash] = it; if (it == VERIFIED) crossCallMemo.put(child.bytesHash to cand.spkiHash, it) }
    }

    fun loops(cand: Cert, path: List<Cert>) = path.any { it.subjectRaw == cand.subjectRaw && it.spki == cand.spki }   // RFC 4158 §5.2, as webpki and pkix compare: the leaf and the child included

    /** The first sound path through path.last(); DeadEnd when none within the depth bound; Spent when the budget ran out (the whole walk ends) */
    fun walk(path: List<Cert>, seen: Set<ByteString>): Step {
        if (path.size > MAX_DEPTH) return DeadEnd                                // a local dead end, not exhaustion
        val child = path.last(); val isLeaf = path.size == 1
        for (cand in index.related(presented, child, seen).filterNot { loops(it, path) }) {   // a loop is skipped like a certificate on the path: not a candidate, not charged
            if (isLeaf) relatedAtLeaf = true
            if (!budget.explore()) return Spent                                // the 257th is not explored
            if (isLeaf && child.tbsSigOid in probe) unsupported += child.tbsSigOid   // pkix order: issuer-independent before the link; the leaf deferred until it has an issuer
            if (!index.isAnchorBytes(cand) && cand.tbsSigOid in probe) unsupported += cand.tbsSigOid   // a key or curve OID never counts (decision step 6)
            if (!index.isAnchorBytes(cand) && !cand.issuer.mayIssue(path.size - 1, requiredEku)) continue   // before verifyOnce, as pkix checks the issuer before VerifySignedData
            when (cand.nameConstraints?.check(path, budget.comparisons)) { VIOLATION -> continue; EXHAUSTED -> return Spent; else -> {} }   // an anchor's too
            if (verifyOnce(child, cand) != VERIFIED) continue                    // INVALID and UNSUPPORTED are never trusted
            if (isLeaf) verifiedAtLeaf = true
            if (index.isAnchorBytes(cand)) return Path(path + cand)              // the first sound path ends the walk, at every depth
            when (val s = walk(path + cand, seen + cand.bytesHash)) { DeadEnd -> {}; else -> return s }
            // M2: a preload candidate with no anchor reachable through it is recorded as a preload-only path, a terminal of last resort
        }
        return DeadEnd
    }

    val step = walk(listOf(leaf), setOf(leaf.bytesHash))
    val stats = WalkStats(verifications, budget.explored)
    return when (step) {
        is Path -> Walk.Found(WalkPath(step.certs, ANCHOR), step.certs[1].spkiHash, unsupported, findings, stats)   // every path here has ≥ 2 certificates; the [leaf] case is decision step 2
        Spent   -> Walk.Budget(unsupported, findings, stats)
        DeadEnd -> Walk.NotFound(when { !relatedAtLeaf -> NO_CANDIDATE; !verifiedAtLeaf -> ALL_CANDIDATES_INVALID; else -> UNANCHORED }, unsupported, findings, stats)
    }
}
```
