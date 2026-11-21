<!-- SPDX-FileCopyrightText: 2026 revokt contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The `reconstruct` pseudocode

Not normative. Moved out of the spec's §5.1 at revision 59 (#216), as it stood at revision 58, with revision 59's CA check on issuers; milestone: 0.2 (explanatory). A note is promoted into the spec when its milestone starts, and edited there.

```kotlin
// Declarations the walker and the §9.1 harness compile against. Walk, WalkPath, Cert, CandidateIndex and reconstruct are `internal`
// to revokt-engine; the walker-only harness and the Jazzer walker fuzzer live in revokt-engine's own test source set; revokt-testing's
// reference walker takes List<ByteArray> and returns the Set<String> of lowercase-hex leaf-issuer SPKI hashes (value equality), so it needs no internal type.
internal class Cert(val der: ByteArray, val bytesHash: ByteString, val tbs: ByteArray /* the TBS re-encoded by the §9.2 unsigned-header rule: the verified message and the input of every TBS field */, val sig: ByteArray /* signatureValue content after the unused-bits octet, padding bits cleared (§9.2) */, val tbsSigAlg: ByteArray, val tbsSigOid: String, val issuer: IssuerProfile /* cA (pathLen ≤ 127), pathLen, keyCertSign, extKeyUsage; each failing closed (#237) */, val nameConstraints: NameConstraints? /* read on first use */, val presentedNames: List<PresentedName>? /* subjectAltName names, then the subject, then without a subjectAltName its emailAddress attributes; null when unreadable */, val presentedNamesAsServerLeaf: List<PresentedName>? /* the same plus the CN-ID, for the leaf of a serverAuth request */, val spki: ByteArray /* rawSpki TLV */, val spkiHash: ByteString, val keyOid: String, val curveOid: String?, val keyFamily: KeyFamily, val subjectRaw: ByteArray, val issuerRaw: ByteArray, val canonicalSubject: String?, val ski: ByteArray?, val akiKeyId: ByteArray?, val serial: ByteArray, val scts: List<CrliteSct>, val notBefore: Long? /* null when the time does not decode (§9.2; every JDK-accepted form decodes) */, val notAfter: Long?, val producerKeyable: Boolean, val keyabilityClause: KeyabilityClause? /* null ⇔ producerKeyable (§9.2 K1–K8); evaluated for the leaf at decision step 3 only */, val findings: List<Finding>)   // the §5.5/§9.2 parser's output; one object per certificate
internal class WalkPath(val certs: List<Cert>, val terminal: TerminalKind)   // leaf → … → terminal; distinct from Finding.Path
internal sealed interface Walk {                          // every variant carries unsupportedOids (the probe-listed own signature OIDs of explored related non-anchors, unrelated-loop nodes, and the leaf once it had a related candidate; revision 57), findings and stats: WalkStats (verifications, candidatesExplored, relatedExploredAtLeaf, unrelatedExploredAtLeaf), built at the three return sites
    class Found(val paths: List<WalkPath>, val leafKeys: Set<ByteString>, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk
    class NotFound(val reason: NoIssuerReason, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk
    class Budget(val end: WalkEnd, val endDepth: Int, val partialPaths: List<WalkPath>, val partialLeafKeys: Set<ByteString>, val unsupportedOids: Set<String>, val findings: List<Finding>, val stats: WalkStats) : Walk
}
/** Built once per snapshot, synchronously at wiring or inside start() (§5.1 "Anchor snapshot"), rebuilt on the loader by refreshAnchors() (~10 ms for 140 anchors on ART; ~150–200 ms for M2's 2,500 preload certificates):
 *  bySubjectRaw, bySubjectCanonical, bySki over store certificates, with canonicalSubject, keyFamily and spkiHash precomputed and exact-byte duplicates removed.
 *  The presented chain (≤ ~10 certificates) is scanned linearly per call; no maps are built for it. */
internal class CandidateIndex {
    fun related(presented: List<Cert>, child: Cert, seen: Set<ByteString>): Sequence<Cert>   // at every depth (revision 57, the maintainer's decision on #196, Firefox's order): the store's anchors, then the presented certificates by index, then (M2) the store's preload certificates (NSSCertDBTrustDomain FindIssuer: roots first, then intermediates). Within store, in order: raw-name matches, canonical-name matches, SKI matches; within each group candidates whose keyFamily is compatible with child.tbsSigOid's family first, incompatible last; ties by bytesHash. Byte-duplicates yielded once at the earliest position: the store's for an anchor; M2: the presented one for a preload certificate. The index is per snapshot and shared across calls, so the presented chain is an argument.
    fun unrelated(presented: List<Cert>, child: Cert, seen: Set<ByteString>): Sequence<Cert>   // the presented certificates NOT in related(child), by index
    fun isAnchorBytes(c: Cert): Boolean
    fun isPreloadBytes(c: Cert): Boolean                                                   // M2: the store's second candidate set (Mozilla's bytes), yielded by related() after the anchors and the presented certificates
    val customCanonicaliser: Boolean                                                        // platformTrust is not one of the two shipped final classes, or the delegate is not platformTrust.defaultDelegate() (§3, a class check); §5.1 deferral rule
}
internal class LruMap<K, V>(capacity: Int) { /* synchronized, access-ordered; put/get */ }

internal fun reconstruct(presented: List<Cert>, index: CandidateIndex, verifier: SignatureVerifier, probe: Set<String>, crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>, requiredEku: RequiredEku = SERVER_AUTH): Walk {
    val leaf = presented[0]
    val found = mutableListOf<WalkPath>(); val unsupported = mutableSetOf<String>(); val findings = mutableListOf<Finding>()
    var verifications = 0; var explored = 0; var relatedAtLeaf = false; var verifiedAtLeaf = false   // leaf-level flags decide NoIssuerReason; deeper nodes never change it
    var relatedExploredAtLeaf = 0; var unrelatedExploredAtLeaf = 0
    var endDepth = 0                                                                                // set to path.size at the node where a limit is detected, before unwinding
    val memo = HashMap<Pair<ByteString, ByteString>, VerifyResult>()        // (child bytesHash, candidate spkiHash) → result

    fun verifyOnce(child: Cert, cand: Cert): VerifyResult? {               // null = VERIFICATION_BUDGET
        memo[child.bytesHash to cand.spkiHash]?.let { return it }
        crossCallMemo[child.bytesHash to cand.spkiHash]?.let { return it }   // per Revokt, VERIFIED only, CROSS_CALL_MEMO_ENTRIES, synchronized
        if (verifications >= MAX_VERIFICATIONS) return null
        verifications++
        return verifier.verify(child.tbsSigAlg, cand.spki, child.tbs, child.sig).also { memo[child.bytesHash to cand.spkiHash] = it; if (it == VERIFIED) crossCallMemo.put(child.bytesHash to cand.spkiHash, it) }
    }

    /** null when the node completed; a WalkEnd when any limit stopped the walk */
    fun walk(child: Cert, path: List<Cert>, seen: Set<ByteString>): WalkEnd? {
        if (path.size > MAX_DEPTH) return null                                // dead end
        val isLeaf = path.size == 1
        var foundHere = false; var related = 0
        if (!isLeaf && child.tbsSigOid in probe) unsupported += child.tbsSigOid   // a node that verified its child: an unrelated-loop node (a related one was already counted as a candidate)

        fun explore(cand: Cert, isRelated: Boolean): WalkEnd? {
            if (explored >= MAX_EXPLORED) { endDepth = path.size; return EXPLORATION_BUDGET }
            explored++
            if (isRelated) { if (isLeaf && child.tbsSigOid in probe) unsupported += child.tbsSigOid; if (!index.isAnchorBytes(cand) && cand.tbsSigOid in probe) unsupported += cand.tbsSigOid }   // pkix order: issuer-independent before the link; the leaf deferred until it has an issuer; a key or curve OID never counts (decision step 6)
            if (!index.isAnchorBytes(cand) && !cand.issuer.mayIssue(path.size - 1, requiredEku)) return null   // before verifyOnce, as pkix checks the issuer before VerifySignedData
            when (cand.nameConstraints?.check(path, comparisonBudget)) { VIOLATION -> return null; EXHAUSTED -> return Budget(EXPLORATION_BUDGET); else -> {} }   // an anchor's too
            when (verifyOnce(child, cand) ?: run { endDepth = path.size; return VERIFICATION_BUDGET }) {
                INVALID -> return null
                UNSUPPORTED -> return null
                VERIFIED -> { if (isLeaf) verifiedAtLeaf = true }
            }
            val before = found.size
            if (index.isAnchorBytes(cand)) {
                found += WalkPath(path + cand, terminal = ANCHOR)
            } else {
                walk(cand, path + cand, seen + cand.bytesHash)?.let { return it }
                if (found.size == before && index.isPreloadBytes(cand)) found += WalkPath(path + cand, terminal = PRELOAD)   // M2: preload-only path, recorded only when no anchor is reachable through it (invariant); a terminal of last resort
            }
            if (found.size > before) foundHere = true
            return null
        }

        for (cand in index.related(presented, child, seen)) {
            if (isLeaf) relatedAtLeaf = true
            if (!isLeaf && foundHere) break
            if (related >= MAX_RELATED_PER_LEVEL) { endDepth = path.size; return RELATED_BUDGET }   // the 65th related candidate is not explored
            related++; if (isLeaf) relatedExploredAtLeaf++
            explore(cand, isRelated = true)?.let { return it }
        }
        val relatedPath = foundHere                                                     // a path through a related candidate exists at this node
        for (cand in index.unrelated(presented, child, seen)) { if (foundHere && !(isLeaf && (index.customCanonicaliser || !relatedPath))) break; if (isLeaf) unrelatedExploredAtLeaf++; explore(cand, isRelated = false)?.let { return it } }   // stops as soon as a path exists, except at the leaf under a custom canonicaliser (deferral rule) or with no related path (every unrelated issuer is collected, revision 48)
        return null
    }

    val end = walk(leaf, listOf(leaf), setOf(leaf.bytesHash))          // endDepth is recorded where the WalkEnd originated
    val leafKeys = found.map { it.certs[1].spkiHash }.toSet()            // every found path here has ≥ 2 certificates; the [leaf] case is decision step 2
    val stats = WalkStats(verifications, explored, relatedExploredAtLeaf, unrelatedExploredAtLeaf)
    return when {
        end != null        -> Walk.Budget(end, endDepth, found, leafKeys, unsupported, findings, stats)   // some node did not complete
        found.isNotEmpty() -> Walk.Found(found, leafKeys, unsupported, findings, stats)
        else               -> Walk.NotFound(when { !relatedAtLeaf -> NO_CANDIDATE; !verifiedAtLeaf -> ALL_CANDIDATES_INVALID; else -> UNANCHORED }, unsupported, findings, stats)
    }
}
```
