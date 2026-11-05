// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.SignatureVerifier
import dev.revokt.TerminalKind
import dev.revokt.VerifyResult
import dev.revokt.WalkEnd
import dev.revokt.WalkStats
import dev.revokt.verify.verifyClassified
import okio.ByteString

/**
 * Spec §5.1 `reconstruct`: every sound path from the leaf, `presented[0]`, to an anchor of [index], under the budgets of
 * §5.1's limits table. It follows §5.1's pseudocode line for line; the comments name the rules it implements.
 *
 * - A link is trusted only when [verifier] answers `VERIFIED`. Each (child, candidate key) pair is verified once per
 *   walk (the per-walk memo), and a `VERIFIED` pair once per [crossCallMemo] lifetime; a memo hit costs an exploration
 *   but no verification. A verifier throw is `INVALID` plus a `Finding.VerifierError` with the child's signature OID;
 *   only a fatal error (§5.5, [isFatal]) propagates, so the walk never throws otherwise.
 * - At the leaf every related candidate is explored; below it the first sound path suffices. Unrelated candidates are
 *   explored only while no path exists through the node, except at the leaf when [index] has a custom canonicaliser
 *   or no related path exists there (revision 48): then every unrelated one is.
 * - `MAX_DEPTH` is a local dead end. Any other limit aborts the whole walk with [Walk.Budget], which records the path
 *   size where the limit was detected and keeps the paths found so far.
 * - `UNSUPPORTED` adds the child's own signature OID to `unsupportedOids` only against a related candidate and only
 *   when [probe] lists it; a candidate's key or curve OID never counts (§10 item 14).
 *
 * [presented] must not be empty (decision step 3 parsed the leaf); it is read, never changed.
 */
internal fun reconstruct(
    presented: List<Cert>,
    index: CandidateIndex,
    verifier: SignatureVerifier,
    probe: Set<String>,
    crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>,
): Walk {
    require(presented.isNotEmpty()) { "reconstruct needs the leaf: the presented chain is empty" }
    return Reconstruction(presented, index, verifier, probe, crossCallMemo).run()
}

/** One walk's state: the pseudocode's locals, with `walk` and `explore` as [Node]'s methods. */
private class Reconstruction(
    private val presented: List<Cert>,
    private val index: CandidateIndex,
    private val verifier: SignatureVerifier,
    private val probe: Set<String>,
    private val crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>,
) {
    private val found = ArrayList<WalkPath>()
    private val unsupported = LinkedHashSet<String>()
    private val findings = ArrayList<Finding>()
    private var verifications = 0
    private var explored = 0

    // The leaf-level flags decide the NoIssuerReason; deeper nodes never change it.
    private var relatedAtLeaf = false
    private var verifiedAtLeaf = false
    private var relatedExploredAtLeaf = 0
    private var unrelatedExploredAtLeaf = 0

    /** The path size at the node where a limit was detected, set before unwinding. */
    private var endDepth = 0

    /** (child bytesHash, candidate spkiHash) → result. */
    private val memo = HashMap<Pair<ByteString, ByteString>, VerifyResult>()

    @OptIn(RevoktInternalApi::class)
    fun run(): Walk {
        val leaf = presented[0]
        val end = walk(leaf, listOf(leaf), setOf(leaf.bytesHash))
        // Every path found here has at least two certificates; the anchor leaf is decision step 2.
        val leafKeys = found.mapTo(LinkedHashSet()) { it.certs[1].spkiHash }
        val stats = WalkStats(verifications, explored, relatedExploredAtLeaf, unrelatedExploredAtLeaf)
        return when {
            end != null -> Walk.Budget(end, endDepth, found.toList(), leafKeys, unsupported, findings, stats)
            found.isNotEmpty() -> Walk.Found(found.toList(), leafKeys, unsupported, findings, stats)
            else -> Walk.NotFound(reason(), unsupported, findings, stats)
        }
    }

    private fun reason(): NoIssuerReason =
        when {
            !relatedAtLeaf -> NoIssuerReason.NO_CANDIDATE
            !verifiedAtLeaf -> NoIssuerReason.ALL_CANDIDATES_INVALID
            else -> NoIssuerReason.UNANCHORED
        }

    /** The memoised verification of [child] under [candidate]'s key; null when `MAX_VERIFICATIONS` stops it. */
    private fun verifyOnce(
        child: Cert,
        candidate: Cert,
    ): VerifyResult? {
        val key = child.bytesHash to candidate.spkiHash
        memo[key]?.let { return it }
        crossCallMemo[key]?.let { return it }
        // The guard-tripping attempt is not counted.
        if (verifications >= RevoktLimits.MAX_VERIFICATIONS) return null
        verifications++
        val classified = verifier.verifyClassified(child.tbsSigAlg, candidate.spki, child.tbs, child.sig)
        classified.error?.let { findings += Finding.VerifierError.of(child.tbsSigOid, it) }
        memo[key] = classified.result
        if (classified.result == VerifyResult.VERIFIED) crossCallMemo.put(key, VerifyResult.VERIFIED)
        return classified.result
    }

    /** null when the node completed; a [WalkEnd] when a limit stopped the walk. */
    private fun walk(
        child: Cert,
        path: List<Cert>,
        seen: Set<ByteString>,
    ): WalkEnd? {
        if (path.size > RevoktLimits.MAX_DEPTH) return null // a dead end, not exhaustion
        return Node(child, path, seen).walk()
    }

    private inner class Node(
        private val child: Cert,
        private val path: List<Cert>,
        private val seen: Set<ByteString>,
    ) {
        private val isLeaf = path.size == 1
        private var foundHere = false
        private var related = 0

        // The candidate sequences read `presented` and `seen` lazily; neither is changed while they are iterated.
        fun walk(): WalkEnd? = exploreRelated() ?: exploreUnrelated(relatedPath = foundHere)

        private fun exploreRelated(): WalkEnd? {
            for (candidate in index.related(presented, child, seen, belowLeaf = !isLeaf)) {
                if (isLeaf) relatedAtLeaf = true
                if (!isLeaf && foundHere) break
                if (related >= RevoktLimits.MAX_RELATED_PER_LEVEL) {
                    // The 65th related candidate is not explored.
                    endDepth = path.size
                    return WalkEnd.RELATED_BUDGET
                }
                related++
                if (isLeaf) relatedExploredAtLeaf++
                explore(candidate, isRelated = true)?.let { return it }
            }
            return null
        }

        /** [relatedPath]: a path through a related candidate exists at this node. */
        private fun exploreUnrelated(relatedPath: Boolean): WalkEnd? {
            // Stops as soon as a path exists, except at the leaf under a custom canonicaliser (deferral rule) or with no
            // related path (every unrelated issuer is collected, revision 48).
            val collectAll = isLeaf && (index.customCanonicaliser || !relatedPath)
            for (candidate in index.unrelated(presented, child, seen)) {
                if (foundHere && !collectAll) break
                if (isLeaf) unrelatedExploredAtLeaf++
                explore(candidate, isRelated = false)?.let { return it }
            }
            return null
        }

        private fun explore(
            candidate: Cert,
            isRelated: Boolean,
        ): WalkEnd? {
            if (explored >= RevoktLimits.MAX_EXPLORED) {
                endDepth = path.size
                return WalkEnd.EXPLORATION_BUDGET
            }
            explored++
            val result = verifyOnce(child, candidate)
            when (result) {
                null -> {
                    endDepth = path.size
                    return WalkEnd.VERIFICATION_BUDGET
                }

                VerifyResult.INVALID -> {
                    return null
                }

                VerifyResult.UNSUPPORTED -> {
                    // Only the child's own signature OID counts toward ISSUER_UNVERIFIED (decision step 6); a
                    // candidate's key or curve OID is server-chosen.
                    if (isRelated && child.tbsSigOid in probe) unsupported += child.tbsSigOid
                    return null
                }

                VerifyResult.VERIFIED -> {
                    if (isLeaf) verifiedAtLeaf = true
                }
            }
            val before = found.size
            if (index.isAnchorBytes(candidate)) {
                found += WalkPath(path + candidate, TerminalKind.ANCHOR)
            } else {
                walk(candidate, path + candidate, seen + candidate.bytesHash)?.let { return it }
                // M2 records a preload-only path here when none was found through the candidate (§5.1 invariant).
            }
            if (found.size > before) foundHere = true
            return null
        }
    }
}
