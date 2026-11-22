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
import dev.revokt.WalkStats
import dev.revokt.verify.verifyClassified
import okio.ByteString

/**
 * Spec §5.1 `reconstruct`: the first sound path from the leaf, `presented[0]`, to an anchor of [index], depth first,
 * under one work budget, as webpki's `build_chain` and mozilla::pkix's `BuildForward` search. The comments name the
 * rules it implements.
 *
 * - **Candidates** of a node are [CandidateIndex.related]'s, in its order at every depth: the store's anchors, then the
 *   presented certificates by index. A store anchor that issues a node is therefore always tried first, whatever the
 *   server presents. No other certificate is a candidate.
 * - **Loops:** a candidate whose raw subject and raw SPKI equal those of a certificate on the path, the leaf and the
 *   node included, is skipped like a certificate already on the path, before any work is charged (RFC 4158 §5.2, as
 *   webpki and mozilla::pkix compare).
 * - **The budget** ([WalkBudget]): every other candidate is one exploration, charged before anything is checked;
 *   [RevoktLimits.MAX_EXPLORED] explorations, and [NameConstraints.MAX_COMPARISONS] name-constraint comparisons, per
 *   walk. Spending either aborts the whole walk with [Walk.Budget]; `MAX_DEPTH` is a local dead end.
 * - A candidate that is not an anchor must be able to issue ([IssuerProfile.mayIssue]): a CA (basicConstraints
 *   `cA = TRUE`, #225), within its `pathLenConstraint`, with `keyCertSign` when it has keyUsage, and listing
 *   [requiredEku] when it has extKeyUsage (#237), as webpki and mozilla::pkix require of every issuer. One that cannot
 *   is a dead end before its link is verified, as pkix runs the issuer's checks before `VerifySignedData`; its own
 *   signature OID is still counted. At the leaf it leaves `ALL_CANDIDATES_INVALID` possible: no issuer verified.
 * - A link is trusted only when [verifier] answers `VERIFIED`. Each (child, candidate key) pair is verified once per
 *   walk (the per-walk memo), and a `VERIFIED` pair once per [crossCallMemo] lifetime; a memo hit costs an exploration
 *   but no verification. A verifier throw is `INVALID` plus a `Finding.VerifierError` with the child's signature OID;
 *   only a fatal error (§5.5, [isFatal]) propagates, so the walk never throws otherwise.
 * - **The first sound path ends the walk**, at every depth, the leaf included, as both references stop: [Walk.Found]
 *   carries that one path and its leaf-issuer key. A [Walk.Budget] therefore never carries a path.
 * - `unsupportedOids` follows mozilla::pkix's issuer-independent check (CheckIssuerIndependentProperties, run before
 *   the link's VerifySignedData): every explored candidate that is not an anchor adds its own signature OID when [probe]
 *   lists it, whether or not it verifies the child. The leaf's own OID is deferred, as pkix defers an end-entity
 *   error: it counts only when a candidate was explored at the leaf, so a leaf with no candidate stays `NO_CANDIDATE`.
 *   A candidate's key or curve OID never counts, and an `UNSUPPORTED` link is never trusted (§5.1 soundness). The OIDs
 *   are recorded on every outcome: on a `Found` walk they are diagnostics only (`UnsupportedAlgorithm(outcomeDepended =
 *   false)`), which is expected, since a server can add such a candidate on a dead branch (fixture (n)).
 *
 * [presented] must not be empty (decision step 3 parsed the leaf); it is read, never changed.
 */
internal fun reconstruct(
    presented: List<Cert>,
    index: CandidateIndex,
    verifier: SignatureVerifier,
    probe: Set<String>,
    crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>,
    requiredEku: RequiredEku = RequiredEku.SERVER_AUTH,
): Walk {
    require(presented.isNotEmpty()) { "reconstruct needs the leaf: the presented chain is empty" }
    return Reconstruction(presented, index, verifier, probe, crossCallMemo, requiredEku).run()
}

/**
 * One walk's work budget (spec §5.1 limits), as webpki's `Budget`: [explore] charges one exploration against
 * [RevoktLimits.MAX_EXPLORED], and [comparisons] charges one name-constraint comparison against
 * [NameConstraints.MAX_COMPARISONS], a separate unit, as webpki counts it. A false answer means the walk is spent.
 */
private class WalkBudget {
    var explored = 0
        private set
    private var compared = 0

    /** Charges one exploration; false, charging nothing, when `MAX_EXPLORED` were already charged. */
    fun explore(): Boolean = if (explored >= RevoktLimits.MAX_EXPLORED) false else true.also { explored++ }

    val comparisons =
        ComparisonBudget {
            if (compared >= NameConstraints.MAX_COMPARISONS) false else true.also { compared++ }
        }
}

/** A node's search result: [Path] is the first sound path through it. */
private sealed interface Step {
    class Path(
        val certs: List<Cert>,
    ) : Step

    /** No sound path through the node, within the depth bound. */
    data object DeadEnd : Step

    /** The budget is spent: the whole walk ends. */
    data object Spent : Step
}

/** One walk's state: the leaf-level flags, the budget, the memo and what was recorded. */
private class Reconstruction(
    private val presented: List<Cert>,
    private val index: CandidateIndex,
    private val verifier: SignatureVerifier,
    private val probe: Set<String>,
    private val crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>,
    private val requiredEku: RequiredEku,
) {
    private val budget = WalkBudget()
    private val unsupported = LinkedHashSet<String>()
    private val findings = ArrayList<Finding>()
    private var verifications = 0

    // The leaf-level flags decide the NoIssuerReason; deeper nodes never change it.
    private var relatedAtLeaf = false
    private var verifiedAtLeaf = false

    /** (child bytesHash, candidate spkiHash) → result. */
    private val memo = HashMap<Pair<ByteString, ByteString>, VerifyResult>()

    @OptIn(RevoktInternalApi::class)
    fun run(): Walk {
        val leaf = presented[0]
        val step = walk(listOf(leaf), setOf(leaf.bytesHash))
        val stats = WalkStats(verifications, budget.explored)
        return when (step) {
            // Every path found here has at least two certificates; the anchor leaf is decision step 2.
            is Step.Path -> {
                val path = WalkPath(step.certs, TerminalKind.ANCHOR)
                Walk.Found(path, step.certs[1].spkiHash, unsupported, findings, stats)
            }

            Step.DeadEnd -> {
                Walk.NotFound(reason(), unsupported, findings, stats)
            }

            Step.Spent -> {
                Walk.Budget(unsupported, findings, stats)
            }
        }
    }

    private fun reason(): NoIssuerReason =
        when {
            !relatedAtLeaf -> NoIssuerReason.NO_CANDIDATE
            !verifiedAtLeaf -> NoIssuerReason.ALL_CANDIDATES_INVALID
            else -> NoIssuerReason.UNANCHORED
        }

    /** Adds [c]'s own signature OID to `unsupportedOids` when the probe lists it; a key or curve OID never counts. */
    private fun countOwn(c: Cert) {
        if (c.tbsSigOid in probe) unsupported += c.tbsSigOid
    }

    /** The memoised verification of [child] under [candidate]'s key. */
    private fun verifyOnce(
        child: Cert,
        candidate: Cert,
    ): VerifyResult {
        val key = child.bytesHash to candidate.spkiHash
        memo[key]?.let { return it }
        crossCallMemo[key]?.let { return it }
        verifications++
        val classified = verifier.verifyClassified(child.tbsSigAlg, candidate.spki, child.tbs, child.sig)
        classified.error?.let { findings += Finding.VerifierError.of(child.tbsSigOid, it) }
        memo[key] = classified.result
        if (classified.result == VerifyResult.VERIFIED) crossCallMemo.put(key, VerifyResult.VERIFIED)
        return classified.result
    }

    /**
     * The first sound path through the last certificate of [path] (leaf first, every link verified); [seen] is its
     * certificates' bytes hashes. A path of more than `MAX_DEPTH` certificates is a dead end, not exhaustion.
     */
    private fun walk(
        path: List<Cert>,
        seen: Set<ByteString>,
    ): Step {
        if (path.size > RevoktLimits.MAX_DEPTH) return Step.DeadEnd
        val child = path.last()
        val isLeaf = path.size == 1
        // The candidate sequence reads `presented` and `seen` lazily; neither is changed while it is iterated. A loop
        // is filtered out like a certificate on the path: never related at the leaf, never charged.
        for (candidate in index.related(presented, child, seen).filterNot { loops(it, path) }) {
            if (isLeaf) relatedAtLeaf = true
            if (!budget.explore()) return Step.Spent
            val step = explore(candidate, path, seen, isLeaf)
            if (step != Step.DeadEnd) return step
        }
        return Step.DeadEnd
    }

    /** [candidate] has the raw subject and raw SPKI of a certificate on [path] (RFC 4158 §5.2's loop). */
    private fun loops(
        candidate: Cert,
        path: List<Cert>,
    ): Boolean = path.any { it.subjectRaw.contentEquals(candidate.subjectRaw) && it.spki.contentEquals(candidate.spki) }

    /**
     * Decision step 6's issuer-independent check, in Firefox's order: a candidate that is not an anchor counts its own
     * signature OID before its link is verified, whether or not it verifies the child (CheckIssuerIndependentProperties
     * runs before VerifySignedData). The leaf's own OID is deferred, as pkix defers an end-entity error: it counts only
     * once a candidate, an issuer, was found for it.
     */
    private fun countIssuerIndependent(
        child: Cert,
        candidate: Cert,
        isLeaf: Boolean,
    ) {
        if (isLeaf) countOwn(child)
        if (!index.isAnchorBytes(candidate)) countOwn(candidate)
    }

    /**
     * [candidate]'s nameConstraints checked against every certificate on [path], the leaf first, whose CN-ID counts in
     * a serverAuth request.
     */
    private fun constrains(
        candidate: Cert,
        path: List<Cert>,
    ): NameConstraints.Result {
        val nc = candidate.nameConstraints ?: return NameConstraints.Result.CONFORMS
        for ((i, below) in path.withIndex()) {
            val names =
                if (i == 0 && requiredEku == RequiredEku.SERVER_AUTH) {
                    below.presentedNamesAsServerLeaf
                } else {
                    below.presentedNames
                }
            val r = nc.check(names, budget.comparisons)
            if (r != NameConstraints.Result.CONFORMS) return r
        }
        return NameConstraints.Result.CONFORMS
    }

    /** One charged exploration of [candidate] as the issuer of [path]'s last certificate. */
    private fun explore(
        candidate: Cert,
        path: List<Cert>,
        seen: Set<ByteString>,
        isLeaf: Boolean,
    ): Step {
        val child = path.last()
        countIssuerIndependent(child, candidate, isLeaf)
        val anchor = index.isAnchorBytes(candidate)
        // The issuer rules (#225, #237), checked before the link as pkix checks them: the candidate would sit at path
        // index path.size, with path.size - 1 CAs between it and the leaf.
        if (!anchor && !candidate.issuer.mayIssue(path.size - 1, requiredEku)) return Step.DeadEnd
        // Its nameConstraints, an anchor's included, bind every certificate below it (webpki, pkix); a walk that spends
        // the comparison budget ends as any other exhaustion does.
        when (constrains(candidate, path)) {
            NameConstraints.Result.CONFORMS -> Unit
            NameConstraints.Result.VIOLATION -> return Step.DeadEnd
            NameConstraints.Result.EXHAUSTED -> return Step.Spent
        }
        if (verifyOnce(child, candidate) != VerifyResult.VERIFIED) return Step.DeadEnd
        if (isLeaf) verifiedAtLeaf = true
        // M2 continues from a preload-only candidate here and records its path when none is found through it (§5.1).
        return if (anchor) Step.Path(path + candidate) else walk(path + candidate, seen + candidate.bytesHash)
    }
}
