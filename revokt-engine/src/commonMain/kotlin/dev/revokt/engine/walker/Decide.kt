// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.AnchorSnapshot
import dev.revokt.ChainSource
import dev.revokt.CrliteSct
import dev.revokt.FallbackReason
import dev.revokt.Finding
import dev.revokt.KeyabilityClause
import dev.revokt.Layer
import dev.revokt.NoIssuerReason
import dev.revokt.ParseReason
import dev.revokt.PathBuilderFallback
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import dev.revokt.SignatureVerifier
import dev.revokt.TerminalKind
import dev.revokt.VerifyResult
import dev.revokt.WalkEnd
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * What decision steps 1 to 6 hand to `evaluate`, steps 7 and 8 (spec §5.1 decision list): [path] is the
 * `Finding.Path`; [issuerKeys] are its `issuerSpkiSha256s`, the distinct leaf-issuer keys step 7 queries (walker keys
 * in candidate order, then the fallback key if new); [serial] and [scts] are the leaf's, null and empty when the leaf
 * is `PARSE_FAILED`, which is never queried; [findings] are the parse, walk and step-6 findings. [parses] holds the
 * parse of each presented certificate, in presented order, null where the parser rejected it or decide never read it,
 * so an exemption's `PresentedChain` (#133) parses nothing twice.
 *
 * [buildThrew] is true when step 6's `PathBuilderFallback.build` threw: the result is then cached nowhere, neither in
 * the path cache nor, through its verdict, in the verdict cache (§5.1 flow steps 2 and 3a, revision 50).
 */
internal class PathDecision(
    val path: Finding.Path,
    val issuerKeys: List<ByteString>,
    val serial: ByteArray?,
    val scts: List<CrliteSct>,
    val findings: List<Finding>,
    val buildThrew: Boolean,
    val parses: List<ParsedCertificate?>,
)

/**
 * The inputs of [decide] besides the chain and the anchor snapshot.
 *
 * - [verifier], [probe] and [crossCallMemo] are [reconstruct]'s (decision step 5); [probe] is the verifier's startup
 *   `unsupportedOids()`.
 * - [fallback] is step 6's PKIX builder, called at [nowMillis]; null when the fallback is disabled
 *   (`pkixFallback(false)`, and the walker-only harness's disabled path).
 * - [platformOnly] is step 6's `PLATFORM_ONLY` promotion of a `NO_ISSUER`: on for the trust-manager bindings and
 *   `Revokt.evaluate`, which run step 1; off for the walker-only harness and `Evaluator.evaluate`, where the walker's
 *   reason is reported directly.
 */
internal class DecideContext(
    val verifier: SignatureVerifier,
    val probe: Set<String>,
    val crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult>,
    val fallback: PathBuilderFallback?,
    val nowMillis: Long,
    val platformOnly: Boolean,
)

/**
 * Spec §5.1 `decide`: decision steps 1 to 6 over the presented [chain] (leaf first), for step 4 only on Android (0.3).
 * Step 1 is the caller's: [index] is the `CandidateIndex` it read once, and [snapshot] the `AnchorSnapshot` that index
 * was built from, whose id is `anchorSnapshotId` and which step 6's fallback is given.
 *
 * - **Step 2:** a leaf equal by bytes to a parsed anchor is `FOUND` with the path `[leaf]`, keyed by its own SPKI.
 * - **Step 3:** the leaf is parsed once (§5.5): over `MAX_CERT_BYTES` is `PARSE_FAILED(OVERSIZE)` (checked before the
 *   parse), unparseable `PARSE_FAILED(STRUCTURE)`, outside the §9.2 keyability profile
 *   `PARSE_FAILED(PRODUCER_UNKEYABLE)` with its clause (D8). Then more than `MAX_PRESENTED` certificates or more than
 *   `MAX_PRESENTED_BYTES` of DER, over the raw chain, is `PATH_BUDGET_EXCEEDED` with `EXPLORATION_BUDGET` at
 *   `endDepth = 0` and no walk. Only then are the other certificates parsed; one the parser rejects is dropped and
 *   counted in `candidatesDropped`. `producerKeyable` gates the leaf only.
 * - **Step 5:** [reconstruct]; a `Found` is final.
 * - **Step 6:** on a walk `NotFound` or `Budget`, the PKIX fallback runs when it is enabled and the chain has at most
 *   `FALLBACK_MAX_PRESENTED` certificates. A `build` that returns null or throws is a failed fallback; a throw is
 *   caught, except a fatal error ([isFatal], §5.5), keeps an interrupt ([absorb]) and sets [PathDecision.buildThrew].
 *   Exactly one `FallbackNotUsed` is reported when no fallback path was evaluated.
 *
 * Every exit carries `AlgorithmIdMismatch` once per certificate parsed here whose outer and TBS signature algorithms
 * differ, and every walk `UnsupportedAlgorithm(oid, PATH, outcomeDepended = status == ISSUER_UNVERIFIED)` once per
 * OID in `Walk.unsupportedOids`. Nothing here throws except a fatal error and an empty [chain].
 */
internal fun decide(
    chain: List<ByteArray>,
    index: CandidateIndex,
    snapshot: AnchorSnapshot,
    context: DecideContext,
): PathDecision = Decider(chain, index, snapshot, context).run(presentedCut = true)

/**
 * [decide] for the walker-only harness (spec §9): step 3's leaf checks without its `MAX_PRESENTED` and
 * `MAX_PRESENTED_BYTES` cut, so fixtures (i), (s2), (t) and (y), which present more than `MAX_PRESENTED`
 * certificates, reach the walk. Test-visible only: no trust-manager path and no `Evaluator.evaluate` calls it, since on
 * every one of them those rows are cut at step 3. `@RevoktTestingApi`, so skipping the cut is an explicit opt-in.
 */
@RevoktTestingApi
internal fun decideWalkerHarness(
    chain: List<ByteArray>,
    index: CandidateIndex,
    snapshot: AnchorSnapshot,
    context: DecideContext,
): PathDecision = Decider(chain, index, snapshot, context).run(presentedCut = false)

/** Step 6's PKIX fallback, as decide uses it. */
private sealed interface Fallback {
    /** A fallback path: its DER hashes, leaf → anchor, and its leaf-issuer key. */
    class Path(
        val hashes: List<ByteString>,
        val key: ByteString,
    ) : Fallback

    /** No fallback path was evaluated, for [reason]. */
    class NotUsed(
        val reason: FallbackReason,
    ) : Fallback
}

/** One decision's state: the findings so far, the dropped count and whether `build` threw. */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
private class Decider(
    private val chain: List<ByteArray>,
    private val index: CandidateIndex,
    private val snapshot: AnchorSnapshot,
    private val context: DecideContext,
) {
    private val findings = ArrayList<Finding>()
    private var dropped = 0
    private var buildThrew = false
    private val parses = arrayOfNulls<ParsedCertificate>(chain.size)

    fun run(presentedCut: Boolean): PathDecision {
        require(chain.isNotEmpty()) { "decide needs the leaf: the presented chain is empty" }
        // Step 3's leaf parse runs first because step 2 compares the parsed leaf. A leaf the parser rejects is never
        // an anchor by bytes, since the index holds parsed anchors only, so step 2 still decides before step 3. The
        // parser checks MAX_CERT_BYTES before it parses.
        val leaf =
            when (val r = CertificateParser.parse(chain[0])) {
                is CertificateParse.Failed -> return parseFailed(r.reason, clause = null)
                is CertificateParse.Parsed -> index.cert(r.certificate).also { parses[0] = r.certificate }
            }
        mismatch(leaf, 0)
        if (index.isAnchorBytes(leaf)) return anchorLeaf(leaf)
        leaf.keyabilityClause?.let { return parseFailed(ParseReason.PRODUCER_UNKEYABLE, it) }
        if (presentedCut && overPresented()) return presentedCut(leaf)
        val walk = reconstruct(presented(leaf), index, context.verifier, context.probe, context.crossCallMemo)
        findings += walk.findings
        return when (walk) {
            is Walk.Found -> found(walk, leaf)
            is Walk.NotFound -> notFound(walk, leaf)
            is Walk.Budget -> budget(walk, leaf)
        }
    }

    /** Step 3's cut, over the raw presented chain before any candidate is dropped (`MAX_PRESENTED` bounds parsing). */
    private fun overPresented(): Boolean =
        chain.size > RevoktLimits.MAX_PRESENTED ||
            chain.sumOf { it.size.toLong() } > RevoktLimits.MAX_PRESENTED_BYTES

    /** [leaf], then every other presented certificate the parser reads, in order; the rest are dropped. */
    private fun presented(leaf: Cert): List<Cert> {
        val certs = ArrayList<Cert>(chain.size)
        certs += leaf
        for (i in 1 until chain.size) {
            when (val r = CertificateParser.parse(chain[i])) {
                is CertificateParse.Failed -> {
                    dropped++
                }

                is CertificateParse.Parsed -> {
                    parses[i] = r.certificate
                    certs += index.cert(r.certificate).also { mismatch(it, i) }
                }
            }
        }
        return certs
    }

    private fun mismatch(
        c: Cert,
        certIndex: Int,
    ) {
        if (c.algorithmIdMismatch) {
            findings +=
                Finding.AlgorithmIdMismatch
                    .Builder()
                    .certIndex(certIndex)
                    .build()
        }
    }

    private fun base(status: PathStatus): Finding.Path.Builder =
        Finding.Path
            .Builder()
            .status(status)
            .source(ChainSource.RECONSTRUCTED)
            .anchorSnapshotId(snapshot.id)

    private fun parseFailed(
        reason: ParseReason,
        clause: KeyabilityClause?,
    ): PathDecision =
        result(
            base(PathStatus.PARSE_FAILED).parseReason(reason).keyabilityClause(clause),
            keys = emptyList(),
            reported = emptyList(),
            leaf = null,
        )

    /** Step 2: `Found([WalkPath([leaf], terminal = ANCHOR)])`; no walk ran. */
    private fun anchorLeaf(leaf: Cert): PathDecision =
        result(
            base(PathStatus.FOUND).pathsFound(1),
            keys = listOf(leaf.spkiHash),
            reported = listOf(leaf.bytesHash),
            leaf = leaf,
        )

    /** Step 3's `Budget(EXPLORATION_BUDGET)` without a walk: no CRLite query and no `FallbackNotUsed`. */
    private fun presentedCut(leaf: Cert): PathDecision =
        result(
            base(PathStatus.PATH_BUDGET_EXCEEDED).endReason(WalkEnd.EXPLORATION_BUDGET).endDepth(0),
            keys = emptyList(),
            reported = emptyList(),
            leaf = leaf,
        )

    private fun found(
        walk: Walk.Found,
        leaf: Cert,
    ): PathDecision =
        walked(
            walk,
            base(PathStatus.FOUND).endReason(WalkEnd.COMPLETE).pathsFound(walk.paths.size),
            keys = walk.leafKeys.toList(),
            reported = walk.paths.first().hashes(),
            leaf = leaf,
            notUsed = null,
        )

    /**
     * Step 6 on a walk `NotFound`: a fallback path is `FOUND`; otherwise a chain over `FALLBACK_MAX_PRESENTED` is
     * `PATH_BUDGET_EXCEEDED` (the fallback skipped or disabled, whether or not step 1 ran), and any other is
     * `ISSUER_UNVERIFIED` when a certificate the walk visited has an unsupported own signature OID, else
     * `NO_ISSUER`, promoted to `PLATFORM_ONLY` under [DecideContext.platformOnly].
     */
    private fun notFound(
        walk: Walk.NotFound,
        leaf: Cert,
    ): PathDecision {
        val builder = base(PathStatus.FOUND).endReason(WalkEnd.COMPLETE).walkerReason(walk.reason)
        val fallback = fallback(leaf)
        if (fallback is Fallback.Path) {
            return walked(
                walk,
                builder.usedFallback(true).pathsFound(1),
                keys = listOf(fallback.key),
                reported = fallback.hashes,
                leaf = leaf,
                notUsed = null,
            )
        }
        when {
            chain.size > RevoktLimits.FALLBACK_MAX_PRESENTED -> {
                builder.status(PathStatus.PATH_BUDGET_EXCEEDED)
            }

            walk.unsupportedOids.isNotEmpty() -> {
                builder.status(PathStatus.ISSUER_UNVERIFIED)
            }

            else -> {
                val reason = if (context.platformOnly) NoIssuerReason.PLATFORM_ONLY else walk.reason
                builder.status(PathStatus.NO_ISSUER).noIssuerReason(reason)
            }
        }
        return walked(walk, builder, emptyList(), emptyList(), leaf, (fallback as Fallback.NotUsed).reason)
    }

    /**
     * Step 6 on a walk `Budget`: `PATH_BUDGET_EXCEEDED` whatever the fallback does. A fallback path's key is appended
     * to the partial leaf keys, only so that step 7 reports `REVOKED` when it is reachable; the reported path is the
     * first partial path, else the fallback path.
     */
    private fun budget(
        walk: Walk.Budget,
        leaf: Cert,
    ): PathDecision {
        val keys = LinkedHashSet(walk.partialLeafKeys)
        var reported = walk.partialPaths.firstOrNull()?.hashes()
        val fallback = fallback(leaf)
        if (fallback is Fallback.Path) {
            keys += fallback.key
            reported = reported ?: fallback.hashes
        }
        return walked(
            walk,
            base(PathStatus.PATH_BUDGET_EXCEEDED)
                .endReason(walk.end)
                .endDepth(walk.endDepth)
                .pathsFound(walk.partialPaths.size)
                .usedFallback(fallback is Fallback.Path),
            keys = keys.toList(),
            reported = reported.orEmpty(),
            leaf = leaf,
            notUsed = (fallback as? Fallback.NotUsed)?.reason,
        )
    }

    /**
     * Step 6's PKIX fallback: `DISABLED` with none configured, `SKIPPED` over `FALLBACK_MAX_PRESENTED`, else one
     * `build` over the raw presented chain (copies, so the builder cannot change the caller's arrays). `FAILED` is a
     * null, a throw, or a path decide cannot use: empty, holding a null element (a Java builder), not starting with the
     * presented leaf's bytes (a consumer builder's path could otherwise be keyed by an unrelated issuer), or with a
     * leaf-issuer key that cannot be read. Reading the result runs inside the catch, so nothing it does escapes as an
     * engine error.
     */
    @Suppress("TooGenericExceptionCaught") // §5.5's rule: every throwable but a fatal error is caught
    private fun fallback(leaf: Cert): Fallback {
        val builder = context.fallback ?: return Fallback.NotUsed(FallbackReason.DISABLED)
        if (chain.size > RevoktLimits.FALLBACK_MAX_PRESENTED) return Fallback.NotUsed(FallbackReason.SKIPPED)
        return try {
            builder.build(chain.map { it.copyOf() }, snapshot, context.nowMillis)?.let { path(it, leaf) }
        } catch (t: Throwable) {
            absorb(t)
            buildThrew = true
            null
        } ?: Fallback.NotUsed(FallbackReason.FAILED)
    }

    /** A usable fallback [result], or null; [result] is typed as a Java builder may fill it. */
    private fun path(
        result: List<ByteArray?>,
        leaf: Cert,
    ): Fallback.Path? {
        val ders = result.map { it ?: return null }
        if (ders.isEmpty() || !ders[0].contentEquals(chain[0])) return null
        val key = issuerKey(ders, leaf) ?: return null
        return Fallback.Path(ders.map { it.toByteString().sha256() }, key)
    }

    /**
     * The leaf-issuer key of a fallback path, the SPKI hash of its second certificate, or of the leaf when the path
     * is the leaf alone (an anchor, as at step 2); null when that certificate does not parse, since step 7 could not
     * query under it.
     */
    private fun issuerKey(
        ders: List<ByteArray>,
        leaf: Cert,
    ): ByteString? {
        if (ders.size == 1) return leaf.spkiHash
        val issuer = CertificateParser.parse(ders[1]) as? CertificateParse.Parsed ?: return null
        return issuer.certificate
            .rawSpki()
            .toByteString()
            .sha256()
    }

    /** An exit after the walk: the walk's stats and `UnsupportedAlgorithm` findings, then any `FallbackNotUsed`. */
    private fun walked(
        walk: Walk,
        builder: Finding.Path.Builder,
        keys: List<ByteString>,
        reported: List<ByteString>,
        leaf: Cert,
        notUsed: FallbackReason?,
    ): PathDecision {
        builder.walkStats(walk.stats)
        val status = builder.status
        for (oid in walk.unsupportedOids) {
            findings +=
                Finding.UnsupportedAlgorithm
                    .Builder()
                    .oid(oid)
                    .where(Layer.PATH)
                    .outcomeDepended(status == PathStatus.ISSUER_UNVERIFIED)
                    .build()
        }
        notUsed?.let {
            findings +=
                Finding.FallbackNotUsed
                    .Builder()
                    .reason(it)
                    .build()
        }
        return result(builder, keys, reported, leaf)
    }

    /** The decision: [reported] is the reported path's DER hashes, leaf → anchor, empty when there is none. */
    private fun result(
        builder: Finding.Path.Builder,
        keys: List<ByteString>,
        reported: List<ByteString>,
        leaf: Cert?,
    ): PathDecision {
        val path =
            builder
                .candidatesDropped(dropped)
                .issuerSpkiSha256s(keys.map { it.toByteArray() })
                .reportedPathSha256s(reported.map { it.toByteArray() })
                // Every M1 terminal is an anchor; M2's preload-only terminal will need the WalkPath's.
                .terminalKind(if (reported.isEmpty()) null else TerminalKind.ANCHOR)
                .anchorSha256(reported.lastOrNull()?.toByteArray())
                .build()
        return PathDecision(
            path,
            keys,
            leaf?.serial,
            leaf?.scts.orEmpty(),
            findings.toList(),
            buildThrew,
            parses.toList(),
        )
    }

    private fun WalkPath.hashes(): List<ByteString> = certs.map { it.bytesHash }
}
