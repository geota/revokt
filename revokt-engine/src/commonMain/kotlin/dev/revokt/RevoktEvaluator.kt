// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.EvaluationInput
import dev.revokt.engine.evaluate.NamedEngine
import dev.revokt.engine.evaluate.evaluate
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.walker.CandidateIndex
import dev.revokt.engine.walker.DecideContext
import dev.revokt.engine.walker.DecideInputs
import dev.revokt.engine.walker.IndexedSnapshot
import dev.revokt.engine.walker.PathDecision
import dev.revokt.engine.walker.PathDetail
import dev.revokt.engine.walker.decide
import dev.revokt.engine.walker.decideVerified
import dev.revokt.engine.walker.verifiedAnchorSnapshotId

/**
 * The single [Evaluator] (spec §4 `revokt.evaluator`, §11's 0.2 row): decision steps 1 to 8 over one candidate index,
 * outside any trust manager, so with no step 1 to fall back to, no step 4 and no `PLATFORM_ONLY` promotion (the
 * walker's reason is reported directly). It shares no path or verdict cache with the trust managers and keeps none of
 * its own, emits no event and counts nothing (§4; caches, events and counters are 0.3).
 *
 * - **Before any boundary** (§4, §5.5): [lifecycle] outside `STARTED`, and [anchors] with no index yet (a start over an
 *   empty or throwing default trust store), throw `IllegalStateException`.
 * - **One read each at entry** (§5.1 decision step 1, flow step 2): [anchors], [generation] and [policy], threaded
 *   through the whole evaluation.
 * - **`presented`** is decided over that index ([decide]: steps 2, 3, 5 and 6 with [walk]'s verifier, probe, shared
 *   cross-call memo and PKIX fallback, null under `pkixFallback(false)`), `anchorSnapshotId` being the snapshot's id.
 * - **`verifiedPath`** is trusted without re-verification ([decideVerified]): no walk, `source = PLATFORM`, and the
 *   path is both the reported path and the exemptions' chain. Only a one-certificate path consults the snapshot (step
 *   2's anchor-by-bytes test), so `anchorSnapshotId` is its id there and 0 for a longer path. When a request carries
 *   both, the verified path wins and the walk is skipped, as on the trust-manager flow where a platform-verified chain
 *   (step 4) makes the walk unnecessary; `EvaluationRequest` has already checked that it starts with the presented
 *   leaf (the maintainer's decision on #195).
 * - **The time** is the request's `nowMillis`, else one read of [clock]; the host is host' (§5.1 flow step 2).
 * - **One `DEBUG` line per evaluation** to [logger]: the path's status and reason, then the decision's [PathDetail]
 *   (the walker's reason and counters, the reported path, `anchorSnapshotId`), or "no decision" with the
 *   `anchorSnapshotId` when the boundary caught a throw before one.
 */
@OptIn(RevoktInternalApi::class)
internal class RevoktEvaluator(
    private val lifecycle: () -> RevoktLifecycle,
    private val anchors: () -> IndexedSnapshot?,
    private val generation: () -> GenerationSnapshot,
    private val policy: () -> PolicyForm,
    engine: RevocationEngine,
    private val walk: DecideInputs,
    private val clock: () -> Long,
    private val logger: RevoktLogger = RevoktLogger { _, _, _ -> },
    private val deciders: Deciders = Deciders(),
) : Evaluator {
    private val engine = NamedEngine(engine)

    override fun evaluate(request: EvaluationRequest): Verdict {
        val state = lifecycle()
        check(state == RevoktLifecycle.STARTED) { "Evaluator.evaluate needs a STARTED Revokt; it is $state" }
        val indexed = checkNotNull(anchors()) { "Evaluator.evaluate has no candidate index: no anchor snapshot exists" }
        val snapshot = generation()
        val form = policy()
        val verified = request.verifiedPath?.map { it.toByteArray() }
        val chain =
            checkNotNull(verified ?: request.presented?.map { it.toByteArray() }) {
                "a request holds a chain or a path (spec §4)"
            }
        val input =
            EvaluationInput(
                chain,
                normalisedHost(request.host),
                snapshot,
                form,
                source = request.chainSource,
            )
        val now = request.nowMillis
        val evaluated =
            evaluate(
                input,
                engine,
                clock = if (now != null) ({ now }) else clock,
                decide = { nowMillis ->
                    if (verified != null) {
                        deciders.verified(chain, indexed.index, indexed.snapshot)
                    } else {
                        deciders.presented(
                            chain,
                            indexed.index,
                            indexed.snapshot,
                            walk.at(nowMillis, platformOnly = false),
                        )
                    }
                },
            )
        val verdict = evaluated.verdict
        val detail =
            evaluated.decision?.detail?.toString()
                ?: "no decision, anchorSnapshotId=${
                    verified?.let { verifiedAnchorSnapshotId(it, indexed.snapshot) } ?: indexed.snapshot.id
                }"
        val reason = verdict.path.reason?.let { "($it)" } ?: ""
        logger.safeLog(LogLevel.DEBUG, "evaluate: ${verdict.path.status}$reason: $detail")
        return verdict
    }
}

/** [RevoktEvaluator]'s two decision routes: [decide] for a presented chain, [decideVerified] for a verified path. */
internal class Deciders(
    val presented: (List<ByteArray>, CandidateIndex, AnchorSnapshot, DecideContext) -> PathDecision = ::decide,
    val verified: (List<ByteArray>, CandidateIndex, AnchorSnapshot) -> PathDecision = ::decideVerified,
)
