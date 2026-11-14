// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.EvaluationInput
import dev.revokt.engine.evaluate.NamedEngine
import dev.revokt.engine.evaluate.evaluate
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.update.GenerationSnapshot
import dev.revokt.engine.walker.CandidateIndex
import dev.revokt.engine.walker.DecideContext
import dev.revokt.engine.walker.DecideInputs
import dev.revokt.engine.walker.IndexedSnapshot
import dev.revokt.engine.walker.PathDecision
import dev.revokt.engine.walker.decide
import dev.revokt.engine.walker.decideVerified

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
 * - **`verifiedPath`** is trusted without re-verification ([decideVerified]): no walk, `source = PLATFORM`,
 *   `anchorSnapshotId = 0`, and the path is both the reported path and the exemptions' chain. When a request carries
 *   both, the verified path wins and the walk is skipped, as on the trust-manager flow where a platform-verified chain
 *   (step 4) makes the walk unnecessary; `EvaluationRequest` has already checked that it starts with the presented
 *   leaf (the maintainer's decision on #195).
 * - **The time** is the request's `nowMillis`, else one read of [clock]; the host is host' (§5.1 flow step 2).
 */
internal class RevoktEvaluator(
    private val lifecycle: () -> RevoktLifecycle,
    private val anchors: () -> IndexedSnapshot?,
    private val generation: () -> GenerationSnapshot,
    private val policy: () -> PolicyForm,
    engine: RevocationEngine,
    private val walk: DecideInputs,
    private val clock: () -> Long,
    private val decidePresented: (List<ByteArray>, CandidateIndex, AnchorSnapshot, DecideContext) -> PathDecision =
        ::decide,
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
                anchorSnapshotId = if (verified != null) 0 else indexed.snapshot.id,
                source = request.chainSource,
            )
        val now = request.nowMillis
        return evaluate(
            input,
            engine,
            clock = if (now != null) ({ now }) else clock,
            decide = { nowMillis ->
                if (verified != null) {
                    decideVerified(chain)
                } else {
                    decidePresented(chain, indexed.index, indexed.snapshot, walk.at(nowMillis, platformOnly = false))
                }
            },
        ).verdict
    }
}
