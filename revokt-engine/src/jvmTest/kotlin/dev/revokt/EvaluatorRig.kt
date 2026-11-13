// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.NOW
import dev.revokt.engine.evaluate.StubEngine
import dev.revokt.engine.evaluate.snapshot
import dev.revokt.engine.update.GenerationSnapshot
import dev.revokt.engine.walker.CandidateIndex
import dev.revokt.engine.walker.DecideContext
import dev.revokt.engine.walker.DecideInputs
import dev.revokt.engine.walker.IndexedSnapshot
import dev.revokt.engine.walker.LruMap
import dev.revokt.engine.walker.PathDecision
import dev.revokt.engine.walker.WalkerFixture
import dev.revokt.engine.walker.WalkerHarness
import dev.revokt.engine.walker.decide
import dev.revokt.testing.SymVerifier

/**
 * A [RevoktEvaluator] over one walker fixture's world, its suppliers faked as `Revokt` (#143) will publish them: the
 * fields are what the next evaluation reads, and each supplier counts its reads. The verifier is the fixture's
 * [SymVerifier], counted in [verifications].
 */
@OptIn(RevoktTestingApi::class)
internal class EvaluatorRig(
    f: WalkerFixture,
    var policy: RevoktPolicy = RevoktPolicy.DEFAULT,
    var generation: GenerationSnapshot = snapshot(),
    engine: RevocationEngine = StubEngine.always(CrliteQueryResult.NOT_REVOKED),
    fallback: PathBuilderFallback? = null,
    clock: () -> Long = { NOW },
    decidePresented: (List<ByteArray>, CandidateIndex, AnchorSnapshot, DecideContext) -> PathDecision = ::decide,
) {
    var lifecycle: RevoktLifecycle = RevoktLifecycle.STARTED
    var indexed: IndexedSnapshot? = indexed(f.snapshot, WalkerHarness.SNAPSHOT_ID, f.customCanonicaliser)
    var lifecycleReads = 0
    var anchorReads = 0
    var generationReads = 0
    var policyReads = 0
    var verifications = 0

    private val sym = SymVerifier(f.ok, f.unsupported)

    private val verifier =
        object : SignatureVerifier {
            override fun verify(
                sigAlg: ByteArray,
                spki: ByteArray,
                message: ByteArray,
                signature: ByteArray,
            ): VerifyResult {
                verifications++
                return sym.verify(sigAlg, spki, message, signature)
            }

            override fun unsupportedOids(): Set<String> = sym.unsupportedOids()
        }

    val evaluator: Evaluator =
        RevoktEvaluator(
            lifecycle = { lifecycle.also { lifecycleReads++ } },
            anchors = { indexed.also { anchorReads++ } },
            generation = { generation.also { generationReads++ } },
            policy = { policy.form.also { policyReads++ } },
            engine = engine,
            walk =
                DecideInputs(
                    verifier,
                    sym.unsupportedOids(),
                    LruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
                    fallback,
                ),
            clock = clock,
            decidePresented = decidePresented,
        )

    fun evaluate(request: EvaluationRequest): Verdict = evaluator.evaluate(request)

    /** [presented] (default: the fixture's chain) as a request for [host]. */
    fun presented(
        presented: List<ByteArray>,
        host: String? = null,
    ): Verdict =
        evaluate(
            EvaluationRequest
                .Builder()
                .presented(presented)
                .host(host)
                .build(),
        )

    companion object {
        /** The snapshot of [anchors] with [id], and its index. */
        fun indexed(
            anchors: List<ByteArray>,
            id: Long,
            customCanonicaliser: Boolean = false,
        ): IndexedSnapshot =
            IndexedSnapshot(
                AnchorSnapshot
                    .Builder()
                    .id(id)
                    .sha256(ByteArray(32))
                    .anchors(anchors)
                    .createdMillis(NOW)
                    .build(),
                CandidateIndex(anchors, customCanonicaliser = customCanonicaliser),
            )
    }
}
