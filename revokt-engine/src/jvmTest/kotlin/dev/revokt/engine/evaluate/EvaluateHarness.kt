// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.ChainSource
import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Finding
import dev.revokt.Freshness
import dev.revokt.GenerationFiles
import dev.revokt.NoIssuerReason
import dev.revokt.ParseReason
import dev.revokt.PathBuilderFallback
import dev.revokt.PathStatus
import dev.revokt.PreparedGeneration
import dev.revokt.PresentedChain
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLimits
import dev.revokt.RevoktPolicy
import dev.revokt.RevoktTestingApi
import dev.revokt.TrustClass
import dev.revokt.Verdict
import dev.revokt.engine.update.DatasetGeneration
import dev.revokt.engine.update.GenerationSnapshot
import dev.revokt.engine.walker.CandidateIndex
import dev.revokt.engine.walker.DecideContext
import dev.revokt.engine.walker.LruMap
import dev.revokt.engine.walker.PathDecision
import dev.revokt.engine.walker.WalkerFixture
import dev.revokt.engine.walker.WalkerHarness
import dev.revokt.engine.walker.decide
import dev.revokt.testing.SymVerifier
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** The evaluation tests' clock: one fixed instant, the walker harness's. */
internal const val NOW: Long = WalkerHarness.NOW

internal const val DAY: Long = 24L * 60 * 60 * 1_000

/**
 * A stub [RevocationEngine] (spec §3.2): [answer] gives each query's result, by issuer key; [queries] records them in
 * order, and [nameReads] counts reads of [name], which is the class's simple name unless [fixedName] is given.
 */
internal open class StubEngine(
    private val fixedName: String? = null,
    private val answer: (ByteString) -> CrliteQueryResult,
) : RevocationEngine {
    val queries = ArrayList<CrliteQuery>()
    var nameReads = 0
        private set

    override val name: String
        get() {
            nameReads++
            return fixedName ?: super.name
        }

    override val formats: Set<FilterFormat> get() = setOf(FilterFormat.V3, FilterFormat.V4)

    override fun prepare(generation: GenerationFiles): PreparedGeneration = error("not in these tests")

    override fun activate(prepared: PreparedGeneration): Unit = error("not in these tests")

    override fun query(q: CrliteQuery): CrliteQueryResult {
        queries += q
        return answer(q.issuerSpkiHash.toByteString())
    }

    override val coverageEndMillis: Long? get() = COVERAGE_END

    override fun close(): Unit = Unit

    companion object {
        const val COVERAGE_END: Long = NOW + DAY

        /** Answers [result] for every key. */
        fun always(result: CrliteQueryResult): StubEngine = StubEngine { result }
    }
}

/**
 * A published CRLite generation [ageMillis] old of [trustClass]; [fromSeed] with the seed gate [gateOpen]. `pending`
 * and `clockBehind` are false unless given.
 */
internal fun generation(
    ageMillis: Long = 0,
    trustClass: TrustClass = TrustClass.SIGNED,
    fromSeed: Boolean = false,
    gateOpen: Boolean = true,
    clockBehind: Boolean = false,
): DatasetGeneration =
    DatasetGeneration(
        generationId = if (fromSeed) "seed-1" else "1700000000000/rec-1",
        trustClass = trustClass,
        freshness = if (fromSeed) Freshness.SEED_SIGNED_TIME else Freshness.RECORD_LAST_MODIFIED,
        fromSeed = fromSeed,
        sourceTimestampMillis = NOW - ageMillis,
        seedFormat = if (fromSeed) 1 else null,
        pending = false,
        staleGateOpen = gateOpen,
        clockBehind = clockBehind,
    )

/** The dataset with no generation: the start task found nothing ([pending] false), or has not finished. */
internal fun noGeneration(pending: Boolean = false): DatasetGeneration =
    DatasetGeneration(
        generationId = null,
        trustClass = null,
        freshness = null,
        fromSeed = false,
        sourceTimestampMillis = null,
        seedFormat = null,
        pending = pending,
        staleGateOpen = false,
        clockBehind = false,
    )

internal const val EPOCH: Long = 7

/** A snapshot holding [crlite] for `CRLITE`, or nothing for it when null. */
internal fun snapshot(crlite: DatasetGeneration? = generation()): GenerationSnapshot =
    GenerationSnapshot(
        EPOCH,
        listOfNotNull(crlite?.let { Dataset.CRLITE to it }).toMap(),
        if (crlite?.generationId != null) StubEngine.COVERAGE_END else null,
    )

/** One evaluation of a walker fixture or a hand-made decision, with the stub engine and the fixed clock by default. */
@OptIn(RevoktTestingApi::class)
internal class Run(
    val presented: List<ByteArray>,
    val policy: RevoktPolicy = RevoktPolicy.DEFAULT,
    val snapshot: GenerationSnapshot = snapshot(),
    val engine: RevocationEngine = StubEngine.always(CrliteQueryResult.NOT_REVOKED),
    val host: String? = null,
    val clock: () -> Long = { NOW },
    val decide: (Long) -> PathDecision,
) {
    var chainsBuilt = 0
        private set

    fun evaluate(named: NamedEngine = NamedEngine(engine)): Evaluated =
        evaluate(
            EvaluationInput(presented, host, snapshot, policy.form, WalkerHarness.SNAPSHOT_ID),
            named,
            clock,
            decide,
            chainOf = { ders, parses ->
                chainsBuilt++
                PresentedChain.of(ders, parses)
            },
        )

    companion object {
        /** [f] decided as on every trust-manager path (step 3's `MAX_PRESENTED` cut applies), fallback [fallback]. */
        fun of(
            f: WalkerFixture,
            policy: RevoktPolicy = RevoktPolicy.DEFAULT,
            snapshot: GenerationSnapshot = snapshot(),
            engine: RevocationEngine = StubEngine.always(CrliteQueryResult.NOT_REVOKED),
            host: String? = null,
            fallback: PathBuilderFallback? = null,
        ): Run = Run(f.presented, policy, snapshot, engine, host) { now -> decideFixture(f, fallback, now) }

        fun decideFixture(
            f: WalkerFixture,
            fallback: PathBuilderFallback?,
            now: Long,
        ): PathDecision {
            val index = CandidateIndex(f.snapshot, customCanonicaliser = f.customCanonicaliser)
            val sym = SymVerifier(f.ok, f.unsupported)
            val context =
                DecideContext(
                    sym,
                    sym.unsupportedOids(),
                    LruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
                    fallback,
                    now,
                    platformOnly = false,
                )
            return decide(f.presented, index, WalkerHarness.snapshot(f.snapshot), context)
        }
    }
}

/** A hand-made decision: [status] with leaf-issuer [keys] and the leaf's serial, as decide would hand it on. */
@OptIn(RevoktTestingApi::class)
internal fun decision(
    status: PathStatus,
    vararg keys: ByteString,
    presented: Int = 1,
): PathDecision {
    val path =
        Finding.Path
            .Builder()
            .status(status)
            .source(ChainSource.RECONSTRUCTED)
            .anchorSnapshotId(WalkerHarness.SNAPSHOT_ID)
            .apply {
                if (status == PathStatus.PARSE_FAILED) parseReason(ParseReason.STRUCTURE)
                if (status == PathStatus.NO_ISSUER) noIssuerReason(NoIssuerReason.NO_CANDIDATE)
            }.issuerSpkiSha256s(keys.map { it.toByteArray() })
            .build()
    return PathDecision(
        path = path,
        issuerKeys = keys.toList(),
        serial = if (status == PathStatus.PARSE_FAILED) null else byteArrayOf(1),
        scts = emptyList(),
        findings = emptyList(),
        buildThrew = false,
        parses = List(presented) { null },
    )
}

/** A distinct 32-byte issuer key, numbered [n]. */
internal fun key(n: Int): ByteString = ByteArray(32) { n.toByte() }.toByteString()

/** The `Finding.EngineError`s of [verdict]'s findings. */
internal fun engineErrors(verdict: Verdict): List<Finding.EngineError> =
    verdict.findings.filterIsInstance<Finding.EngineError>()
