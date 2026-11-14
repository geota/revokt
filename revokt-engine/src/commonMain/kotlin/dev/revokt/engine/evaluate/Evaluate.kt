// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.ChainSource
import dev.revokt.CredentialType
import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.EngineErrorProducer
import dev.revokt.ExemptionContext
import dev.revokt.Finding
import dev.revokt.Outcome
import dev.revokt.PathStatus
import dev.revokt.PresentedChain
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktTestingApi
import dev.revokt.Rule
import dev.revokt.Verdict
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.update.GenerationSnapshot
import dev.revokt.engine.walker.PathDecision
import dev.revokt.engine.walker.absorb
import dev.revokt.engine.walker.isFatal
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * A [RevocationEngine] with its [name] read once (spec §3.2: "revokt reads it once per instance"): the `engineName` of
 * every `ENGINE_ERROR` whose producer is the engine, however many queries run.
 */
internal class NamedEngine(
    val engine: RevocationEngine,
) {
    val name: String = engine.name
}

/**
 * One evaluation's inputs besides the engine and the decision (spec §5.1 flow step 2): the [presented] chain, leaf
 * first; [host] as host' (already normalised, so it is never normalised twice); the [snapshot] and [policy] read once
 * for this handshake; the [anchorSnapshotId] decision step 1 consumed and the chain's [source], which a path the
 * evaluation never reached reports.
 */
internal class EvaluationInput(
    val presented: List<ByteArray>,
    val host: String?,
    val snapshot: GenerationSnapshot,
    val policy: PolicyForm,
    val anchorSnapshotId: Long,
    val source: ChainSource = ChainSource.RECONSTRUCTED,
)

/** A verdict and the decision it was computed from; [decision] is null when the boundary caught a throw before it. */
internal class Evaluated(
    val verdict: Verdict,
    val decision: PathDecision?,
)

/**
 * Decision steps 1 to 8 inside spec §5.5's one catch boundary.
 *
 * - **Data rules, before the boundary:** one guarded read of [clock] (a throw is `ENGINE_ERROR(BOUNDARY)`, never an
 *   escape), then [dataStates] from the snapshot, merged into every verdict whatever happens next.
 * - **Steps 1 to 6:** [decide], given the clock read. A throw reports the path `NOT_WALKED`. A decision with no
 *   leaf-issuer key whose status fires no rule of its own (`FOUND`, `NOT_WALKED`) is the boundary's error, so no keys
 *   is never read as a clean answer.
 * - **Step 7:** [queryCrlite], once per distinct leaf-issuer key.
 * - **Step 8:** [fire] over the facts gathered, then the exemptions for fired, exemptable `REJECT` rules, then the
 *   verdict ([verdict]). The exemptions' `PresentedChain` is built by [chainOf] (a test seam), and only once an
 *   exemption is about to run, since it hashes every SPKI and reads every SAN.
 *
 * The boundary catches every throwable but a fatal one ([isFatal]: every `VirtualMachineError` except
 * `StackOverflowError`, rethrown) and adds `ENGINE_ERROR` with a `Finding.EngineError(BOUNDARY)` to the rules fired so
 * far, `REVOKED` included, never replacing them. After a catch no exemption runs: those that completed before it stand,
 * and the rest are not exempt. A throwing exemption is not exempt and adds `ENGINE_ERROR` with a
 * `Finding.EngineError(EXEMPTION)`. A caught `InterruptedException` sets the thread's interrupt flag again ([absorb]).
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
internal fun evaluate(
    input: EvaluationInput,
    engine: NamedEngine,
    clock: () -> Long,
    decide: (nowMillis: Long) -> PathDecision,
    timeSource: TimeSource = TimeSource.Monotonic,
    chainOf: (List<ByteArray>, List<ParsedCertificate?>) -> PresentedChain = PresentedChain::of,
): Evaluated {
    val start = timeSource.markNow()
    val acc = Accumulator(engine.name)
    val now = guarded(acc) { clock() }
    val dataStates = dataStates(input.snapshot, input.policy, now)
    val published = input.snapshot.datasets[Dataset.CRLITE]?.generationId != null
    if (now != null) {
        guarded(acc) {
            val decision = decide(now)
            acc.decision = decision
            val status = decision.path.status
            check(decision.issuerKeys.isNotEmpty() || (status != PathStatus.FOUND && status != PathStatus.NOT_WALKED)) {
                "a $status decision with no leaf-issuer key: no keys is never a clean answer"
            }
            queryCrlite(decision, input.snapshot, published, engine.engine, acc)
        }
    }
    val decision = acc.decision
    val path = decision?.path ?: notWalked(input)
    val pre = fire(acc.facts(path.status, published, dataStates), input.policy)
    if (now != null && decision != null && !acc.boundaryError) {
        guarded(acc) { exempt(pre, input, decision, now, dataStates, acc, chainOf) }
    }
    // An exemption that threw, or a throw the boundary caught while they ran, fires ENGINE_ERROR, which is not
    // exemptable, so one more pass over the table is the whole of it.
    val facts = acc.facts(path.status, published, dataStates)
    return Evaluated(
        verdict(
            Outcomes(fire(facts, input.policy), acc.exempted),
            path,
            facts,
            acc,
            input.snapshot.generationEpoch,
            start,
        ),
        acc.decision,
    )
}

/** Step 8's result: the [fired] rules with their outcomes and the [exempted] ones among them. */
private class Outcomes(
    val fired: List<FiredRule>,
    val exempted: Set<Rule>,
)

/**
 * Decision step 7 (spec §5.1, §4 "Status-to-rule mappings"): one `CrliteQuery(issuerSpkiHash, the leaf's rawSerial,
 * the leaf's SCTs)` per distinct leaf-issuer key, in `issuerSpkiSha256s` order, through the injected engine, and a
 * `Finding.Crlite` per key. With no CRLite generation in the snapshot the engine is never asked: the finding is
 * synthesised as `NO_DATA`, which fires nothing. With no key nothing is queried.
 */
@OptIn(RevoktTestingApi::class)
private fun queryCrlite(
    decision: PathDecision,
    snapshot: GenerationSnapshot,
    published: Boolean,
    engine: RevocationEngine,
    acc: Accumulator,
) {
    if (decision.issuerKeys.isEmpty()) return
    val serial = requireNotNull(decision.serial) { "a decision with leaf-issuer keys carries the leaf's serial" }
    for (key in decision.issuerKeys) {
        val result =
            if (published) {
                engine.query(
                    CrliteQuery
                        .Builder()
                        .issuerSpkiHash(key.toByteArray())
                        .serial(serial)
                        .scts(decision.scts)
                        .build(),
                )
            } else {
                CrliteQueryResult.NO_DATA
            }
        acc.crlite +=
            Finding.Crlite
                .Builder()
                .result(result)
                .issuerSpkiSha256(key.toByteArray())
                .coverageEndMillis(if (published) snapshot.coverageEndMillis else null)
                .build()
    }
}

/**
 * Step 8's exemptions (spec §4 `Exemption`, §8): one call per fired, exemptable `REJECT` rule with an exemption
 * registered, in `Rule.PRECEDENCE` order. The `PresentedChain` is built only once one is about to run, from the
 * decision's own parses so nothing is parsed twice.
 */
@OptIn(RevoktTestingApi::class)
private fun exempt(
    pre: List<FiredRule>,
    input: EvaluationInput,
    decision: PathDecision,
    now: Long,
    dataStates: Map<Dataset, Finding.DataState>,
    acc: Accumulator,
    chainOf: (List<ByteArray>, List<ParsedCertificate?>) -> PresentedChain,
) {
    val running =
        pre
            .filter { it.outcome == Outcome.REJECT && it.rule.exemptable }
            .mapNotNull { fired -> input.policy.exemption(fired.rule)?.let { fired.rule to it } }
    var chain: PresentedChain? = null
    for ((rule, exemption) in running) {
        val presented =
            chain ?: chainOf(input.presented, decision.parses).also { chain = it }
        val context =
            ExemptionContext
                .Builder()
                .rule(rule)
                .chain(presented)
                .credentialType(CredentialType.X509)
                .path(decision.path)
                .primedHost(input.host)
                .nowMillis(now)
                .dataStates(dataStates)
                .build()
        @Suppress("TooGenericExceptionCaught") // §4: a throw of any kind but a fatal one is not exempt
        try {
            if (exemption.isExempt(context)) acc.exempted += rule
        } catch (t: Throwable) {
            absorb(t)
            acc.exemptionErrors += "the exemption for $rule threw ${described(t)}"
        }
    }
}

/**
 * The verdict (spec §4 `Verdict`, §5.1 decision step 8): the fired rules of [outcomes] are its `rules`, exempted ones
 * included; its `rule` is the first fired, non-exempted `REJECT` rule in `Rule.PRECEDENCE` ([verdictRule]), and it is
 * `Rejected` exactly when there is one; `crlite` is the first `REVOKED` finding in `issuerSpkiSha256s` order, else the
 * one for the first key, else null.
 *
 * `findings` lists the path, the decision's findings, the `Crlite` findings in key order, the data states in `Dataset`
 * order, the engine errors (the engine's, the boundary's, the exemptions', each in the order they occurred) and one
 * `Exempted` per exempted rule, in `Rule.PRECEDENCE` order.
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
private fun verdict(
    outcomes: Outcomes,
    path: Finding.Path,
    facts: RuleFacts,
    acc: Accumulator,
    epoch: Long,
    start: TimeMark,
): Verdict {
    val rules = outcomes.fired.mapTo(HashSet()) { it.rule }
    val rule = verdictRule(outcomes.fired, outcomes.exempted)
    val crlite = acc.crlite.firstOrNull { it.result == CrliteQueryResult.REVOKED } ?: acc.crlite.firstOrNull()
    val findings =
        buildList {
            add(path)
            acc.decision?.let { addAll(it.findings) }
            addAll(acc.crlite)
            addAll(facts.dataStates.values)
            addAll(acc.engineErrors(Rule.ENGINE_ERROR in facts.crliteRules, facts.crlitePublished))
            Rule.PRECEDENCE.filter { it in outcomes.exempted }.forEach {
                add(
                    Finding.Exempted
                        .Builder()
                        .rule(it)
                        .build(),
                )
            }
        }
    val elapsedNanos = start.elapsedNow().inWholeNanoseconds
    return if (rule == null) {
        Verdict.Accepted
            .Builder()
            .rules(rules)
            .findings(findings)
            .elapsedNanos(elapsedNanos)
            .path(path)
            .crlite(crlite)
            .dataStates(facts.dataStates)
            .generationEpoch(epoch)
            .build()
    } else {
        Verdict.Rejected
            .Builder()
            .rules(rules)
            .rule(rule)
            .findings(findings)
            .elapsedNanos(elapsedNanos)
            .path(path)
            .crlite(crlite)
            .dataStates(facts.dataStates)
            .generationEpoch(epoch)
            .build()
    }
}

/** The path of an evaluation that never reached the walk (spec §5.5): `NOT_WALKED`, nothing else known. */
@OptIn(RevoktTestingApi::class)
private fun notWalked(input: EvaluationInput): Finding.Path =
    Finding.Path
        .Builder()
        .status(PathStatus.NOT_WALKED)
        .source(input.source)
        .anchorSnapshotId(input.anchorSnapshotId)
        .build()

/**
 * Runs [block] inside the catch boundary (spec §5.5): a fatal throwable is rethrown, any other is recorded on [acc] as
 * the boundary's error and the result is null.
 */
@Suppress("TooGenericExceptionCaught") // §5.5: the boundary catches Throwable
private inline fun <T> guarded(
    acc: Accumulator,
    block: () -> T,
): T? =
    try {
        block()
    } catch (t: Throwable) {
        absorb(t)
        acc.boundaryErrors += "caught ${described(t)}"
        null
    }

/** [t] as a message; a throwable whose own `toString` throws is named by its class. */
@Suppress("TooGenericExceptionCaught") // a consumer throwable's toString is consumer code
private fun described(t: Throwable): String =
    try {
        t.toString()
    } catch (e: Throwable) {
        if (isFatal(e)) throw e
        t::class.simpleName ?: "a throwable"
    }

/**
 * What one evaluation has gathered so far, kept whole when the boundary catches a throw: the decision, the `Crlite`
 * findings of the keys answered, the boundary's error messages, and the rules exempted and the exemptions' errors.
 * [engineName] names the engine's errors.
 */
private class Accumulator(
    private val engineName: String,
) {
    var decision: PathDecision? = null
    val crlite = ArrayList<Finding.Crlite>()
    val boundaryErrors = ArrayList<String>()
    val exempted = HashSet<Rule>()
    val exemptionErrors = ArrayList<String>()

    val boundaryError: Boolean get() = boundaryErrors.isNotEmpty()

    fun facts(
        status: PathStatus,
        published: Boolean,
        dataStates: Map<Dataset, Finding.DataState>,
    ): RuleFacts =
        RuleFacts(
            pathStatus = status,
            crliteResults = crlite.map { it.result },
            crlitePublished = published,
            dataStates = dataStates,
            boundaryError = boundaryError,
            exemptionError = exemptionErrors.isNotEmpty(),
        )

    /**
     * One `EngineError` per producer occurrence (spec §5.5): one per key whose answer is the engine's error, but only
     * when [engineFired] (key aggregation fired the engine's `ENGINE_ERROR`; on `Budget` or beside a `REVOKED` key it
     * is a `Crlite` finding only), then the boundary's, then the exemptions'.
     */
    @OptIn(RevoktTestingApi::class)
    fun engineErrors(
        engineFired: Boolean,
        published: Boolean,
    ): List<Finding.EngineError> =
        buildList {
            if (engineFired) {
                for (c in crlite) {
                    val message =
                        when {
                            c.result == CrliteQueryResult.ENGINE_ERROR -> {
                                "the engine answered ENGINE_ERROR"
                            }

                            c.result == CrliteQueryResult.NO_DATA && published -> {
                                "the engine answered NO_DATA while a generation is published"
                            }

                            else -> {
                                continue
                            }
                        }
                    add(error(message, EngineErrorProducer.ENGINE, engineName))
                }
            }
            boundaryErrors.forEach { add(error(it, EngineErrorProducer.BOUNDARY, null)) }
            exemptionErrors.forEach { add(error(it, EngineErrorProducer.EXEMPTION, null)) }
        }

    @OptIn(RevoktTestingApi::class)
    private fun error(
        message: String,
        producer: EngineErrorProducer,
        engineName: String?,
    ): Finding.EngineError =
        Finding.EngineError
            .Builder()
            .message(message)
            .producer(producer)
            .engineName(engineName)
            .build()
}
