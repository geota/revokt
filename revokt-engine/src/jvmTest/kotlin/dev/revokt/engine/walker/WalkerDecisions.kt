// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.walker

import dev.revokt.CrliteQueryResult
import dev.revokt.FallbackReason
import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.PathBuilderFallback
import dev.revokt.PathReason
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.Rule
import dev.revokt.TerminalKind
import dev.revokt.Verdict
import dev.revokt.WalkStats
import dev.revokt.engine.evaluate.Run
import dev.revokt.engine.evaluate.StubEngine
import dev.revokt.engine.evaluate.generation
import dev.revokt.engine.evaluate.snapshot
import dev.revokt.engine.generation.DatasetGeneration
import okio.ByteString
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/*
 * The §9 walker fixtures' decision columns (spec §9 "Walker fixtures" schema: expected PathStatus / PathReason,
 * expected Path fields, verdict relation to the honest chain) on the two 0.2 platform paths of the walker-only harness,
 * the JVM walker and the JVM walker with the fallback disabled (#136, #140). The Walk column is [WalkerFixtureTest]'s.
 */

/** A verdict under `DEFAULT`: the [rules] fired and [rule], null for `Accepted`. */
internal data class VerdictWant(
    val rules: Set<Rule>,
    val rule: Rule?,
)

/**
 * The verdict column, run twice with §9.1's CRLite stub: [revoked] with the honest leaf-issuer key `REVOKED`, [clean]
 * with it `NOT_REVOKED`, every other key `NOT_ENROLLED` in both.
 */
internal enum class Verdicts(
    val revoked: VerdictWant,
    val clean: VerdictWant,
) {
    /** The honest key alone is evaluated: the verdict equals the honest chain's. */
    HONEST(VerdictWant(setOf(Rule.REVOKED), Rule.REVOKED), VerdictWant(emptySet(), null)),

    /** Another key alone is evaluated, so the honest key's revocation is not seen (§10 residual 15). */
    OTHER_KEY(VerdictWant(setOf(Rule.NOT_ENROLLED), null), VerdictWant(setOf(Rule.NOT_ENROLLED), null)),

    /** `NO_ISSUER`, no key evaluated; `DEFAULT` allows it. */
    NO_ISSUER(VerdictWant(setOf(Rule.NO_ISSUER), null), VerdictWant(setOf(Rule.NO_ISSUER), null)),

    /** `PATH_BUDGET_EXCEEDED`, no key evaluated: rejected whatever the honest key's state. */
    BUDGET(
        VerdictWant(setOf(Rule.PATH_BUDGET_EXCEEDED), Rule.PATH_BUDGET_EXCEEDED),
        VerdictWant(setOf(Rule.PATH_BUDGET_EXCEEDED), Rule.PATH_BUDGET_EXCEEDED),
    ),

    /** `PATH_BUDGET_EXCEEDED` with the fallback's honest key evaluated: on `Budget` only `REVOKED` fires from CRLite. */
    BUDGET_HONEST(
        VerdictWant(setOf(Rule.REVOKED, Rule.PATH_BUDGET_EXCEEDED), Rule.REVOKED),
        VerdictWant(setOf(Rule.PATH_BUDGET_EXCEEDED), Rule.PATH_BUDGET_EXCEEDED),
    ),

    /** A `PARSE_FAILED` leaf with no CRLite generation, row (ab). */
    PARSE_FAILED_NO_DATA(
        VerdictWant(setOf(Rule.PARSE_FAILED, Rule.NO_DATA), Rule.NO_DATA),
        VerdictWant(setOf(Rule.PARSE_FAILED, Rule.NO_DATA), Rule.NO_DATA),
    ),
}

/**
 * One platform path's expected decision: the `Finding.Path` [status] and [reason], the detail's [walkerReason] and
 * [usedFallback], the reported [path] as fixture labels, leaf → anchor (null: the walk's own path, for the generated
 * rows), whose second certificate's key is the one leaf-issuer key (a one-certificate path: its own), the decision's
 * [findings] before step 6's, then exactly one `FallbackNotUsed` with [notUsed] when it is set, and the [verdict].
 * `pathsFound` is 1 on `FOUND` and 0 otherwise.
 */
internal data class Want(
    val status: PathStatus,
    val verdict: Verdicts,
    val reason: PathReason? = null,
    val walkerReason: NoIssuerReason? = null,
    val usedFallback: Boolean = false,
    val path: List<String>? = emptyList(),
    val notUsed: FallbackReason? = null,
    val findings: List<Finding> = emptyList(),
) {
    /**
     * The same row on the disabled path, where the fallback never runs: a walk that is final ([usedFallback] false)
     * gives the same decision, and a `FallbackNotUsed` becomes `DISABLED` (revision 50). A row whose enabled path used
     * the fallback states its disabled expectation.
     */
    fun onDisabledPath(): Want {
        check(!usedFallback) { "a row whose fallback found a path states its disabled expectation" }
        return copy(notUsed = notUsed?.let { FallbackReason.DISABLED })
    }

    companion object {
        fun found(
            vararg path: String,
            verdict: Verdicts = Verdicts.HONEST,
            findings: List<Finding> = emptyList(),
        ): Want = Want(PathStatus.FOUND, verdict, path = path.toList(), findings = findings)

        /** A walk `NotFound` the fallback does not answer, within `FALLBACK_MAX_PRESENTED`: the walker's reason. */
        fun noIssuer(
            reason: NoIssuerReason,
            notUsed: FallbackReason = FallbackReason.FAILED,
        ): Want = Want(PathStatus.NO_ISSUER, Verdicts.NO_ISSUER, noIssuerReason(reason), reason, notUsed = notUsed)

        /** A walk `Budget` with no fallback path: no key, no reported path. */
        fun budget(notUsed: FallbackReason?): Want =
            Want(PathStatus.PATH_BUDGET_EXCEEDED, Verdicts.BUDGET, PathReason.EXPLORATION_BUDGET, notUsed = notUsed)

        /** A walk `NotFound` over `FALLBACK_MAX_PRESENTED` presented: the fallback skipped. */
        fun fallbackLimit(walkerReason: NoIssuerReason): Want =
            Want(
                PathStatus.PATH_BUDGET_EXCEEDED,
                Verdicts.BUDGET,
                PathReason.FALLBACK_LIMIT,
                walkerReason,
                notUsed = FallbackReason.SKIPPED,
            )
    }
}

/**
 * One fixture row (or one of its cases) with its decision columns: [enabled] on the JVM walker, whose fallback is
 * [fallback] (the harness's [SymPathBuilder] unless the row runs a real one), and [disabled] with no fallback. [honest]
 * labels the honest leaf issuer, whose key the CRLite stub answers for (a generated row's is its Walk column's leaf
 * key, and a row without that certificate has none). [crlite] is the snapshot's CRLite generation. [decide] is decision steps 1 to 6: the harness entry, without step
 * 3's `MAX_PRESENTED` cut, unless [harness] is false. [noWalk] marks a row decided before step 5.
 */
internal class DecisionRow(
    val fixture: WalkerFixture,
    val enabled: Want,
    val disabled: Want = enabled.onDisabledPath(),
    honest: String = "I",
    val crlite: DatasetGeneration? = generation(),
    val harness: Boolean = true,
    val noWalk: Boolean = false,
    val fallback: () -> PathBuilderFallback = { SymPathBuilder(fixture.ok, fixture.unsupported) },
    val decide: (PathBuilderFallback?) -> PathDecision = { WalkerHarness.decide(fixture, it, harness = harness) },
) {
    /** Null when the row holds no honest issuer certificate ((g), (z), (ae)): no key the stub answers is honest. */
    val honestKey: ByteString? = fixture.walk.leafKey ?: find(honest)?.let { WalkerCerts.cert(it).spkiHash }

    /** The certificate labelled [label] among the row's presented and snapshot certificates. */
    fun der(label: String): ByteArray = find(label) ?: error("$fixture: no certificate labelled $label")

    private fun find(label: String): ByteArray? =
        (fixture.presented + fixture.snapshot).firstOrNull { fixture.label(WalkerHarness.hash(it)) == label }

    override fun toString(): String = fixture.toString()
}

/** Runs [DecisionRow]s on both platform paths and asserts every decision column. */
internal object WalkerDecisionRunner {
    fun check(rows: List<DecisionRow>): List<DecisionRow> {
        assertTrue(rows.isNotEmpty())
        rows.forEach(::check)
        return rows
    }

    fun check(row: DecisionRow) {
        for (enabled in listOf(true, false)) {
            val at = "$row, fallback ${if (enabled) "enabled" else "disabled"}"
            val want = if (enabled) row.enabled else row.disabled
            val fallback = if (enabled) row.fallback() else null
            val d = row.decide(fallback)
            decision(row, want, d, at)
            if (fallback is SymPathBuilder) {
                assertTrue(fallback.agreed, "$at: the harness fallback agrees with the reference walker")
            }
            assertFalse(d.buildThrew, "$at: build threw")
            verdicts(row, want, enabled, d, at)
        }
        if (row.harness && row.fixture.presented.size > RevoktLimits.MAX_PRESENTED) cut(row)
    }

    private fun decision(
        row: DecisionRow,
        want: Want,
        d: PathDecision,
        at: String,
    ) {
        val path = want.path?.map(row::der) ?: walkedPath(row)
        val key = path.getOrNull(1) ?: path.firstOrNull()
        assertPath(d, at) {
            status(want.status)
                .reason(want.reason)
                .walkerReason(want.walkerReason)
                .usedFallback(want.usedFallback)
                .pathsFound(if (want.status == PathStatus.FOUND) 1 else 0)
                .reportedPathSha256s(path.map { WalkerHarness.hash(it).toByteArray() })
                .terminalKind(if (path.isEmpty()) null else TerminalKind.ANCHOR)
                .anchorSha256(path.lastOrNull()?.let { WalkerHarness.hash(it).toByteArray() })
                .issuerSpkiSha256s(listOfNotNull(key?.let { WalkerCerts.cert(it).spkiHash.toByteArray() }))
        }
        assertEquals(want.findings + listOfNotNull(want.notUsed?.let(::notUsed)), d.findings, "$at: findings")
        val stats = d.detail.walkStats
        if (row.noWalk) {
            assertEquals(WalkStats(0, 0), stats, "$at: no walk")
        } else {
            row.fixture.walk.verifications
                ?.let { assertEquals(it, stats.verifications, "$at: verifications") }
            row.fixture.walk.candidatesExplored?.let {
                assertEquals(it, stats.candidatesExplored, "$at: candidatesExplored")
            }
        }
    }

    /** The walk's own path, for a generated row: its Walk column asserts it and its leaf key. */
    private fun walkedPath(row: DecisionRow): List<ByteArray> {
        val found = assertIs<Walk.Found>(WalkerHarness.walk(row.fixture), "$row: a generated row is Found")
        return found.path.certs.map { it.der }
    }

    private fun verdicts(
        row: DecisionRow,
        want: Want,
        enabled: Boolean,
        d: PathDecision,
        at: String,
    ) {
        for ((revoked, expected) in listOf(true to want.verdict.revoked, false to want.verdict.clean)) {
            val honest = if (revoked) CrliteQueryResult.REVOKED else CrliteQueryResult.NOT_REVOKED
            val engine = StubEngine { if (it == row.honestKey) honest else CrliteQueryResult.NOT_ENROLLED }
            val fallback = if (enabled) row.fallback() else null
            val run =
                Run(row.fixture.presented, snapshot = snapshot(row.crlite), engine = engine) { row.decide(fallback) }
            val v = run.evaluate().verdict
            val case = "$at, honest key $honest"
            assertEquals(expected.rules, v.rules, "$case: rules")
            assertEquals(expected.rule, (v as? Verdict.Rejected)?.rule, "$case: rule")
            if (expected.rule == null) assertIs<Verdict.Accepted>(v, case)
            // The relation to the honest chain: REVOKED fires exactly when the honest key is evaluated (s2, revision 49).
            if (revoked && row.crlite?.generationId != null) {
                assertEquals(row.honestKey in d.issuerKeys, Rule.REVOKED in v.rules, "$case: REVOKED ⇔ honest key")
            }
        }
    }

    /**
     * A row presenting more than `MAX_PRESENTED` certificates is walker-harness only: on every trust-manager path and
     * `Revokt.evaluate` it is cut at step 3, `PATH_BUDGET_EXCEEDED(EXPLORATION_BUDGET)` without a walk, no CRLite query
     * and no `FallbackNotUsed`, as (ag) asserts.
     */
    private fun cut(row: DecisionRow) {
        val fallback = row.fallback()
        val (d, calls) = cutDecision(row.fixture, fallback)
        val at = "$row, step 3 cut"
        assertPath(d, at) { status(PathStatus.PATH_BUDGET_EXCEEDED).reason(PathReason.EXPLORATION_BUDGET) }
        assertEquals(WalkStats(0, 0), d.detail.walkStats, "$at: no walk")
        assertEquals(0, calls, "$at: no verification")
        assertEquals(emptyList(), d.findings, "$at: no FallbackNotUsed")
        assertEquals(0, (fallback as? SymPathBuilder)?.calls ?: 0, "$at: no fallback")
    }
}
