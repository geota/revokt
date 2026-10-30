// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.Outcome
import dev.revokt.Rule
import dev.revokt.TrustClass

/** The two presets of spec §8. */
internal enum class Preset { DEFAULT, STRICT }

/**
 * A dataset's staleness thresholds (spec §8): [staleAfterMillis] is the loud flag only (`DataState.stale`), and
 * [rejectStaleAfterMillis] the only threshold at which `Rule.STALE` fires; null means it never fires.
 */
internal data class StalenessTable(
    val staleAfterMillis: Long,
    val rejectStaleAfterMillis: Long?,
)

/**
 * One preset as spec §8 tabulates it: an outcome for every rule, the required datasets, the staleness and
 * `minTrustClass` maps and the three time fields, all in milliseconds. The public `RevoktPolicy` (0.2) wraps it.
 */
internal class PresetTable(
    private val outcomes: Map<Rule, Outcome>,
    val requiredDatasets: Set<Dataset>,
    val staleness: Map<Dataset, StalenessTable>,
    val minTrustClass: Map<Dataset, TrustClass>,
    val rollbackWindowMillis: Long,
    val clockSkewMillis: Long,
    val signedSourceFailingAfterMillis: Long,
) {
    fun outcome(rule: Rule): Outcome = outcomes.getValue(rule)
}

/**
 * The preset table of spec §8 and the per-rule columns the growability golden fixture carries besides `Rule`'s own
 * (spec §4 "Growability contract"): the "empty path" mark, the minor that introduced each rule and the minor in which
 * a preset's outcome flipped from `ALLOW` to `REJECT`.
 */
internal object PolicyTable {
    private const val DAY_MILLIS = 24L * 60 * 60 * 1_000

    /**
     * `DEFAULT` rejects only the evidence, the budget and missing data. `STALE` and `UNSIGNED_DATA` never fire in it;
     * their recorded outcome, `ALLOW`, follows `validate()`'s `STALE_REJECTS_WITHOUT_THRESHOLD` for `STALE`, and
     * awaits the spec decision in #75 for `UNSIGNED_DATA`.
     */
    private fun defaultOutcome(rule: Rule): Outcome =
        when (rule) {
            Rule.REVOKED, Rule.PATH_BUDGET_EXCEEDED, Rule.NO_DATA -> Outcome.REJECT

            Rule.ENGINE_ERROR, Rule.PARSE_FAILED, Rule.ISSUER_UNVERIFIED, Rule.NO_ISSUER, Rule.NOT_ENROLLED,
            Rule.NO_SCTS, Rule.NOT_COVERED, Rule.STALE, Rule.UNSIGNED_DATA,
            -> Outcome.ALLOW
        }

    /** `STRICT` rejects everything but `NOT_COVERED`, the coverage gap every preset leaves unchecked. */
    private fun strictOutcome(rule: Rule): Outcome =
        when (rule) {
            Rule.NOT_COVERED -> Outcome.ALLOW

            Rule.REVOKED, Rule.PATH_BUDGET_EXCEEDED, Rule.NO_DATA, Rule.ENGINE_ERROR, Rule.PARSE_FAILED,
            Rule.ISSUER_UNVERIFIED, Rule.NO_ISSUER, Rule.NOT_ENROLLED, Rule.NO_SCTS, Rule.STALE, Rule.UNSIGNED_DATA,
            -> Outcome.REJECT
        }

    val DEFAULT: PresetTable =
        PresetTable(
            outcomes = Rule.entries.associateWith(::defaultOutcome),
            requiredDatasets = setOf(Dataset.CRLITE),
            staleness = mapOf(Dataset.CRLITE to StalenessTable(3 * DAY_MILLIS, null)),
            minTrustClass = Dataset.entries.associateWith { TrustClass.BUNDLED },
            rollbackWindowMillis = DAY_MILLIS,
            clockSkewMillis = DAY_MILLIS,
            signedSourceFailingAfterMillis = DAY_MILLIS,
        )

    val STRICT: PresetTable =
        PresetTable(
            outcomes = Rule.entries.associateWith(::strictOutcome),
            requiredDatasets = setOf(Dataset.CRLITE),
            staleness = mapOf(Dataset.CRLITE to StalenessTable(3 * DAY_MILLIS, 30 * DAY_MILLIS)),
            minTrustClass = Dataset.entries.associateWith { TrustClass.SIGNED },
            rollbackWindowMillis = DAY_MILLIS,
            clockSkewMillis = DAY_MILLIS,
            signedSourceFailingAfterMillis = DAY_MILLIS,
        )

    fun preset(preset: Preset): PresetTable =
        when (preset) {
            Preset.DEFAULT -> DEFAULT
            Preset.STRICT -> STRICT
        }

    /**
     * The rules marked "empty path" in the spec §8 table: they fire only on an empty reported path, where `anchorIn`
     * never matches, so `exemptAnchors` skips them.
     */
    val EMPTY_PATH: Set<Rule> = setOf(Rule.ISSUER_UNVERIFIED, Rule.NO_ISSUER)

    /** The minor that introduced [rule]: every M1 rule is 0.1's. */
    fun introducedIn(rule: Rule): String =
        when (rule) {
            Rule.REVOKED, Rule.PATH_BUDGET_EXCEEDED, Rule.NO_DATA, Rule.ENGINE_ERROR, Rule.PARSE_FAILED,
            Rule.ISSUER_UNVERIFIED, Rule.NO_ISSUER, Rule.NOT_ENROLLED, Rule.NO_SCTS, Rule.NOT_COVERED, Rule.STALE,
            Rule.UNSIGNED_DATA,
            -> "0.1"
        }

    /** The one-minor `ALLOW → REJECT` flips made so far, by preset and rule: none yet. */
    private val FLIPPED: Map<Pair<Preset, Rule>, String> = emptyMap()

    /** The minor in which [preset]'s outcome for [rule] flipped from `ALLOW` to `REJECT`; null while none has. */
    fun flippedIn(
        preset: Preset,
        rule: Rule,
    ): String? = FLIPPED[preset to rule]
}
