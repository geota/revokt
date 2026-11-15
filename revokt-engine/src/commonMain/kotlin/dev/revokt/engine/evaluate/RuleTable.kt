// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.Finding
import dev.revokt.Layer
import dev.revokt.Outcome
import dev.revokt.PathStatus
import dev.revokt.Rule
import dev.revokt.RuleClass
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.firedRule

/**
 * Everything a rule's predicate reads (spec §5.1 decision step 8: "rules fire from the path status, the CRLite
 * results, the `DataState`s and an exemption that throws"), as plain data, so a later policy-language rule (#84) reads
 * the same facts:
 * - [pathStatus], `NOT_WALKED` when the evaluation did not reach the walk;
 * - [crliteResults], one per evaluated leaf-issuer key in `issuerSpkiSha256s` order, and [crlitePublished], whether
 *   the snapshot held a CRLite generation (an engine's `NO_DATA` is then its error, §4);
 * - [dataStates], whose `rules` the data-rule rows have already filled;
 * - [boundaryError] and [exemptionError], whether the catch boundary caught a throw and whether an exemption threw.
 */
internal data class RuleFacts(
    val pathStatus: PathStatus,
    val crliteResults: List<CrliteQueryResult>,
    val crlitePublished: Boolean,
    val dataStates: Map<Dataset, Finding.DataState>,
    val boundaryError: Boolean,
    val exemptionError: Boolean,
) {
    /** The rule the path status fires (spec §4 "Status-to-rule mappings"), or null. */
    val pathRule: Rule? get() = pathStatus.firedRule()

    /**
     * The CRLite rules after key aggregation (spec §4 "Key aggregation (L3, M1)"): `REVOKED` alone when any evaluated
     * key is `REVOKED`; otherwise every evaluated key's non-answer or engine error, except on `Budget`
     * (`PATH_BUDGET_EXCEEDED`), where only `REVOKED` fires and the other results are findings only. With no evaluated
     * key nothing fires: no keys is never read as a clean answer, the path status's own rule decides.
     */
    val crliteRules: Set<Rule>
        get() {
            val fired = crliteResults.mapNotNullTo(HashSet()) { it.firedRule(crlitePublished) }
            return when {
                Rule.REVOKED in fired -> setOf(Rule.REVOKED)
                pathStatus == PathStatus.PATH_BUDGET_EXCEEDED -> emptySet()
                else -> fired
            }
        }

    /** Whether [rule] fired for any dataset. */
    fun dataRule(rule: Rule): Boolean = dataStates.values.any { rule in it.rules }
}

/**
 * One rule's row (spec §4, §8): the predicate over [RuleFacts] that fires [rule]. Its class, layer and exemptable flag
 * are the rule's own, and its outcome is the policy's, so a row is the whole definition of a rule's evaluation, and a
 * later rule (M2's layers, #84's `POLICY`) is one more row.
 */
internal class RuleRow(
    val rule: Rule,
    val fires: (RuleFacts) -> Boolean,
) {
    val ruleClass: RuleClass get() = rule.ruleClass

    val layer: Layer? get() = rule.layer

    val exemptable: Boolean get() = rule.exemptable
}

/** A rule that fired and the outcome the policy maps it to, before any exemption runs. */
internal data class FiredRule(
    val rule: Rule,
    val outcome: Outcome,
)

/**
 * The rule table: one row per `Rule`, in `Rule.PRECEDENCE` order (spec §4 "Status-to-rule mappings", "Key
 * aggregation", "Data rules"; §8 "Produced by"). `ENGINE_ERROR` has its three producers (§5.5): an engine result, the
 * catch boundary and an exemption that throws.
 */
internal val RULE_TABLE: List<RuleRow> =
    listOf(
        RuleRow(Rule.REVOKED) { Rule.REVOKED in it.crliteRules },
        RuleRow(Rule.PATH_BUDGET_EXCEEDED) { it.pathRule == Rule.PATH_BUDGET_EXCEEDED },
        RuleRow(Rule.NO_DATA) { it.dataRule(Rule.NO_DATA) },
        RuleRow(Rule.ENGINE_ERROR) { Rule.ENGINE_ERROR in it.crliteRules || it.boundaryError || it.exemptionError },
        RuleRow(Rule.PARSE_FAILED) { it.pathRule == Rule.PARSE_FAILED },
        RuleRow(Rule.ISSUER_UNVERIFIED) { it.pathRule == Rule.ISSUER_UNVERIFIED },
        RuleRow(Rule.NO_ISSUER) { it.pathRule == Rule.NO_ISSUER },
        RuleRow(Rule.NOT_ENROLLED) { Rule.NOT_ENROLLED in it.crliteRules },
        RuleRow(Rule.NO_SCTS) { Rule.NO_SCTS in it.crliteRules },
        RuleRow(Rule.NOT_COVERED) { Rule.NOT_COVERED in it.crliteRules },
        RuleRow(Rule.STALE) { it.dataRule(Rule.STALE) },
        RuleRow(Rule.UNSIGNED_DATA) { it.dataRule(Rule.UNSIGNED_DATA) },
    )

/**
 * The rules [facts] fire, each with [policy]'s outcome, in `Rule.PRECEDENCE` order: the explicit intermediate result
 * of decision step 8, before exemptions and the final outcome (spec §5.1).
 */
internal fun fire(
    facts: RuleFacts,
    policy: PolicyForm,
): List<FiredRule> = RULE_TABLE.filter { it.fires(facts) }.map { FiredRule(it.rule, policy.outcome(it.rule)) }

/**
 * `Verdict.rule` (spec §4, §5.1 decision step 8): the first of [fired] whose outcome is `REJECT` and that is not in
 * [exempted], in `Rule.PRECEDENCE` order whatever order [fired] is in; null when there is none, an `Accepted` verdict.
 */
internal fun verdictRule(
    fired: List<FiredRule>,
    exempted: Set<Rule>,
): Rule? {
    val rejecting = fired.filter { it.outcome == Outcome.REJECT && it.rule !in exempted }.mapTo(HashSet()) { it.rule }
    return Rule.PRECEDENCE.firstOrNull { it in rejecting }
}
