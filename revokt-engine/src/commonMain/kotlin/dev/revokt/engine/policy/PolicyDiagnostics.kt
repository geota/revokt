// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.Enforcement
import dev.revokt.Outcome
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevoktTestingApi
import dev.revokt.Rule
import dev.revokt.RuleClass
import dev.revokt.Severity

/**
 * The V diagnostics of spec §4 that are functions of the policy alone, in the order §4 lists them, each code's rules
 * in `Rule.PRECEDENCE` order and its datasets in declaration order. `Revokt.validate(enforcement)` (#139) adds the
 * configuration-dependent ones. Only `EVIDENCE_LOWERED_BELOW_PRESET` can be an `ERROR`, and only under `ENFORCE`.
 *
 * [currentMinor] and [flippedIn] are the growability table's (`PolicyTable`); tests pass others to reach the grace
 * minor before any preset row has flipped.
 */
internal fun validatePolicy(
    policy: PolicyForm,
    enforcement: Enforcement,
    currentMinor: String = PolicyTable.CURRENT_MINOR,
    flippedIn: (Preset, Rule) -> String? = PolicyTable::flippedIn,
): List<PolicyDiagnostic> =
    staleRejectsWithoutThreshold(policy) +
        exemptOnAllow(policy) +
        evidenceLoweredBelowPreset(policy, enforcement) { rule -> flippedIn(policy.preset, rule) == currentMinor } +
        exemptionOnEvidenceRule(policy) +
        budgetAllows(policy) +
        stalenessClearedForRequiredDataset(policy)

/** `STALE` rejects, and no dataset has a `rejectStaleAfter`: the rule can never fire. */
private fun staleRejectsWithoutThreshold(policy: PolicyForm): List<PolicyDiagnostic> =
    if (policy.outcome(Rule.STALE) == Outcome.REJECT &&
        policy.staleness.values.none { it.rejectStaleAfterMillis != null }
    ) {
        listOf(
            diagnostic(
                DiagnosticCode.STALE_REJECTS_WITHOUT_THRESHOLD,
                Severity.WARNING,
                Rule.STALE,
                "STALE rejects, but no dataset has a rejectStaleAfter, so it can never fire",
            ),
        )
    } else {
        emptyList()
    }

/** An exemption on a rule that allows, so it never runs. */
private fun exemptOnAllow(policy: PolicyForm): List<PolicyDiagnostic> =
    Rule.PRECEDENCE
        .filter { policy.exemption(it) != null && policy.outcome(it) == Outcome.ALLOW }
        .map { rule ->
            diagnostic(
                DiagnosticCode.EXEMPT_ON_ALLOW,
                Severity.WARNING,
                rule,
                "$rule has an exemption but allows, so the exemption never runs",
            )
        }

/**
 * An `EVIDENCE` rule that allows where the preset the policy derives from rejects. Under `ENFORCE` it is a `WARNING`
 * in the minor the preset row flipped ([inGrace]) and an `ERROR` otherwise, from the next minor or, for a row that has
 * rejected since the major's x.0, at once; a `WARNING` under every other enforcement.
 */
private fun evidenceLoweredBelowPreset(
    policy: PolicyForm,
    enforcement: Enforcement,
    inGrace: (Rule) -> Boolean,
): List<PolicyDiagnostic> {
    val preset = PolicyTable.preset(policy.preset)
    return Rule.PRECEDENCE
        .filter {
            it.ruleClass == RuleClass.EVIDENCE &&
                policy.outcome(it) == Outcome.ALLOW &&
                preset.outcome(it) == Outcome.REJECT
        }.map { rule ->
            val fatal = enforcement == Enforcement.ENFORCE && !inGrace(rule)
            diagnostic(
                DiagnosticCode.EVIDENCE_LOWERED_BELOW_PRESET,
                if (fatal) Severity.ERROR else Severity.WARNING,
                rule,
                "$rule allows, but ${policy.preset}, which this policy derives from, rejects it: derive from DEFAULT " +
                    "and raise the other rows, or exempt per anchor",
            )
        }
}

/** An exemption on an `EVIDENCE` rule: a constant-true one is `ALLOW` by another name. */
private fun exemptionOnEvidenceRule(policy: PolicyForm): List<PolicyDiagnostic> =
    Rule.PRECEDENCE
        .filter { it.ruleClass == RuleClass.EVIDENCE && policy.exemption(it) != null }
        .map { rule ->
            diagnostic(
                DiagnosticCode.EXEMPTION_ON_EVIDENCE_RULE,
                Severity.WARNING,
                rule,
                "$rule is an evidence rule with an exemption; a constant-true exemption is ALLOW by another name",
            )
        }

/** `PATH_BUDGET_EXCEEDED` allows, which re-opens the chain-stuffing evasion. */
private fun budgetAllows(policy: PolicyForm): List<PolicyDiagnostic> =
    if (policy.outcome(Rule.PATH_BUDGET_EXCEEDED) == Outcome.ALLOW) {
        listOf(
            diagnostic(
                DiagnosticCode.BUDGET_ALLOWS,
                Severity.WARNING,
                Rule.PATH_BUDGET_EXCEEDED,
                "PATH_BUDGET_EXCEEDED allows, which re-opens the chain-stuffing evasion",
            ),
        )
    } else {
        emptyList()
    }

/**
 * A required dataset whose staleness entry is cleared: the preset the policy derives from has one, and the policy has
 * none. A dataset the preset never had an entry for (a later minor's, §4 "Growability contract") is not "cleared".
 */
private fun stalenessClearedForRequiredDataset(policy: PolicyForm): List<PolicyDiagnostic> {
    val preset = PolicyTable.preset(policy.preset)
    return Dataset.entries
        .filter { it in policy.requiredDatasets && it in preset.staleness && policy.staleness(it) == null }
        .map { dataset ->
            diagnostic(
                DiagnosticCode.STALENESS_CLEARED_FOR_REQUIRED_DATASET,
                Severity.WARNING,
                rule = null,
                dataset = dataset,
                message = "required dataset $dataset has no staleness entry: stale data is not flagged or rejected",
            )
        }
}

@OptIn(RevoktTestingApi::class)
private fun diagnostic(
    code: DiagnosticCode,
    severity: Severity,
    rule: Rule?,
    message: String,
    dataset: Dataset? = null,
): PolicyDiagnostic =
    PolicyDiagnostic
        .Builder()
        .code(code)
        .severity(severity)
        .rule(rule)
        .dataset(dataset)
        .message(message)
        .build()
