// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.Exemption
import dev.revokt.Outcome
import dev.revokt.Rule
import dev.revokt.RuleClass

/**
 * A policy as decide and evaluate read it (spec §3, §8): the public `RevoktPolicy` (jvmMain) compiles to it, so
 * commonMain never sees `java.time`. One row per rule, an outcome for every rule and an exemption where one is
 * registered, plus the required datasets, the staleness map and `signedSourceFailingAfter` in milliseconds. Every
 * input is copied into a read-only collection.
 *
 * [preset] is the preset the policy derives from (spec §4 "Growability contract": `newBuilder()` only from a preset).
 */
internal class PolicyForm(
    val preset: Preset,
    outcomes: Map<Rule, Outcome>,
    exemptions: Map<Rule, Exemption>,
    requiredDatasets: Set<Dataset>,
    staleness: Map<Dataset, StalenessTable>,
    val signedSourceFailingAfterMillis: Long,
) {
    val outcomes: Map<Rule, Outcome> = buildMap { putAll(outcomes) }

    val exemptions: Map<Rule, Exemption> = buildMap { putAll(exemptions) }

    val requiredDatasets: Set<Dataset> = buildSet { addAll(requiredDatasets) }

    val staleness: Map<Dataset, StalenessTable> = buildMap { putAll(staleness) }

    init {
        val missing = Rule.entries.filter { it !in this.outcomes }
        require(missing.isEmpty()) { "a policy has an outcome for every rule; missing $missing" }
    }

    fun outcome(rule: Rule): Outcome = outcomes.getValue(rule)

    fun exemption(rule: Rule): Exemption? = exemptions[rule]

    fun staleness(dataset: Dataset): StalenessTable? = staleness[dataset]

    companion object {
        /** [preset] itself, as spec §8 tabulates it, with no exemptions. */
        fun of(preset: Preset): PolicyForm {
            val table = PolicyTable.preset(preset)
            return PolicyForm(
                preset = preset,
                outcomes = Rule.entries.associateWith(table::outcome),
                exemptions = emptyMap(),
                requiredDatasets = table.requiredDatasets,
                staleness = table.staleness,
                signedSourceFailingAfterMillis = table.signedSourceFailingAfterMillis,
            )
        }
    }
}

/**
 * Whether `exemptAnchors` covers [this] rule when its outcome is `REJECT` (spec §4 `exemptAnchors`): exemptable, not
 * `EVIDENCE` (an M2 `ONECRL` or M4 `DISTRUST` exemption is always explicit, so an M1 call never widens to evidence on
 * upgrade), and not marked "empty path" in the §8 table, where `anchorIn` can never match.
 */
internal fun Rule.anchorExemptable(): Boolean =
    exemptable && ruleClass != RuleClass.EVIDENCE && this !in PolicyTable.EMPTY_PATH
