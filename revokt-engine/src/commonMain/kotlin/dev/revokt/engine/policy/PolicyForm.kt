// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.Exemption
import dev.revokt.Outcome
import dev.revokt.Rule
import dev.revokt.RuleClass
import dev.revokt.TrustClass

/**
 * A policy as decide and evaluate read it (spec §3, §8): the public `RevoktPolicy` (jvmMain) compiles to it, so
 * commonMain never sees `java.time`. One row per rule, an outcome for every rule and an exemption where one is
 * registered, plus the required datasets, the staleness and `minTrustClass` maps and the three time fields in
 * milliseconds. Every input is copied into a read-only collection.
 *
 * [preset] is the preset the policy derives from (spec §4 "Growability contract": `newBuilder()` only from a preset).
 * [minTrustClass] holds only the entries the policy set; a dataset with none takes the preset's floor, which
 * therefore applies to datasets added later (§4).
 */
internal class PolicyForm(
    val preset: Preset,
    outcomes: Map<Rule, Outcome>,
    exemptions: Map<Rule, Exemption>,
    requiredDatasets: Set<Dataset>,
    staleness: Map<Dataset, StalenessTable>,
    minTrustClass: Map<Dataset, TrustClass>,
    val rollbackWindowMillis: Long,
    val clockSkewMillis: Long,
    val signedSourceFailingAfterMillis: Long,
) {
    val outcomes: Map<Rule, Outcome> = buildMap { putAll(outcomes) }

    val exemptions: Map<Rule, Exemption> = buildMap { putAll(exemptions) }

    val requiredDatasets: Set<Dataset> = buildSet { addAll(requiredDatasets) }

    val staleness: Map<Dataset, StalenessTable> = buildMap { putAll(staleness) }

    /** The `minTrustClass` entries this policy set; [minTrustClass] falls back to the preset for the others. */
    val minTrustClassEntries: Map<Dataset, TrustClass> = buildMap { putAll(minTrustClass) }

    init {
        val missing = Rule.entries.filter { it !in this.outcomes }
        require(missing.isEmpty()) { "a policy has an outcome for every rule; missing $missing" }
    }

    fun outcome(rule: Rule): Outcome = outcomes.getValue(rule)

    fun exemption(rule: Rule): Exemption? = exemptions[rule]

    fun staleness(dataset: Dataset): StalenessTable? = staleness[dataset]

    fun minTrustClass(dataset: Dataset): TrustClass =
        minTrustClassEntries[dataset] ?: PolicyTable.preset(preset).minTrustClass.getValue(dataset)

    companion object {
        /** [preset] itself, as spec §8 tabulates it: no exemptions, every `minTrustClass` the preset floor. */
        fun of(preset: Preset): PolicyForm {
            val table = PolicyTable.preset(preset)
            return PolicyForm(
                preset = preset,
                outcomes = Rule.entries.associateWith(table::outcome),
                exemptions = emptyMap(),
                requiredDatasets = table.requiredDatasets,
                staleness = table.staleness,
                minTrustClass = emptyMap(),
                rollbackWindowMillis = table.rollbackWindowMillis,
                clockSkewMillis = table.clockSkewMillis,
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
