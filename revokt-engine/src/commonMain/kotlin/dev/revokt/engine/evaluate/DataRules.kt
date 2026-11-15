// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.Dataset
import dev.revokt.Finding
import dev.revokt.RevoktTestingApi
import dev.revokt.Rule
import dev.revokt.TrustClass
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.StalenessTable
import dev.revokt.engine.update.DatasetGeneration
import dev.revokt.engine.update.GenerationSnapshot

/**
 * What one data rule reads about one dataset (spec §8 data rules): its published [generation] (null when the snapshot
 * has no entry for it), whether the policy [required] it, its [ageMillis] (null with no generation or no clock read),
 * the policy's [staleness] entry and [minTrustClass] floor. Plain data, like every fact a rule reads.
 */
internal class DatasetFacts(
    val dataset: Dataset,
    val generation: DatasetGeneration?,
    val required: Boolean,
    val ageMillis: Long?,
    val staleness: StalenessTable?,
    val minTrustClass: TrustClass,
) {
    val generationId: String? get() = generation?.generationId

    val pending: Boolean get() = generation?.pending == true
}

/** One data rule's row (spec §8 data rules): the per-dataset predicate that fires [rule] for a dataset. */
internal class DataRuleRow(
    val rule: Rule,
    val fires: (DatasetFacts) -> Boolean,
)

/**
 * The three data rules, one row each in `Rule.PRECEDENCE` order (spec §4 "Data rules", §8):
 * - `NO_DATA` for a required dataset with no generation that is not `pending` (never with a generation installed from
 *   a seed or a system cache, §5.1 decision step 7);
 * - `STALE` for a dataset with a staleness entry whose `rejectStaleAfter` is set, when `ageMillis > rejectStaleAfter`
 *   and, for a `fromSeed` generation, the persisted seed gate is open (a sync attempt has completed since the seed
 *   install, or no fetching source is configured);
 * - `UNSIGNED_DATA` when the generation's `trustClass` ranks below the policy's `minTrustClass` (never on a null
 *   `trustClass`, that is with no generation).
 */
internal val DATA_RULES: List<DataRuleRow> =
    listOf(
        DataRuleRow(Rule.NO_DATA) { it.required && it.generationId == null && !it.pending },
        DataRuleRow(Rule.STALE) { f ->
            val reject = f.staleness?.rejectStaleAfterMillis
            val age = f.ageMillis
            val gateOpen = f.generation?.let { !it.fromSeed || it.staleGateOpen } == true
            reject != null && age != null && age > reject && gateOpen
        },
        DataRuleRow(Rule.UNSIGNED_DATA) { f ->
            val trustClass = f.generation?.trustClass
            trustClass != null && trustClass.rank < f.minTrustClass.rank
        },
    )

/**
 * The data states of one verdict (spec §4 `Verdict.dataStates`, §5.1 decision step 7, §8): one per dataset that
 * [policy] requires or [snapshot] holds (the datasets a layer consults), in `Dataset` order, computed before decision
 * step 1 so they are on every verdict whatever the path or any exception. [nowMillis] is the evaluation's one clock
 * read, null when the clock threw: then no age is known, so nothing is stale and `STALE` cannot fire, while `NO_DATA`
 * and `UNSIGNED_DATA`, which need no time, still do.
 *
 * `ageMillis = now − sourceTimestampMillis`, clamped at 0 (the clock-behind case, §4 `DataState.clockBehind`);
 * `stale` is `ageMillis > staleAfter` for a dataset with a staleness entry, the loud flag that fires no rule; `rules` is
 * what [DATA_RULES] fire. A required dataset the snapshot does not hold has no generation and is not pending.
 */
@OptIn(RevoktTestingApi::class)
internal fun dataStates(
    snapshot: GenerationSnapshot,
    policy: PolicyForm,
    nowMillis: Long?,
): Map<Dataset, Finding.DataState> =
    buildMap {
        for (dataset in Dataset.entries) {
            val required = dataset in policy.requiredDatasets
            val generation = snapshot.datasets[dataset]
            if (!required && generation == null) continue
            val timestamp = generation?.sourceTimestampMillis
            val age = if (timestamp == null || nowMillis == null) null else (nowMillis - timestamp).coerceAtLeast(0)
            val staleness = policy.staleness(dataset)
            val facts = DatasetFacts(dataset, generation, required, age, staleness, policy.minTrustClass(dataset))
            put(
                dataset,
                Finding.DataState
                    .Builder()
                    .dataset(dataset)
                    .trustClass(generation?.trustClass)
                    .generationId(generation?.generationId)
                    .freshness(generation?.freshness)
                    .fromSeed(generation?.fromSeed == true)
                    .sourceTimestampMillis(timestamp)
                    .ageMillis(age)
                    .pending(facts.pending)
                    .clockBehind(generation?.clockBehind == true)
                    .seedFormat(generation?.seedFormat)
                    .stale(staleness != null && age != null && age > staleness.staleAfterMillis)
                    .rules(DATA_RULES.filter { it.fires(facts) }.mapTo(HashSet()) { it.rule })
                    .build(),
            )
        }
    }
