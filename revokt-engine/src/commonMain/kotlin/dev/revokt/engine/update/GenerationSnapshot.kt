// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.Freshness

/**
 * What the loader publishes for handshakes to read (spec §3 "Purity gate", §5.1 flow step 2): one immutable value
 * behind one `@Volatile` reference, whose only writers are the loader dispatcher and, in the sole-seed synchronous path
 * of §4 S, the `start()` caller before any loader task exists. A handshake reads it once and threads it through the
 * walk, the engine query and the data rules, so the store is never read on the handshake path.
 *
 * [generationEpoch] is the verdict-cache key's generation part (spec §6.5 install order, §8): it advances on every install and when
 * a dataset leaves `pending` without a generation. Process-local, never persisted. [coverageEndMillis] is the engine's
 * `RevocationEngine.coverageEndMillis` for the generation it holds, null when the engine cannot tell.
 */
internal class GenerationSnapshot(
    val generationEpoch: Long,
    datasets: Map<Dataset, DatasetGeneration>,
    val coverageEndMillis: Long?,
) {
    /** One entry per configured dataset. */
    val datasets: Map<Dataset, DatasetGeneration> = buildMap { putAll(datasets) }

    override fun equals(other: Any?): Boolean =
        other is GenerationSnapshot &&
            generationEpoch == other.generationEpoch &&
            datasets == other.datasets &&
            coverageEndMillis == other.coverageEndMillis

    override fun hashCode(): Int = listOf(generationEpoch, datasets, coverageEndMillis).hashCode()

    override fun toString(): String =
        "GenerationSnapshot(generationEpoch=$generationEpoch, datasets=$datasets, coverageEndMillis=$coverageEndMillis)"
}

/**
 * One dataset's published generation, the inputs of its `Finding.DataState` (spec §4, §8 data rules) other than the
 * age, which the handshake computes from its own clock read; [generationId] is null when the dataset has none.
 *
 * - [pending]: the start task has not yet passed the seed step for this dataset (in-process).
 * - [staleGateOpen]: §8's persisted `STALE` gate for a seed generation, evaluated by the loader when it writes
 *   `updater.json` (`datasetLastAttemptAtMillis ≥ seedInstalledAtMillis`, or no fetching source), so the handshake
 *   never reads the store. Read only when [fromSeed].
 * - [clockBehind]: `sourceTimestampMillis > now + clockSkew` at this publish; recomputed at every publish.
 * - [maxCoverageMillis]: the generation's maximum coverage `high` as the loader decoded it from its `index.bin` at
 *   install ([maxCoverageMillis] of the index), null when it covers no log: the §6.3 coverage-monotonic bound the next
 *   sync compares against ([LiveGeneration]), never the engine's `coverageEndMillis`, which an injected engine may leave
 *   null (#137's review note on #190).
 */
internal data class DatasetGeneration(
    val generationId: String?,
    val freshness: Freshness?,
    val fromSeed: Boolean,
    val sourceTimestampMillis: Long?,
    val seedFormat: Int?,
    val pending: Boolean,
    val staleGateOpen: Boolean,
    val clockBehind: Boolean,
    val maxCoverageMillis: Long? = null,
)
