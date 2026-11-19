// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import kotlin.test.Test

/**
 * #214's fixed-seed run of [StoreModel]: [SEEDS] seeds of [STEPS] steps each, every invariant checked after every step
 * and the recovery check at the end. A failure names its seed and steps; `StoreModelFuzzTest` explores further.
 */
internal class StoreModelTest {
    @Test
    fun `the store, install and sync keep the model's invariants under faults, stops and damage`() {
        val model = StoreModel()
        // `./gradlew :revokt-engine:jvmTest --tests '*StoreModelTest' -Drevokt.storeModel.seed=<n>` replays one seed.
        val seeds = System.getProperty("revokt.storeModel.seed")?.toLong()?.let { it..it } ?: 1L..SEEDS
        for (seed in seeds) {
            try {
                model.run(Choices.seeded(seed), STEPS)
            } catch (v: ModelViolation) {
                throw ModelViolation("seed $seed: ${v.message}", v)
            } catch (
                @Suppress("TooGenericExceptionCaught") t: Throwable,
            ) {
                // The model's own failure keeps its seed too.
                throw ModelViolation("seed $seed: the model threw $t", t)
            }
        }
    }

    private companion object {
        const val SEEDS = 200L
        const val STEPS = 24
    }
}
