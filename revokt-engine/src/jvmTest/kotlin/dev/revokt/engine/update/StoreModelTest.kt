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
        for (seed in 1L..SEEDS) {
            try {
                model.run(Choices.seeded(seed), STEPS)
            } catch (v: ModelViolation) {
                throw ModelViolation("seed $seed: ${v.message}", v)
            }
        }
    }

    private companion object {
        const val SEEDS = 200L
        const val STEPS = 24
    }
}
