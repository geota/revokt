// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import com.code_intelligence.jazzer.junit.FuzzTest

/**
 * #214's Jazzer target over [StoreModel]: the input's bytes are the model's choices, one per choice, so the nightly
 * fuzzing explores sequences of syncs, faults, stops and damage the fixed seeds of [StoreModelTest] do not reach. A
 * broken invariant is a [ModelViolation] naming the steps. With `JAZZER_FUZZ` unset JUnit replays
 * `StoreModelFuzzTestInputs/`; the nightly job runs it with `-max_len=512`.
 */
class StoreModelFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun explore(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** The steps of one input: each takes a few choices, so longer inputs reach deeper states. */
        private const val STEPS = 16

        private val model by lazy { StoreModel() }

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            model.run(Choices.bytes(data), STEPS)
        }
    }
}
