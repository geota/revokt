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
        /** The steps of an input of 128 bytes or less; a longer one draws one more step per [BYTES_PER_STEP] bytes. */
        private const val STEPS = 16

        /** About the choices one step draws, so every byte of a longer input can matter. */
        private const val BYTES_PER_STEP = 8

        /** The steps of the longest input the nightly job feeds (`-max_len=512`). */
        private const val MAX_STEPS = 64

        private val model by lazy { StoreModel() }

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            model.run(Choices.bytes(data), (data.size / BYTES_PER_STEP).coerceIn(STEPS, MAX_STEPS))
        }
    }
}
