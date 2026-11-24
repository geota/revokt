// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import com.code_intelligence.jazzer.junit.FuzzTest

/**
 * Spec §9.1's walker fuzzer (#144, the 0.2 P1–P8 gate): each input is a generator seed, world shape and mutation list
 * ([WalkerFuzzInput]), checked by [WalkerFuzzRun] against P1 to P8. A property failure is a walker bug.
 *
 * With `JAZZER_FUZZ` unset JUnit replays `WalkerFuzzTestInputs/` (the PR tier; `WalkerFuzzCorpusTest` checks what each
 * committed input decodes to); the nightly job runs it with `-max_len=129` (the 128 bytes the input reads, plus one) and
 * `-timeout=10`.
 */
class WalkerFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun walk(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** The static entry point the nightly job's merge and minimise drive (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            WalkerFuzzRun(WalkerFuzzInput.decode(data)).check()
        }
    }
}
