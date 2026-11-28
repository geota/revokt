// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.clubcard.RevoktInternalApi

/**
 * Spec §9.1 target "v3/v4 filter decoders", the coverage-only read ([ClubcardFilters.coverage], spec §6.5 Load) over
 * bytes read back from the store: its only declared results are a coverage or a [ClubcardFormatException]; and
 * differentially against [ClubcardFilters.decode], whenever decode returns a filter the coverage read returns its
 * universe, entry for entry and in order, so a load that reads coverage alone builds the `index.bin` an install built
 * from the whole filter. With `JAZZER_FUZZ` unset JUnit replays the committed inputs in
 * `ClubcardCoverageFuzzTestInputs/`. Fuzzing runs it with `-max_len=16777217`, `RevoktLimits.MAX_FILTER_BYTES` + 1
 * (§9.1: the default filter cap + 1; the reader has no cap of its own).
 */
@OptIn(RevoktInternalApi::class)
class ClubcardCoverageFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun coverageAgreesWithDecode(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** The static entry point a standalone Jazzer driver calls (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val coverage = orNull { ClubcardFilters.coverage(data).logs.toList() }
            val decoded =
                orNull {
                    ClubcardFilters
                        .decode(data)
                        .universe.logs
                        .toList()
                }
            if (decoded != null) check(coverage == decoded) { "coverage read $coverage, decode $decoded" }
        }

        /** [block]'s result, or null for the one declared failure; any other throwable is a finding and propagates. */
        private fun <T> orNull(block: () -> T): T? =
            try {
                block()
            } catch (_: ClubcardFormatException) {
                null
            }
    }
}
