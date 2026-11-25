// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits

/**
 * Spec §9.1 target "store readers" (#213): two of the files a store reads back from a disk that can rot, `current`
 * ([PointerJson]) and `updater.json` ([UpdaterJson]), each read from the same input; the generation file is
 * `GenerationFileFuzzTest`'s. A reader returns a value or null, never throws, and reads the same bytes the same way twice; over
 * `RevoktLimits.MAX_JSON_BYTES` every reader returns null. Whatever a reader returns is written and read back to
 * itself. `updater.json`, read at the start and at the end of the clock, never holds a backoff past
 * `now + MAX_BACKOFF`, and counts one store failure per dropped source entry and one for a malformed `sources`.
 * `-max_len=4194305`, `RevoktLimits.MAX_JSON_BYTES` + 1, so the over-cap answer is reached. With `JAZZER_FUZZ` unset
 * JUnit replays `StoreJsonFuzzTestInputs/`.
 */
class StoreJsonFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** A clock in 2026, and one where `now + MAX_BACKOFF` saturates. */
        private val NOWS = listOf(1_763_251_200_000L, Long.MAX_VALUE - 1)

        /** The static entry point a standalone Jazzer driver calls (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val over = data.size > RevoktLimits.MAX_JSON_BYTES

            val pointer = PointerJson.read(data)
            check(pointer == PointerJson.read(data)) { "a second pointer read differs" }
            check(!over || pointer == null) { "a pointer over the cap" }
            if (pointer != null) {
                check(PointerJson.read(PointerJson.write(pointer)) == pointer) { "the pointer does not round-trip" }
            }

            for (now in NOWS) {
                val read = UpdaterJson.read(data, now)
                check(read == UpdaterJson.read(data, now)) { "a second updater.json read differs" }
                check(!over || read == null) { "an updater.json over the cap" }
                if (read == null) continue
                val saturated = now > Long.MAX_VALUE - RevoktLimits.MAX_BACKOFF
                val cap = if (saturated) Long.MAX_VALUE else now + RevoktLimits.MAX_BACKOFF
                check(
                    read.record.sources.values
                        .all { (it.backoffUntilMillis ?: Long.MIN_VALUE) <= cap },
                ) { "a backoff past the cap" }
                check(read.droppedSources.none { it in read.record.sources }) { "a dropped source is kept" }
                check(
                    read.storeFailures == read.droppedSources.size + if (read.sourcesMalformed) 1 else 0,
                ) { "storeFailures" }
                val back = UpdaterJson.read(UpdaterJson.write(read.record, now), now)
                check(
                    back != null && back.record == read.record && back.storeFailures == 0,
                ) { "updater.json does not round-trip" }
            }
        }
    }
}
