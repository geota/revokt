// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import com.code_intelligence.jazzer.junit.FuzzTest

/**
 * Spec §9.1 target "store readers": `store.version` (§6.5), read from a disk that can rot. [StoreVersion.parse] returns
 * a version or null, never throws, and returns one exactly when the bytes are ASCII `[1-9][0-9]{0,8}`; a version it
 * returns is written back to the same bytes. `-max_len=10`, the 9-digit cap + 1, so the over-cap answer is reached.
 * With `JAZZER_FUZZ` unset JUnit replays `StoreVersionFuzzTestInputs/`.
 */
class StoreVersionFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun parse(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private val GRAMMAR = Regex("[1-9][0-9]{0,8}")

        /** The static entry point a standalone Jazzer driver calls (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val version = StoreVersion.parse(data)
            check(version == StoreVersion.parse(data)) { "a second parse differs" }
            val ascii = data.all { it in 0..0x7f }
            val matches = ascii && GRAMMAR.matches(String(data, Charsets.US_ASCII))
            check((version != null) == matches) { "parsed ${data.contentToString()} as $version" }
            if (version != null) check(StoreVersion.encode(version).contentEquals(data)) { "does not round-trip" }
        }
    }
}
