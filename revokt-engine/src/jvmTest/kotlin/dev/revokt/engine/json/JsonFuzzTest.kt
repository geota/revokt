// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import com.code_intelligence.jazzer.junit.FuzzTest

/**
 * Spec §9.1 target "JSON and canonical JSON" (#92): the only declared result of a parse is a tree or a
 * [JsonParseException]; anything else is a finding. A tree's canonical JSON is printable ASCII, reads back to the same
 * tree, and canonicalises to the same bytes again (`canonicalise(parse(canonicalise(parse(x)))) ==
 * canonicalise(parse(x))`). `-max_len=4194305`, `RevoktLimits.MAX_JSON_BYTES` + 1, so the over-cap rejection is
 * reached. With `JAZZER_FUZZ` unset JUnit replays the committed inputs in `JsonFuzzTestInputs/`.
 */
class JsonFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun parseAndCanonicalise(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val tree =
                try {
                    Json.parse(data)
                } catch (_: JsonParseException) {
                    return
                }
            val once = CanonicalJson.write(tree)
            check(once.all { it in 0x20..0x7E }) { "the canonical JSON is not printable ASCII" }
            // Escapes can triple a string's length, so the read-back is not held to the input cap.
            val again = Json.parse(once, maxBytes = Long.MAX_VALUE)
            check(again == tree) { "the canonical JSON reads back to a different tree" }
            check(CanonicalJson.write(again).contentEquals(once)) { "canonicalisation is not idempotent" }
        }
    }
}
