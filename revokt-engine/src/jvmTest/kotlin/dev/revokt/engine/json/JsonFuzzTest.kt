// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import com.code_intelligence.jazzer.junit.FuzzTest

/**
 * Spec §9.1 target "JSON and canonical JSON" (#92): the only declared result of a parse is a tree or a
 * [JsonParseException]; anything else is a finding. A tree's canonical JSON is printable ASCII, reads back to the same
 * tree, and canonicalises to the same bytes again (`canonicalise(parse(canonicalise(parse(x)))) ==
 * canonicalise(parse(x))`). The parse stays within spec §6.5's 20·len + 64 KiB ([JsonBudget]): checked in replay,
 * not under Jazzer's instrumentation (see `instrumented`) or where the JVM has no allocation counter. `-max_len=4194305`, `RevoktLimits.MAX_JSON_BYTES` + 1, so the over-cap rejection is
 * reached. With `JAZZER_FUZZ` unset JUnit replays the committed inputs in `JsonFuzzTestInputs/`.
 */
class JsonFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun parseAndCanonicalise(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        init {
            // Spec §6.5's warm-up, so that class loading does not count against the first input's budget.
            JsonBudget.warmUp()
        }

        /**
         * Whether Jazzer is fuzzing, through JUnit (`JAZZER_FUZZ`) or its standalone driver (ClusterFuzzLite, which
         * calls the entry point from `com.code_intelligence.jazzer.driver`). Its data-flow instrumentation allocates
         * inside the parser itself (Jazzer 0.30.0's `TraceDataFlowInstrumentor` builds a `long[]` of case values at every
         * executed switch), so an allocation count there measures the harness; the budget is asserted where the parser
         * runs uninstrumented: the PR-tier replay of the committed inputs and [JsonFuzzHeapTest]'s 4 MiB inputs.
         */
        private val instrumented: Boolean =
            !System.getenv("JAZZER_FUZZ").isNullOrEmpty() ||
                StackWalker.getInstance().walk { frames ->
                    frames.anyMatch { it.className.startsWith("com.code_intelligence.jazzer.driver.") }
                }

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val (tree, bytes) = measuredParse(data)
            if (!instrumented) {
                check(bytes <= JsonBudget.bound(20, data.size)) { "the parse allocated $bytes bytes for ${data.size}" }
            }
            if (tree == null) return
            val once = CanonicalJson.write(tree)
            check(once.all { it in 0x20..0x7E }) { "the canonical JSON is not printable ASCII" }
            // Escapes can triple a string's length, so the read-back is not held to the input cap.
            val again = Json.parse(once, maxBytes = Long.MAX_VALUE)
            check(again == tree) { "the canonical JSON reads back to a different tree" }
            check(CanonicalJson.write(again).contentEquals(once)) { "canonicalisation is not idempotent" }
        }

        private fun measuredParse(data: ByteArray): Pair<JsonValue?, Long> =
            JsonBudget.allocated {
                try {
                    Json.parse(data)
                } catch (_: JsonParseException) {
                    null
                }
            }
    }
}
