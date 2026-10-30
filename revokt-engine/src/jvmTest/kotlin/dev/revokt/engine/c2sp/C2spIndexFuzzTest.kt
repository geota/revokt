// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.c2sp

import com.code_intelligence.jazzer.junit.FuzzTest
import okio.ByteString.Companion.toByteString

/**
 * Spec §9.1 target "`index.bin` round trip" (#86): the only declared result of a read is an [IndexFile] or an
 * [IndexFormatException]; anything else is a finding. An index that reads is written back and read again to the same
 * tables, and its own selection runs over every log it names. With `JAZZER_FUZZ` unset JUnit replays the committed inputs
 * in `C2spIndexFuzzTestInputs/`.
 */
class C2spIndexFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun readAndRoundTrip(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val index =
                try {
                    C2spIndex.read(data)
                } catch (_: IndexFormatException) {
                    return
                }
            val again = C2spIndex.read(C2spIndex.write(index))
            check(again == index) { "the index did not survive a write and a read" }
            for ((log, entries) in index.logs) {
                for (e in entries) C2spIndex.covering(index, listOf(log to e.window.low, log to e.window.high))
            }
            C2spIndex.covering(index, listOf(ByteArray(32).toByteString() to 0uL))
        }
    }
}
