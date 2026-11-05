// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits

/**
 * Spec §9.1 target "seed archive and x5u PEM", the PEM half (#106): the reader returns only `Certificates` or `Failed`;
 * `OVERSIZE` exactly when the body is over the cap; and a body it reads is the canonical encoding of what it read once
 * CRLF is taken as LF and a final line ending added, so the strict form has one spelling per line ending. The input is
 * also read as one DER, whose canonical encoding must read back to it. With `JAZZER_FUZZ` unset JUnit replays
 * `X5uPemFuzzTestInputs/`; the nightly job runs it with `-max_len=65537`, `MAX_X5U_BYTES` + 1, so the cap is reached.
 */
class X5uPemFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val first = X5uPem.read(data)
            val second = X5uPem.read(data)
            when (first) {
                is X5uPemRead.Certificates -> {
                    check(
                        second is X5uPemRead.Certificates && same(first.ders, second.ders),
                    ) { "a second read differs" }
                    check(first.ders.isNotEmpty() && first.ders.all { it.isNotEmpty() }) { "an empty read" }
                    check(
                        X5uPemFixtures.pem(*first.ders.toTypedArray()) == normalised(data),
                    ) { "a non-canonical body was read" }
                }

                is X5uPemRead.Failed -> {
                    check(
                        second is X5uPemRead.Failed && second.reason == first.reason && second.detail == first.detail,
                    ) {
                        "a second read differs"
                    }
                    check((first.reason == X5uPemFailure.OVERSIZE) == (data.size > RevoktLimits.MAX_X5U_BYTES)) {
                        "${first.reason} for ${data.size} bytes"
                    }
                }
            }
            if (data.isNotEmpty()) {
                val pem = X5uPemFixtures.pem(data).encodeToByteArray()
                if (pem.size <= RevoktLimits.MAX_X5U_BYTES) {
                    val back = X5uPem.read(pem)
                    check(
                        back is X5uPemRead.Certificates && same(back.ders, listOf(data)),
                    ) { "the canonical encoding did not read back" }
                }
            }
        }

        /** [data] with each CRLF taken as LF and a final LF added where it has none. */
        private fun normalised(data: ByteArray): String {
            val text = String(data, Charsets.US_ASCII).replace("\r\n", "\n")
            return if (text.endsWith("\n")) text else "$text\n"
        }

        private fun same(
            a: List<ByteArray>,
            b: List<ByteArray>,
        ): Boolean = a.size == b.size && a.indices.all { a[it].contentEquals(b[it]) }
    }
}
