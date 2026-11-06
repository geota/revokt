// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits
import java.util.Base64

/**
 * Spec §9.1 target "seed archive and x5u PEM", the PEM half (#106): the reader returns only `Certificates` or `Failed`;
 * `OVERSIZE` exactly when the body is over the cap; under the cap it reads exactly what [reference], an independent
 * model of the grammar on the JDK's `Base64` (canonical when re-encoding gives the text back), reads. The input is also
 * read as one DER, whose canonical encoding must read back to it. With `JAZZER_FUZZ` unset JUnit replays
 * `X5uPemFuzzTestInputs/`; the nightly job runs it with `-max_len=65537`, `MAX_X5U_BYTES` + 1, so the cap is reached.
 */
class X5uPemFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private const val BEGIN = "-----BEGIN CERTIFICATE-----"
        private const val END = "-----END CERTIFICATE-----"

        /** HT, LF, VT, FF, CR and space. */
        private val WHITESPACE = setOf(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20)

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
                    check(first.ders.all { it.isNotEmpty() }) { "an empty block was read" }
                    val expected = reference(data)
                    check(expected != null && same(first.ders, expected)) { "the reference reads otherwise" }
                }

                is X5uPemRead.Failed -> {
                    check(
                        second is X5uPemRead.Failed && second.reason == first.reason && second.detail == first.detail,
                    ) {
                        "a second read differs"
                    }
                    val over = data.size > RevoktLimits.MAX_X5U_BYTES
                    check((first.reason == X5uPemFailure.OVERSIZE) == over) { "${first.reason} for ${data.size} bytes" }
                    check(
                        over || reference(data) == null,
                    ) { "the reference reads a body that failed with ${first.reason}" }
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

        /** The grammar of [X5uPem] written independently: the blocks' DER, or null where the body fails. */
        private fun reference(data: ByteArray): List<ByteArray>? {
            val lines = String(data, Charsets.ISO_8859_1).split('\n', '\r')
            val out = ArrayList<ByteArray>()
            var block: StringBuilder? = null
            for (line in lines) {
                val open = block
                if (open == null) {
                    if (line.startsWith(BEGIN) &&
                        line.substring(BEGIN.length).all { it == ' ' }
                    ) {
                        block = StringBuilder()
                    }
                } else if (!line.startsWith(END)) {
                    open.append(line.filterNot { it.code in WHITESPACE })
                } else {
                    out += canonical(open.toString()) ?: return null
                    block = null
                }
            }
            return if (block != null || out.isEmpty()) null else out
        }

        /** [text] decoded when it is non-empty, canonical base64, else null. */
        private fun canonical(text: String): ByteArray? {
            if (text.isEmpty()) return null
            val der =
                try {
                    Base64.getDecoder().decode(text)
                } catch (_: IllegalArgumentException) {
                    return null
                }
            return der.takeIf { Base64.getEncoder().encodeToString(it) == text }
        }

        private fun same(
            a: List<ByteArray>,
            b: List<ByteArray>,
        ): Boolean = a.size == b.size && a.indices.all { a[it].contentEquals(b[it]) }
    }
}
