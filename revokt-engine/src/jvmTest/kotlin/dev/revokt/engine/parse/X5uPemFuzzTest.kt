// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits
import java.util.Base64

/**
 * Spec §9.1 target "seed archive and x5u PEM", the PEM half (#106): the reader returns only `Certificates` or `Failed`;
 * `OVERSIZE` exactly when the body is over the cap; under the cap it reads exactly what [reference] reads, an
 * independent model of `rustls-pki-types` 1.15.1's framing (written on regular expressions) and decoding (the JDK's
 * `Base64` over the text with whitespace removed). The input is also read as one DER, whose canonical encoding must read
 * back to it. With `JAZZER_FUZZ` unset JUnit replays `X5uPemFuzzTestInputs/`; the nightly job runs it with
 * `-max_len=65537`, `MAX_X5U_BYTES` + 1, so the cap is reached.
 */
class X5uPemFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** A BEGIN line: the label, then exactly five dashes with spaces among and after them. */
        private val BEGIN = Regex("^-----BEGIN (.*?)-(?: *-){4} *$")

        /** HT, LF, VT, FF, CR and space. */
        private val WHITESPACE = Regex("[\\t\\n\\x0B\\f\\r ]")

        private val KNOWN =
            setOf(
                "CERTIFICATE",
                "PUBLIC KEY",
                "RSA PRIVATE KEY",
                "PRIVATE KEY",
                "EC PRIVATE KEY",
                "X509 CRL",
                "CERTIFICATE REQUEST",
                "ECHCONFIG",
            )

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

        /** The blocks' DER as `rustls-pki-types` reads them, or null where it reports an error or finds no certificate. */
        private fun reference(data: ByteArray): List<ByteArray>? {
            val out = ArrayList<ByteArray>()
            var label: String? = null
            val text = StringBuilder()
            for (line in String(data, Charsets.ISO_8859_1).split('\n', '\r')) {
                val open = label
                when {
                    line.startsWith("-----BEGIN ") -> label = beginLabel(line) ?: return null
                    open == null -> Unit
                    !line.startsWith("-----END $open-----") -> text.append(line)
                    else -> label = if (close(open, text, out)) null else return null
                }
            }
            return if (label != null || out.isEmpty()) null else out
        }

        /** A BEGIN line's label, or null when it is malformed: a label that still ends in a dash had six or more. */
        private fun beginLabel(line: String): String? {
            val label = BEGIN.find(line)?.groupValues?.get(1) ?: return null
            return label.takeUnless { it.trimEnd(' ').endsWith('-') }
        }

        /** Ends the block [label]: decodes a known label's [text], keeps a certificate in [out]; false on an error. */
        private fun close(
            label: String,
            text: StringBuilder,
            out: MutableList<ByteArray>,
        ): Boolean {
            val der = if (label in KNOWN) decoded(text.toString()) ?: return false else null
            if (label == "CERTIFICATE") out += checkNotNull(der)
            text.clear()
            return true
        }

        /** [text] decoded as the JDK decodes base64 once whitespace is removed; null where it rejects the text. */
        private fun decoded(text: String): ByteArray? =
            try {
                Base64.getDecoder().decode(text.replace(WHITESPACE, ""))
            } catch (_: IllegalArgumentException) {
                null
            }

        private fun same(
            a: List<ByteArray>,
            b: List<ByteArray>,
        ): Boolean = a.size == b.size && a.indices.all { a[it].contentEquals(b[it]) }
    }
}
