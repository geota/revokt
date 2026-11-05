// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.verify.JcaFixtures
import dev.revokt.verify.JcaSignatureVerifier
import java.math.BigInteger
import java.util.Base64

/**
 * Spec §9.1 target "DER ECDSA conversion": the content signature's text decoder and raw-to-DER conversion
 * ([RawSignature]) on any input. The input read as Latin-1 text decodes exactly when the JDK's base64url decoder reads
 * it as 96 bytes from 128 unpadded characters, to the same bytes; its first 96 bytes (zero-padded) convert to the DER
 * `BigInteger.toByteArray()` gives, which the JDK's `SHA384withECDSA` takes without throwing; and the whole check over
 * the input as `records.json` answers without throwing and never verifies. With `JAZZER_FUZZ` unset JUnit replays
 * `RawSignatureFuzzTestInputs/`; the nightly job runs it with `-max_len=4097`.
 */
class RawSignatureFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun convert(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private val verifier = JcaSignatureVerifier()
        private val leaf = JcaFixtures.ec("secp384r1").public.encoded
        private val urlAlphabet = Regex("[A-Za-z0-9_-]*")

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val text = String(data, Charsets.ISO_8859_1)
            val decoded = RawSignature.decode(text)
            val jdk =
                if (text.length == RawSignature.TEXT_CHARS && urlAlphabet.matches(text)) {
                    Base64.getUrlDecoder().decode(text)
                } else {
                    null
                }
            check((decoded == null) == (jdk == null)) { "decoder ${decoded != null}, JDK ${jdk != null}" }
            check(decoded == null || decoded.contentEquals(jdk)) { "decoder and JDK disagree" }

            val raw = data.copyOf(RawSignature.RAW_BYTES)
            val der = RawSignature.toDer(raw)
            check(der.contentEquals(expected(raw))) { "toDer differs from BigInteger's minimal INTEGERs" }
            check(der.size in 8..104) { "DER of ${der.size} bytes" }
            check(verifier.verify(ECDSA_WITH_SHA384, leaf, data, der) != dev.revokt.VerifyResult.VERIFIED) {
                "a fuzzed signature verified"
            }

            val result = ContentSignature.verifyRawPayload(verifier, data, text, ContentSignature.MODE, leaf)
            check(!result.verified) { "a fuzzed content signature verified" }
            if (decoded == null) check(result.failure == ContentSignatureFailure.ENCODING) { "$result" }
        }

        private val ECDSA_WITH_SHA384 = JcaFixtures.algId(JcaFixtures.ECDSA_SHA384)

        private fun expected(raw: ByteArray): ByteArray {
            val r = BigInteger(1, raw.copyOfRange(0, 48)).toByteArray()
            val s = BigInteger(1, raw.copyOfRange(48, 96)).toByteArray()
            return byteArrayOf(0x30, (r.size + s.size + 4).toByte(), 0x02, r.size.toByte()) + r +
                byteArrayOf(0x02, s.size.toByte()) + s
        }
    }
}
