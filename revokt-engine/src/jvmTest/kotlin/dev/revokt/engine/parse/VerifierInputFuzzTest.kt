// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.verify.JcaSignatureVerifier
import java.security.AlgorithmParameters
import java.security.KeyPairGenerator
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/**
 * Spec §9.1 target "`AlgorithmIdentifier`/PSS parameters": the verifier's readers ([VerifierInput]) answer a value or
 * null for any input, never throw, and answer the same twice. Where the PSS reader accepts parameters with SHA-1 or
 * SHA-2 hashes and trailer field 1, the JDK's own `RSASSA-PSS` `AlgorithmParameters` decode them to the same values
 * (the reader is never more lenient than the JDK); and [JcaSignatureVerifier] over the JDK providers answers for them
 * as signature parameters without throwing. With `JAZZER_FUZZ` unset JUnit replays `VerifierInputFuzzTestInputs/`; the
 * nightly job runs it with `-max_len=4097`.
 */
class VerifierInputFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private val verifier = JcaSignatureVerifier()
        private val rsa =
            KeyPairGenerator
                .getInstance(
                    "RSA",
                ).apply { initialize(2048) }
                .generateKeyPair()
                .public.encoded
        private val pssOid = TestDer.oid("1.2.840.113549.1.1.10")

        private val HASHES =
            mapOf(
                VerifierInput.SHA1 to "SHA-1",
                "2.16.840.1.101.3.4.2.4" to "SHA-224",
                "2.16.840.1.101.3.4.2.1" to "SHA-256",
                "2.16.840.1.101.3.4.2.2" to "SHA-384",
                "2.16.840.1.101.3.4.2.3" to "SHA-512",
                "2.16.840.1.101.3.4.2.5" to "SHA-512/224",
                "2.16.840.1.101.3.4.2.6" to "SHA-512/256",
            )

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val algorithm = VerifierInput.algorithm(data)
            check(same(algorithm, VerifierInput.algorithm(data))) { "algorithm differs on a second read" }
            check(
                same(VerifierInput.spkiAlgorithm(data), VerifierInput.spkiAlgorithm(data)),
            ) { "SPKI differs on a second read" }
            val pss = VerifierInput.pss(data)
            check(pss == VerifierInput.pss(data)) { "PSS parameters differ on a second read" }
            if (pss != null) {
                check(pss.saltLength >= 0 && pss.trailerField >= 0) { "negative PSS integer" }
                val hash = HASHES[pss.hashOid]
                val mgfHash = HASHES[pss.mgfHashOid]
                if (hash != null && mgfHash != null && pss.trailerField == 1) {
                    val jdk =
                        AlgorithmParameters
                            .getInstance("RSASSA-PSS")
                            .apply {
                                init(data)
                            }.getParameterSpec(PSSParameterSpec::class.java)
                    check(jdk.digestAlgorithm == hash) { "JDK hash ${jdk.digestAlgorithm}, reader $hash" }
                    check(
                        (jdk.mgfParameters as MGF1ParameterSpec).digestAlgorithm == mgfHash,
                    ) { "JDK MGF1 hash differs" }
                    check(jdk.saltLength == pss.saltLength) { "JDK salt ${jdk.saltLength}, reader ${pss.saltLength}" }
                }
            }
            // As the TBS signature parameters of a PSS link: an answer, never a throw.
            verifier.verify(TestDer.seq(pssOid, data), rsa, data, data)
        }

        private fun same(
            a: AlgorithmId?,
            b: AlgorithmId?,
        ): Boolean =
            if (a == null || b == null) {
                a == b
            } else {
                a.oid == b.oid && a.parametersOid == b.parametersOid &&
                    (a.parameters ?: ByteArray(0)).contentEquals(b.parameters ?: ByteArray(0))
            }
    }
}
