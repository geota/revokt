// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktInternalApi
import dev.revokt.engine.parse.oracle.Oracle1
import dev.revokt.engine.parse.oracle.PlatformOracle

/**
 * Spec §9.1 target for the §9.2 read fallback ([PlatformRead]), which locates the signature AlgorithmIdentifier in TBS
 * bytes from outside. The input is read twice. As a TBS (after a first octet that sets the signature's length), the
 * platform canon never throws and equals oracle 1's independent `platformCanon`. As a certificate the JDK's `SUN`
 * factory accepts, the production read equals oracle 1's view: its platform canon where revokt's parse of
 * `getEncoded()` is `STRUCTURE` and the canon can be built, else `getEncoded()`. With `JAZZER_FUZZ` unset JUnit
 * replays `PlatformReadFuzzTestInputs/` when it exists; the nightly job runs it with `-max_len=262145`,
 * `MAX_CERT_BYTES` + 1, so the cap is reached.
 */
@OptIn(RevoktInternalApi::class)
class PlatformReadFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** The static entry point a standalone Jazzer driver calls (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            if (data.isNotEmpty()) {
                val split = minOf(data[0].toInt() and 0xff, data.size - 1)
                val signature = data.copyOfRange(1, 1 + split)
                val tbs = data.copyOfRange(1 + split, data.size)
                val ours = PlatformRead.canon(tbs, signature)
                val oracle = Oracle1.platformCanon(tbs, signature)?.canon()
                check(ours.contentEqualsOrBothNull(oracle)) { "the platform canon differs from oracle 1's" }
            }
            val x509 = (Oracle1.run(data) as? PlatformOracle.Outcome.Accept)?.certificate ?: return
            val read = checkNotNull(PlatformRead.of(x509)) { "an accepted certificate has no bytes" }
            val expected =
                try {
                    Oracle1.read("fuzz", x509)?.der ?: x509.encoded
                } catch (_: RuntimeException) {
                    // Oracle 1 propagates a getter that throws (unavailable); production keeps getEncoded().
                    x509.encoded
                }
            check(read.read.contentEquals(expected)) { "the production read differs from oracle 1's" }
        }

        private fun ByteArray?.contentEqualsOrBothNull(other: ByteArray?): Boolean =
            if (this == null || other == null) this == null && other == null else contentEquals(other)
    }
}
