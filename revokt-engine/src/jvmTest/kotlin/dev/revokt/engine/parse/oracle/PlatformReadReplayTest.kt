// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.RevoktInternalApi
import dev.revokt.engine.parse.PlatformRead
import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec §9.2 "The read fallback" over the replay corpus on the test JDK (`-Prevokt.testJdk` runs it on each matrix
 * JDK): for every input oracle 1 accepts, the production read ([PlatformRead]) is oracle 1's view, its independent
 * platform canon where revokt's parse of `getEncoded()` is `STRUCTURE` and the canon can be built, else
 * `getEncoded()`. The certificates are not retained (#64).
 */
@OptIn(RevoktInternalApi::class)
class PlatformReadReplayTest {
    @Test
    fun `the production read is oracle 1's on every accepted replay input`() {
        var accepted = 0
        var canon = 0
        for (input in ProducerCorpus.inputs) {
            val x509 = (Oracle1.run(input.der) as? PlatformOracle.Outcome.Accept)?.certificate ?: continue
            accepted++
            val ours = checkNotNull(PlatformRead.of(x509)) { "${input.name}: no bytes" }
            val oracle = Oracle1.read(input.name, x509)
            val expected = oracle?.der ?: x509.encoded
            assertEquals(expected.toByteString(), ours.read.toByteString(), input.name)
            val oracleCanon = oracle?.name?.endsWith(Oracle1.PLATFORM_CANON) == true
            assertEquals(oracleCanon, ours.platformCanon, "${input.name}: read through the platform canon")
            if (ours.platformCanon) canon++
        }
        assertTrue(accepted > 1000, "$accepted accepted inputs")
        assertTrue(canon >= 9, "$canon platform-canon reads (the nine indefinite-TBS inputs at least)")
    }
}
