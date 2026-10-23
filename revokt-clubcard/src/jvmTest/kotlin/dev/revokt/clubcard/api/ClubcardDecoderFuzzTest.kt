// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.port.CrliteKey
import dev.revokt.clubcard.port.IssuerSpkiHash
import dev.revokt.clubcard.port.LogId
import dev.revokt.clubcard.port.LogTimestamp
import dev.revokt.clubcard.port.Timestamp
import okio.ByteString.Companion.toByteString

/**
 * Spec §9.1 target "v3/v4 filter decoders": the only declared result of a decode is a filter or a
 * [ClubcardFormatException]; anything else (an index out of bounds, an arithmetic exception, an out-of-memory from a
 * lying length) is a finding. A decoded filter is then queried once per issuer in its index so the query path runs
 * over whatever structure the decoder accepted. With `JAZZER_FUZZ` unset JUnit replays the committed inputs in
 * `ClubcardDecoderFuzzTestInputs/`; the differential run against `clubcard-crlite` is the nightly job.
 */
@OptIn(RevoktInternalApi::class)
class ClubcardDecoderFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun decodeAndQuery(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private val serial = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8).toByteString()

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val filter =
                try {
                    ClubcardFilters.decode(data)
                } catch (_: ClubcardFormatException) {
                    return
                }
            val covered = filter.universe.logs.map { (log, interval) -> LogTimestamp(log, interval.low) }
            // A v3 block id of any length decodes (as upstream); only a 32-byte one can be an issuer, so only those
            // are queried. The others stay in the index, unreachable, which is what upstream does with them too.
            for (block in filter.index.keys.filter { it.size == 32 }) {
                val key = CrliteKey(IssuerSpkiHash(block), serial)
                filter.contains(key, covered + LogTimestamp(LogId(block), Timestamp(0)))
                filter.contains(key, emptyList())
            }
        }
    }
}
