// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.GenerationFiles
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.clubcard.port.CrliteClubcard
import dev.revokt.clubcard.port.CrliteKey
import dev.revokt.clubcard.port.CrliteStatus
import dev.revokt.clubcard.port.IssuerSpkiHash
import dev.revokt.clubcard.port.LogId
import dev.revokt.clubcard.port.LogTimestamp
import dev.revokt.clubcard.port.Timestamp

/**
 * A decoded CRLite generation (spec §6.2 to §6.4): every filter `index.bin` names, full and deltas alike, each with its
 * own coverage and index. Immutable, so concurrent queries need no locking.
 */
@OptIn(RevoktInternalApi::class)
internal class CrliteGeneration private constructor(
    val generationId: String,
    private val filters: List<CrliteClubcard>,
) {
    /**
     * The latest coverage `high` of any filter, compared unsigned, or null when no filter covers any log. A `high` past
     * [Long.MAX_VALUE] (an open-ended window, up to `u64::MAX`) is clamped to [Long.MAX_VALUE], so the value never reads
     * as a date before 1970.
     */
    val coverageEndMillis: Long? =
        filters
            .flatMap { f ->
                f.universe.logs.values
                    .map { it.high }
            }.maxOrNull()
            ?.value
            ?.let { if (it < 0) Long.MAX_VALUE else it }

    /**
     * The §6.2 aggregate over the filters that cover one of [q]'s SCTs (C2SP step 3): none covering, `NOT_COVERED`; any
     * revoked, `REVOKED`; else any good, `NOT_REVOKED`; else `NOT_ENROLLED`. An empty SCT list is `NO_SCTS` and
     * reaches no filter.
     */
    fun query(q: CrliteQuery): CrliteQueryResult {
        if (q.scts.isEmpty()) return CrliteQueryResult.NO_SCTS
        val key = CrliteKey(IssuerSpkiHash(q.issuerSpkiHashBytes), q.serialByteString)
        val timestamps = q.scts.map { LogTimestamp(LogId(it.logIdBytes), Timestamp(it.timestampMillis)) }
        var covered = false
        var good = false
        for (filter in filters) {
            when (filter.contains(key, timestamps)) {
                CrliteStatus.NOT_COVERED -> continue
                CrliteStatus.REVOKED -> return CrliteQueryResult.REVOKED
                CrliteStatus.GOOD -> good = true
                CrliteStatus.NOT_ENROLLED -> Unit
            }
            covered = true
        }
        return when {
            !covered -> CrliteQueryResult.NOT_COVERED
            good -> CrliteQueryResult.NOT_REVOKED
            else -> CrliteQueryResult.NOT_ENROLLED
        }
    }

    companion object {
        private const val INDEX = "index.bin"

        /**
         * Decodes every filter of [files], each by the encoding its 2-byte prefix names (spec §6.3), whatever the
         * generation's declared format. Throws [IllegalArgumentException] when a filter does not decode under §6.3. The
         * seam carries [dev.revokt.Dataset.CRLITE] only (§3.2), the one dataset today.
         */
        fun decode(files: GenerationFiles): CrliteGeneration {
            val filters =
                files.names.filter { it != INDEX }.sorted().map { name ->
                    try {
                        ClubcardFilters.decode(files.bytes(name))
                    } catch (e: ClubcardFormatException) {
                        throw IllegalArgumentException("filter $name is malformed: ${e.message}", e)
                    }
                }
            return CrliteGeneration(files.generationId, filters)
        }
    }
}
