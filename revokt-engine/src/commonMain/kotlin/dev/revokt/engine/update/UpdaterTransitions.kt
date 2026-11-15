// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.RevoktLimits
import dev.revokt.SyncOutcome
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRead
import dev.revokt.engine.store.UpdaterRecord

/**
 * An `updater.json` as the loader reads it: its [record], and the store failures reading it cost (spec §6.5,
 * `storeFailures`, #178): a malformed file is one and reads as an empty record; each dropped source entry and a
 * `sources` member that is not an object are one each. The watermark an empty record loses is floored at the live
 * `SIGNED` generation's timestamp by [SyncRules] (revision 56, #188).
 */
internal class LoadedUpdater(
    val record: UpdaterRecord,
    val storeFailures: Int,
) {
    override fun toString(): String = "LoadedUpdater($record, storeFailures=$storeFailures)"

    companion object {
        fun of(read: StoreRead<UpdaterRead>): LoadedUpdater =
            when (read) {
                StoreRead.Absent -> LoadedUpdater(UpdaterRecord(), 0)
                StoreRead.Malformed -> LoadedUpdater(UpdaterRecord(), 1)
                is StoreRead.Found -> LoadedUpdater(read.value.record, read.value.storeFailures)
            }
    }
}

/**
 * The `updater.json` transition at the end of one sync of one source (spec §6.5, §7.1), over [UpdaterRecord]:
 * - every outcome but `STORE_LOCKED` sets `datasetLastAttemptAtMillis` and the source's `lastAttemptAtMillis` to now
 *   ("written at the end of every sync whatever its outcome, `STORE_LOCKED` excepted"); `STORE_LOCKED` writes nothing;
 * - `INSTALLED` advances the cursor (`lastVerifiedLastModified`) and `lastVerifiedAtMillis`, and the watermark to the
 *   higher of it and `<ts>`, after the pointer flip; under the §6.3 clock-behind carve-out it advances
 *   `lastVerifiedAtMillis` only. The cursor is set to `<ts>`, not to the higher of the two: it names the installed
 *   generation's verified record set, which the next `_since` changeset is merged with and verified against (§6.5),
 *   so an install inside the rollback window moves it back with the generation, while the watermark stays a
 *   high-water mark;
 * - `UNCHANGED` and `INSTALLED` end a run of failures (`consecutiveFailures = 0`);
 * - `FAILED`, `CLOCK_SKEW` and `STORE_FAILED` are failures: `consecutiveFailures + 1`, leaving the cursor,
 *   `lastVerified*` and the watermark untouched;
 * - `ROLLBACK_REFUSED` is not a feed failure (§7.1): `consecutiveFailures` and `lastVerified*` stay; `DEFERRED` leaves
 *   them too;
 * - `BACKOFF` fetched nothing: the attempt fields only.
 *
 * The backoff (§7.1 "honour `Backoff` and `Retry-After` up to `MAX_BACKOFF`"): every outcome that polled sets
 * `backoffUntilMillis` to now + the server's wait when the response carried one; otherwise a failure waits the computed
 * [failureBackoffMillis] and any other outcome clears it. Every wait is clamped to `MAX_BACKOFF` and the sum
 * saturates; `UpdaterJson` clamps it again on write and on read.
 */
internal object UpdaterTransitions {
    /** §7.1 "poll at most every 6 h": the cap of the computed failure backoff (§5.1 limits, `MAX_BACKOFF`). */
    const val POLL_INTERVAL_MILLIS: Long = 6L * 60 * 60 * 1_000

    /** The first failure's wait; each further consecutive failure doubles it, up to [POLL_INTERVAL_MILLIS]. */
    const val FIRST_FAILURE_BACKOFF_MILLIS: Long = 15L * 60 * 1_000

    /** §7.2 `signedSourceFailing`: this many consecutive failures or more. */
    const val SIGNED_SOURCE_FAILURES: Int = 3

    /**
     * [record] after a sync of [sourceId] that ended as [outcome] at [nowMillis]. For `INSTALLED`,
     * [signedTimestampMillis] is the installed changeset's `<ts>` and [clockBehind] whether it installed under the §6.3
     * carve-out. [serverBackoffMillis] is the longest `Backoff` or `Retry-After` of the sync's responses
     * (`ClientResult.backoffMillis`), null when none.
     */
    fun after(
        record: UpdaterRecord,
        sourceId: String,
        outcome: SyncOutcome,
        nowMillis: Long,
        signedTimestampMillis: Long? = null,
        clockBehind: Boolean = false,
        serverBackoffMillis: Long? = null,
    ): UpdaterRecord {
        require((outcome == SyncOutcome.INSTALLED) == (signedTimestampMillis != null)) {
            "signedTimestampMillis is given exactly for INSTALLED"
        }
        require(!clockBehind || outcome == SyncOutcome.INSTALLED) { "clockBehind is an install's" }
        require(serverBackoffMillis == null || serverBackoffMillis >= 0) { "a server backoff is negative" }
        if (outcome == SyncOutcome.STORE_LOCKED) return record
        val attempted = (record.sources[sourceId] ?: SourceRecord()).copy(lastAttemptAtMillis = nowMillis)
        val source = source(attempted, outcome, nowMillis, serverBackoffMillis)
        if (signedTimestampMillis == null) {
            return record.copy(datasetLastAttemptAtMillis = nowMillis, sources = record.sources + (sourceId to source))
        }
        val verified = source.copy(lastVerifiedAtMillis = nowMillis)
        if (clockBehind) {
            return record.copy(
                datasetLastAttemptAtMillis = nowMillis,
                sources = record.sources + (sourceId to verified),
            )
        }
        return record.copy(
            watermarkMillis = maxOf(record.watermarkMillis ?: Long.MIN_VALUE, signedTimestampMillis),
            datasetLastAttemptAtMillis = nowMillis,
            sources = record.sources + (sourceId to verified.copy(lastVerifiedLastModified = signedTimestampMillis)),
        )
    }

    /** [attempted] after [outcome]: its failure count and backoff; an install's `lastVerified*` are [after]'s. */
    private fun source(
        attempted: SourceRecord,
        outcome: SyncOutcome,
        nowMillis: Long,
        serverBackoffMillis: Long?,
    ): SourceRecord =
        when (outcome) {
            SyncOutcome.BACKOFF -> {
                attempted
            }

            SyncOutcome.INSTALLED, SyncOutcome.UNCHANGED -> {
                attempted.copy(
                    consecutiveFailures = 0,
                    backoffUntilMillis = backoffUntil(nowMillis, serverBackoffMillis, null),
                )
            }

            SyncOutcome.FAILED, SyncOutcome.CLOCK_SKEW, SyncOutcome.STORE_FAILED -> {
                val failures = attempted.consecutiveFailures.let { if (it == Int.MAX_VALUE) it else it + 1 }
                val computed = failureBackoffMillis(failures)
                attempted.copy(
                    consecutiveFailures = failures,
                    backoffUntilMillis = backoffUntil(nowMillis, serverBackoffMillis, computed),
                )
            }

            SyncOutcome.ROLLBACK_REFUSED, SyncOutcome.DEFERRED -> {
                attempted.copy(backoffUntilMillis = backoffUntil(nowMillis, serverBackoffMillis, null))
            }

            SyncOutcome.STORE_LOCKED, SyncOutcome.BLOCKED_BY_SELF -> {
                // STORE_LOCKED returns before this; the BLOCKED_BY_SELF hold (feedHostBlock) is 0.3 (§8, §11).
                throw IllegalArgumentException("no 0.2 transition for $outcome")
            }
        }

    /**
     * The computed failure backoff after [consecutiveFailures] (at least 1) consecutive failures: 15 minutes, doubled
     * per further failure, capped at the 6 h poll interval (§5.1 limits: "computed failure backoff ≤ the 6 h poll
     * interval"; the spec leaves the curve open).
     */
    fun failureBackoffMillis(consecutiveFailures: Int): Long {
        require(consecutiveFailures >= 1) { "no failure to back off from" }
        var wait = FIRST_FAILURE_BACKOFF_MILLIS
        repeat(consecutiveFailures - 1) {
            wait *= 2
            if (wait >= POLL_INTERVAL_MILLIS) return POLL_INTERVAL_MILLIS
        }
        return wait
    }

    /**
     * When [sourceId] may next be polled: its `backoffUntilMillis`, at most [nowMillis] + `MAX_BACKOFF` (§6.5, clamped
     * again on read), or null when it has none and the poll interval alone decides.
     */
    fun nextAttemptAtMillis(
        record: UpdaterRecord,
        sourceId: String,
        nowMillis: Long,
    ): Long? {
        val until = record.sources[sourceId]?.backoffUntilMillis ?: return null
        return minOf(until, saturatingAdd(nowMillis, RevoktLimits.MAX_BACKOFF))
    }

    /**
     * §7.2's `signedSourceFailing` for [sourceId] at [nowMillis]: [SIGNED_SOURCE_FAILURES] consecutive failures or
     * more, or more than [signedSourceFailingAfterMillis] since the last verified changeset (`lastVerifiedAtMillis`,
     * else the seed's install, `seedInstalledAtMillis`, the dataset's last verified data). `ROLLBACK_REFUSED` advances
     * neither, so a source refused on every poll for longer than `signedSourceFailingAfter` is failing (§7.1), and the
     * §6.3 clock-behind install advances `lastVerifiedAtMillis`, so it is not. Internal in 0.2; `RevoktState` is 0.3.
     */
    fun signedSourceFailing(
        record: UpdaterRecord,
        sourceId: String,
        nowMillis: Long,
        signedSourceFailingAfterMillis: Long,
    ): Boolean {
        require(signedSourceFailingAfterMillis >= 0) { "signedSourceFailingAfter is negative" }
        val source = record.sources[sourceId]
        if (source != null && source.consecutiveFailures >= SIGNED_SOURCE_FAILURES) return true
        val since = source?.lastVerifiedAtMillis ?: record.seedInstalledAtMillis ?: return false
        return nowMillis > saturatingAdd(since, signedSourceFailingAfterMillis)
    }

    /** now + the server's wait when there is one, else now + [computed], else none; each wait at most `MAX_BACKOFF`. */
    private fun backoffUntil(
        nowMillis: Long,
        serverBackoffMillis: Long?,
        computed: Long?,
    ): Long? {
        val wait = serverBackoffMillis ?: computed ?: return null
        return saturatingAdd(nowMillis, minOf(wait, RevoktLimits.MAX_BACKOFF))
    }
}
