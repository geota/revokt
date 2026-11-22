// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.RevoktLimits
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRead
import dev.revokt.engine.store.UpdaterRecord

/**
 * An `updater.json` as the loader reads it: its [record], and the store failures reading it cost (spec §6.5,
 * `storeFailures`, #178): a malformed file is one and reads as an empty record; each dropped source entry and a
 * `sources` member that is not an object are one each. The watermark an empty record loses is floored at the live
 * generation's timestamp by [SyncRules].
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
 * - every outcome sets `datasetLastAttemptAtMillis` and the source's `lastAttemptAtMillis` to now ("written at the end
 *   of every sync whatever its outcome");
 * - `INSTALLED` advances the cursor (`lastVerifiedLastModified`) to `<ts>` and `lastVerifiedAtMillis`, after the
 *   pointer flip, in the same write as the install. The watermark is raised to the higher of it and `<ts>`, except
 *   for an install made with no generation loaded (§7.1), which sets it to `<ts>`: an older changeset installed then
 *   moves the watermark and the cursor back with the generation, as Firefox's local timestamp becomes the imported
 *   data's;
 * - `UNCHANGED` and `INSTALLED` end a run of failures (`consecutiveFailures = 0`);
 * - `FAILED`, whatever its [SyncFailure], is a feed failure: `consecutiveFailures + 1`, leaving the cursor,
 *   `lastVerified*` and the watermark untouched;
 * - `SKIPPED` is not: `ROLLBACK_REFUSED` (§7.1) keeps `consecutiveFailures` and `lastVerified*`, and `BACKOFF`
 *   fetched nothing: the attempt fields only.
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
     * [record] after a sync of [sourceId] that ended at [nowMillis] with [failure] (`SKIPPED` or `FAILED`), or, when
     * [failure] is null, `INSTALLED` when [signedTimestampMillis] is given and `UNCHANGED` otherwise. For `INSTALLED`,
     * [signedTimestampMillis] is the installed changeset's `<ts>`, and [noneLoaded] whether it installed with no
     * generation loaded (§7.1): the watermark is then set to `<ts>`, lowered if it was higher, as Firefox's local
     * timestamp becomes the imported data's; otherwise it is raised to the higher of the two. [serverBackoffMillis] is
     * the longest `Backoff` or `Retry-After` of the sync's responses (`ClientResult.backoffMillis`), null when none.
     */
    fun after(
        record: UpdaterRecord,
        sourceId: String,
        failure: SyncFailure?,
        nowMillis: Long,
        signedTimestampMillis: Long? = null,
        serverBackoffMillis: Long? = null,
        noneLoaded: Boolean = false,
    ): UpdaterRecord {
        require(failure == null || signedTimestampMillis == null) { "a stopped sync ($failure) installs nothing" }
        require(!noneLoaded || signedTimestampMillis != null) { "noneLoaded is an install's" }
        require(serverBackoffMillis == null || serverBackoffMillis >= 0) { "a server backoff is negative" }
        val outcome =
            failure?.outcome ?: if (signedTimestampMillis != null) SyncOutcome.INSTALLED else SyncOutcome.UNCHANGED
        val attempted = (record.sources[sourceId] ?: SourceRecord()).copy(lastAttemptAtMillis = nowMillis)
        val source = source(attempted, outcome, failure, nowMillis, serverBackoffMillis)
        if (signedTimestampMillis == null) {
            return record.copy(datasetLastAttemptAtMillis = nowMillis, sources = record.sources + (sourceId to source))
        }
        val verified = source.copy(lastVerifiedAtMillis = nowMillis)
        val raised = maxOf(record.watermarkMillis ?: Long.MIN_VALUE, signedTimestampMillis)
        val watermark = if (noneLoaded) signedTimestampMillis else raised
        return record.copy(
            watermarkMillis = watermark,
            datasetLastAttemptAtMillis = nowMillis,
            sources = record.sources + (sourceId to verified.copy(lastVerifiedLastModified = signedTimestampMillis)),
        )
    }

    /**
     * [attempted] after [outcome] and [failure]: its failure count and backoff; an install's `lastVerified*` are
     * [after]'s.
     */
    private fun source(
        attempted: SourceRecord,
        outcome: SyncOutcome,
        failure: SyncFailure?,
        nowMillis: Long,
        serverBackoffMillis: Long?,
    ): SourceRecord =
        when (outcome) {
            SyncOutcome.INSTALLED, SyncOutcome.UNCHANGED -> {
                attempted.copy(
                    consecutiveFailures = 0,
                    backoffUntilMillis = backoffUntil(nowMillis, serverBackoffMillis, null),
                )
            }

            SyncOutcome.FAILED -> {
                val failures = attempted.consecutiveFailures.let { if (it == Int.MAX_VALUE) it else it + 1 }
                val computed = failureBackoffMillis(failures)
                attempted.copy(
                    consecutiveFailures = failures,
                    backoffUntilMillis = backoffUntil(nowMillis, serverBackoffMillis, computed),
                )
            }

            // BACKOFF fetched nothing; ROLLBACK_REFUSED polled, so a server wait applies, and is not a failure (§7.1).
            SyncOutcome.SKIPPED -> {
                if (failure == SyncFailure.BACKOFF) {
                    attempted
                } else {
                    attempted.copy(backoffUntilMillis = backoffUntil(nowMillis, serverBackoffMillis, null))
                }
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
     * neither, so a source refused on every poll for longer than `signedSourceFailingAfter` is failing (§7.1). Internal
     * in 0.2; `RevoktState` is 0.3.
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
