// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.RevoktLimits
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import kotlin.random.Random

/**
 * When the loader syncs next (spec §5.1 "Lifecycle", §7.1 "poll at most every 6 h with jitter", #147), as wall-clock
 * times on the builder's clock, the way `backoffUntilMillis` is one (§6.5). Pure: the loader turns a time into a delay
 * once ([delayMillis]) and waits it on its monotonic timer.
 *
 * After a sync that started at `now`:
 * - it wrote no `updater.json` (its read or its write threw, or the store read the start task left unresolved is still
 *   unresolved): `now + 15 min`, the first failure backoff, held in memory only, since nothing persisted says more;
 * - `FAILED`: the source's `backoffUntilMillis` as the sync wrote it (the server's `Backoff`/`Retry-After` when sent,
 *   else 15 min × 2^(n − 1) up to 6 h, #131), exact, with no jitter;
 * - `SKIPPED` with `BACKOFF`: the persisted `backoffUntilMillis` it honoured;
 * - anything else (`INSTALLED`, `UNCHANGED`, `ROLLBACK_REFUSED`): `max(now + POLL_INTERVAL + jitter, backoffUntilMillis)`,
 *   the jitter uniform in `[0, POLL_JITTER)` from [Random], so a `Backoff` shorter than the interval never shortens it.
 *
 * Firefox polls on a 24 h timer and on Push, without jitter, and retries no failure before the next one; upki leaves
 * the schedule to its packager (about every 2 h). Revokt has neither Push nor a packager, hence the interval, the jitter
 * that spreads a fleet started together, and the failure backoff of §7.1.
 */
internal object PollSchedule {
    /** The next sync's time after [run] of [sourceId], which started at [nowMillis]; [random] draws the jitter. */
    fun nextAtMillis(
        run: SyncRun,
        sourceId: String,
        nowMillis: Long,
        random: Random,
    ): Long {
        val record = run.updater ?: return retryAtMillis(nowMillis)
        val backoffUntil = UpdaterTransitions.nextAttemptAtMillis(record, sourceId, nowMillis)
        val result = run.result
        return when {
            result.outcome == SyncOutcome.FAILED -> {
                backoffUntil ?: retryAtMillis(nowMillis)
            }

            result.failure == SyncFailure.BACKOFF -> {
                backoffUntil ?: nowMillis
            }

            else -> {
                val interval = saturatingAdd(nowMillis, RevoktLimits.POLL_INTERVAL + jitterMillis(random))
                maxOf(interval, backoffUntil ?: Long.MIN_VALUE)
            }
        }
    }

    /** The wait for a sync that ran nothing (no record to read a backoff from): the first failure backoff, 15 min. */
    fun retryAtMillis(nowMillis: Long): Long = saturatingAdd(nowMillis, UpdaterTransitions.FIRST_FAILURE_BACKOFF_MILLIS)

    /** The jitter: uniform in `[0, POLL_JITTER)`. */
    fun jitterMillis(random: Random): Long = random.nextLong(RevoktLimits.POLL_JITTER)

    /**
     * The delay from [nowMillis] to [atMillis], clamped to `[MIN_POLL_DELAY, MAX_BACKOFF]` (60 s to 24 h): a time
     * already past, or a `Retry-After: 0`, waits 60 s rather than re-polling at once (Firefox's floor between two timer
     * fires is 120 s), and nothing waits longer than the 24 h every honoured backoff is capped at.
     */
    fun delayMillis(
        atMillis: Long,
        nowMillis: Long,
    ): Long {
        if (atMillis <= nowMillis) return RevoktLimits.MIN_POLL_DELAY
        // atMillis > nowMillis, so only a negative now can overflow the difference, upwards.
        val delay = if (nowMillis < 0 && atMillis > Long.MAX_VALUE + nowMillis) Long.MAX_VALUE else atMillis - nowMillis
        return delay.coerceIn(RevoktLimits.MIN_POLL_DELAY, RevoktLimits.MAX_BACKOFF)
    }
}
