// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.RevoktLimits
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.SyncResult
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.UpdaterRecord
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The loader's schedule (spec §5.1, §7.1 "poll at most every 6 h with jitter", #147): when the next sync runs after one
 * ended, and the delay it waits, clamped to 60 s to 24 h. The §9 data-path (a) backoff rows through the loader.
 */
class PollScheduleTest {
    private val now = 1_792_587_631_204
    private val minute = 60_000L
    private val hour = 60 * minute
    private val rs = "remote-settings"

    private fun run(
        failure: SyncFailure?,
        outcome: SyncOutcome = failure?.outcome ?: SyncOutcome.UNCHANGED,
        backoffUntil: Long? = null,
        written: Boolean = true,
    ): SyncRun {
        val result =
            SyncResult
                .Builder()
                .outcome(outcome)
                .atMillis(now)
                .sourceId(rs)
                .failure(failure)
                .build()
        val record = UpdaterRecord(sources = mapOf(rs to SourceRecord(backoffUntilMillis = backoffUntil)))
        return SyncRun(result, 0, if (written) record else null)
    }

    private fun next(
        run: SyncRun,
        random: Random = Random(7),
    ): Long = PollSchedule.nextAtMillis(run, rs, now, random)

    private fun jitter(seed: Int = 7): Long = PollSchedule.jitterMillis(Random(seed))

    @Test
    fun `after a poll that did not fail the next is 6 h plus the jitter, whatever the outcome`() {
        for (r in listOf(
            run(null, SyncOutcome.UNCHANGED),
            run(null, SyncOutcome.INSTALLED),
            run(SyncFailure.ROLLBACK_REFUSED),
        )) {
            assertEquals(now + 6 * hour + jitter(), next(r), "${r.result}")
        }
    }

    @Test
    fun `the jitter only lengthens the wait, uniform below 36 min`() {
        val draws = (0 until 2_000).map { PollSchedule.jitterMillis(Random(it)) }
        assertTrue(draws.all { it in 0 until 36 * minute }, "every draw in [0, 36 min)")
        assertTrue(draws.any { it < 4 * minute } && draws.any { it > 32 * minute }, "the whole range is drawn")
        for (seed in 0 until 200) {
            val at = next(run(null), Random(seed))
            assertTrue(at >= now + 6 * hour && at < now + 6 * hour + 36 * minute, "seed $seed: ${at - now}")
        }
    }

    @Test
    fun `a Backoff on a poll that did not fail waits the longer of it and the interval, up to 24 h`() {
        assertEquals(now + 6 * hour + jitter(), next(run(null, backoffUntil = now + 600_000)), "Backoff: 600")
        assertEquals(now + 24 * hour, next(run(null, backoffUntil = now + 24 * hour)), "Backoff: 100000000, capped")
        // A persisted backoff beyond the cap (a clock far ahead when it was written) is read back clamped.
        assertEquals(now + 24 * hour, next(run(null, backoffUntil = now + 300 * hour)))
    }

    @Test
    fun `a FAILED sync waits its backoff exactly, with no jitter`() {
        for (wait in listOf(minute, 15 * minute, 30 * minute, 6 * hour, 24 * hour)) {
            val failed = run(SyncFailure.CHANGESET_FETCH, backoffUntil = now + wait)
            assertEquals(now + wait, next(failed, Random(1)))
            assertEquals(now + wait, next(failed, Random(2)))
        }
    }

    @Test
    fun `a sync SKIPPED under a backoff waits until the backoff ends`() {
        assertEquals(now + 3 * hour, next(run(SyncFailure.BACKOFF, backoffUntil = now + 3 * hour)))
        // A record whose backoff is gone by then: due at once, which the delay floors at 60 s.
        val due = next(run(SyncFailure.BACKOFF, backoffUntil = null))
        assertEquals(now, due)
        assertEquals(minute, PollSchedule.delayMillis(due, now))
    }

    @Test
    fun `a FAILED sync whose record holds no backoff retries in 15 min, never at once`() {
        assertEquals(now + 15 * minute, next(run(SyncFailure.CHANGESET_FETCH, backoffUntil = null)))
    }

    @Test
    fun `a sync that wrote no updater json retries in 15 min`() {
        for (r in listOf(
            run(SyncFailure.STORE_FAILED, written = false),
            run(null, SyncOutcome.UNCHANGED, written = false),
        )) {
            assertEquals(now + 15 * minute, next(r))
        }
        assertEquals(now + 15 * minute, PollSchedule.retryAtMillis(now))
    }

    @Test
    fun `every delay is between 60 s and 24 h, so a Retry-After of 0 cannot loop the loader`() {
        assertEquals(RevoktLimits.MIN_POLL_DELAY, PollSchedule.delayMillis(now, now), "Retry-After: 0")
        assertEquals(minute, PollSchedule.delayMillis(now - hour, now), "a time already past")
        assertEquals(minute, PollSchedule.delayMillis(now + 1, now))
        assertEquals(minute, PollSchedule.delayMillis(now + minute, now), "Retry-After: 60 waits 60 s")
        assertEquals(15 * minute, PollSchedule.delayMillis(now + 15 * minute, now))
        assertEquals(6 * hour, PollSchedule.delayMillis(now + 6 * hour, now))
        assertEquals(24 * hour, PollSchedule.delayMillis(now + 24 * hour, now))
        assertEquals(24 * hour, PollSchedule.delayMillis(now + 24 * hour + 1, now))
        assertEquals(24 * hour, PollSchedule.delayMillis(Long.MAX_VALUE, -now), "no overflow")
        assertEquals(6 * hour, PollSchedule.delayMillis(6 * hour - minute, -minute), "a negative now, no overflow")
    }
}
