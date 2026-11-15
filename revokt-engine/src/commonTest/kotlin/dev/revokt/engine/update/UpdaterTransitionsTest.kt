// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.RevoktLimits
import dev.revokt.SyncOutcome
import dev.revokt.engine.fetch.Backoff
import dev.revokt.engine.fetch.response
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterJson
import dev.revokt.engine.store.UpdaterRead
import dev.revokt.engine.store.UpdaterRecord
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The `updater.json` transitions of spec §6.5 and §7.1 (#131): the attempt fields, the cursor, `lastVerified*` and the
 * watermark, `consecutiveFailures`, the clamped backoff, and the internal `signedSourceFailing`.
 */
class UpdaterTransitionsTest {
    private val now = 1_800_000_000_000
    private val minute = 60_000L
    private val hour = 60 * minute
    private val day = 24 * hour

    private val verified =
        SourceRecord(
            lastVerifiedLastModified = now - 2 * hour,
            lastVerifiedAtMillis = now - hour,
            lastAttemptAtMillis = now - hour,
            consecutiveFailures = 2,
        )
    private val other = SourceRecord(lastVerifiedAtMillis = 7, consecutiveFailures = 1)
    private val record =
        UpdaterRecord(
            watermarkMillis = now - 2 * hour,
            seedInstalledAtMillis = now - 9 * day,
            datasetLastAttemptAtMillis = now - hour,
            sources = mapOf(RS to verified, "mirror" to other),
        )

    private fun after(
        outcome: SyncOutcome,
        ts: Long? = null,
        clockBehind: Boolean = false,
        server: Long? = null,
        from: UpdaterRecord = record,
        at: Long = now,
    ) = UpdaterTransitions.after(from, RS, outcome, at, ts, clockBehind, server)

    private fun UpdaterRecord.rs(): SourceRecord = sources.getValue(RS)

    @Test
    fun `every outcome but STORE_LOCKED sets both attempt fields and leaves the other sources and the seed field`() {
        val cases =
            listOf(
                after(SyncOutcome.INSTALLED, ts = now - hour),
                after(SyncOutcome.INSTALLED, ts = now + 2 * day, clockBehind = true),
                after(SyncOutcome.UNCHANGED),
                after(SyncOutcome.FAILED),
                after(SyncOutcome.CLOCK_SKEW),
                after(SyncOutcome.STORE_FAILED),
                after(SyncOutcome.ROLLBACK_REFUSED),
                after(SyncOutcome.DEFERRED),
                after(SyncOutcome.BACKOFF),
            )
        for (r in cases) {
            assertEquals(now, r.datasetLastAttemptAtMillis)
            assertEquals(now, r.rs().lastAttemptAtMillis)
            assertEquals(other, r.sources.getValue("mirror"))
            assertEquals(record.seedInstalledAtMillis, r.seedInstalledAtMillis)
        }
        assertSame(record, after(SyncOutcome.STORE_LOCKED))
        // A source with no entry yet gets one.
        val fresh = UpdaterTransitions.after(UpdaterRecord(), RS, SyncOutcome.FAILED, now)
        assertEquals(
            SourceRecord(lastAttemptAtMillis = now, backoffUntilMillis = now + 15 * minute, consecutiveFailures = 1),
            fresh.rs(),
        )
        assertEquals(now, fresh.datasetLastAttemptAtMillis)
    }

    @Test
    fun `INSTALLED advances the cursor, lastVerifiedAtMillis and the watermark, and ends the failure run`() {
        val ts = now - hour
        val r = after(SyncOutcome.INSTALLED, ts = ts)
        assertEquals(ts, r.watermarkMillis)
        assertEquals(ts, r.rs().lastVerifiedLastModified)
        assertEquals(now, r.rs().lastVerifiedAtMillis)
        assertEquals(0, r.rs().consecutiveFailures)
        assertNull(r.rs().backoffUntilMillis)
        // The watermark is a high-water mark: an install inside the window keeps it, and the cursor follows the install.
        val inWindow = after(SyncOutcome.INSTALLED, ts = now - 3 * hour)
        assertEquals(record.watermarkMillis, inWindow.watermarkMillis)
        assertEquals(now - 3 * hour, inWindow.rs().lastVerifiedLastModified)
        assertEquals(record.watermarkMillis, after(SyncOutcome.INSTALLED, ts = now - 2 * hour).watermarkMillis)
        assertEquals(now - 2 * hour + 1, after(SyncOutcome.INSTALLED, ts = now - 2 * hour + 1).watermarkMillis)
        // The first install of a dataset sets it.
        val first = after(SyncOutcome.INSTALLED, ts = Long.MIN_VALUE, from = record.copy(watermarkMillis = null))
        assertEquals(Long.MIN_VALUE, first.watermarkMillis)
    }

    @Test
    fun `the clock-behind install advances lastVerifiedAtMillis only, never the watermark or the cursor`() {
        val r = after(SyncOutcome.INSTALLED, ts = now + 2 * day, clockBehind = true)
        assertEquals(record.watermarkMillis, r.watermarkMillis)
        assertEquals(verified.lastVerifiedLastModified, r.rs().lastVerifiedLastModified)
        assertEquals(now, r.rs().lastVerifiedAtMillis)
        assertEquals(0, r.rs().consecutiveFailures)
        assertFalse(UpdaterTransitions.signedSourceFailing(r, RS, now, day))
    }

    @Test
    fun `UNCHANGED updates the attempt fields and ends the failure run, nothing else`() {
        val r = after(SyncOutcome.UNCHANGED)
        assertEquals(record.watermarkMillis, r.watermarkMillis)
        assertEquals(verified.copy(lastAttemptAtMillis = now, consecutiveFailures = 0), r.rs())
    }

    @Test
    fun `FAILED, CLOCK_SKEW and STORE_FAILED count a failure and wait the computed backoff, advancing nothing`() {
        for (outcome in listOf(SyncOutcome.FAILED, SyncOutcome.CLOCK_SKEW, SyncOutcome.STORE_FAILED)) {
            val r = after(outcome)
            assertEquals(record.watermarkMillis, r.watermarkMillis, "$outcome")
            assertEquals(verified.lastVerifiedLastModified, r.rs().lastVerifiedLastModified, "$outcome")
            assertEquals(verified.lastVerifiedAtMillis, r.rs().lastVerifiedAtMillis, "$outcome")
            assertEquals(3, r.rs().consecutiveFailures, "$outcome")
            assertEquals(now + 60 * minute, r.rs().backoffUntilMillis, "$outcome")
        }
        // The count saturates.
        val most = record.copy(sources = mapOf(RS to verified.copy(consecutiveFailures = Int.MAX_VALUE)))
        val r = after(SyncOutcome.FAILED, from = most)
        assertEquals(Int.MAX_VALUE, r.rs().consecutiveFailures)
        assertEquals(now + UpdaterTransitions.POLL_INTERVAL_MILLIS, r.rs().backoffUntilMillis)
    }

    @Test
    fun `ROLLBACK_REFUSED is not a feed failure and DEFERRED leaves the count too`() {
        for (outcome in listOf(SyncOutcome.ROLLBACK_REFUSED, SyncOutcome.DEFERRED)) {
            val r = after(outcome)
            assertEquals(verified.copy(lastAttemptAtMillis = now), r.rs(), "$outcome")
            assertEquals(record.watermarkMillis, r.watermarkMillis, "$outcome")
        }
    }

    @Test
    fun `data-path (a) a refused rollback leaves consecutiveFailures and lastVerified unchanged`() {
        val refused = after(SyncOutcome.ROLLBACK_REFUSED)
        assertEquals(verified.consecutiveFailures, refused.rs().consecutiveFailures)
        assertEquals(verified.lastVerifiedAtMillis, refused.rs().lastVerifiedAtMillis)
        assertEquals(verified.lastVerifiedLastModified, refused.rs().lastVerifiedLastModified)
        assertEquals(record.watermarkMillis, refused.watermarkMillis)
    }

    @Test
    fun `BACKOFF fetched nothing and keeps the backoff and the count`() {
        val waiting = record.copy(sources = mapOf(RS to verified.copy(backoffUntilMillis = now + hour)))
        val r = after(SyncOutcome.BACKOFF, server = 5, from = waiting)
        assertEquals(verified.copy(backoffUntilMillis = now + hour, lastAttemptAtMillis = now), r.rs())
        assertEquals(record.watermarkMillis, r.watermarkMillis)
    }

    @Test
    fun `data-path (a) Backoff 100000000 gives a next poll within 24 h and backoffUntilMillis at most now + 24 h`() {
        val server = Backoff.read(response(503, headers = arrayOf("Backoff" to "100000000")))
        assertEquals(RevoktLimits.MAX_BACKOFF, server)
        for (outcome in listOf(SyncOutcome.FAILED, SyncOutcome.UNCHANGED, SyncOutcome.ROLLBACK_REFUSED)) {
            val r = after(outcome, server = server)
            val until = assertNotNull(r.rs().backoffUntilMillis)
            assertTrue(until <= now + RevoktLimits.MAX_BACKOFF, "$outcome")
            assertEquals(now + day, until, "$outcome")
            val next = assertNotNull(UpdaterTransitions.nextAttemptAtMillis(r, RS, now))
            assertTrue(next <= now + day, "$outcome")
            // And through updater.json, which clamps on write and on read.
            val back = UpdaterJson.read(UpdaterJson.write(r, now), now)?.record
            assertTrue(assertNotNull(back?.rs()?.backoffUntilMillis) <= now + day, "$outcome")
        }
        // A wait past MAX_BACKOFF is clamped here as well, and the sum saturates.
        assertEquals(now + day, after(SyncOutcome.FAILED, server = Long.MAX_VALUE).rs().backoffUntilMillis)
        val end = after(SyncOutcome.FAILED, server = day, at = Long.MAX_VALUE - 1)
        assertEquals(Long.MAX_VALUE, end.rs().backoffUntilMillis)
    }

    @Test
    fun `a server wait wins over the computed backoff even when shorter, and a success without one clears it`() {
        assertEquals(now + 1_000, after(SyncOutcome.FAILED, server = 1_000).rs().backoffUntilMillis)
        assertEquals(now, after(SyncOutcome.FAILED, server = 0).rs().backoffUntilMillis)
        assertEquals(now + 7_000, after(SyncOutcome.INSTALLED, ts = now, server = 7_000).rs().backoffUntilMillis)
        val waiting = record.copy(sources = mapOf(RS to verified.copy(backoffUntilMillis = now + hour)))
        for (outcome in listOf(SyncOutcome.UNCHANGED, SyncOutcome.ROLLBACK_REFUSED, SyncOutcome.DEFERRED)) {
            assertNull(after(outcome, from = waiting).rs().backoffUntilMillis, "$outcome")
        }
        assertNull(after(SyncOutcome.INSTALLED, ts = now, from = waiting).rs().backoffUntilMillis)
    }

    @Test
    fun `the computed failure backoff doubles from 15 minutes up to the 6 h poll interval`() {
        val expected = listOf(15, 30, 60, 120, 240, 360, 360).map { it * minute }
        assertEquals(expected, (1..7).map(UpdaterTransitions::failureBackoffMillis))
        assertEquals(6 * hour, UpdaterTransitions.failureBackoffMillis(Int.MAX_VALUE))
        assertFailsWith<IllegalArgumentException> { UpdaterTransitions.failureBackoffMillis(0) }
        // Successive failures from no backoff follow the curve.
        var r = UpdaterRecord()
        val waits =
            (1..7).map {
                r = UpdaterTransitions.after(r, RS, SyncOutcome.FAILED, now)
                r.rs().backoffUntilMillis!! - now
            }
        assertEquals(expected, waits)
    }

    @Test
    fun `nextAttemptAtMillis is the backoff, clamped to now + MAX_BACKOFF, or none`() {
        assertNull(UpdaterTransitions.nextAttemptAtMillis(record, RS, now))
        assertNull(UpdaterTransitions.nextAttemptAtMillis(record, "absent", now))
        val far = record.copy(sources = mapOf(RS to verified.copy(backoffUntilMillis = now + 400 * day)))
        assertEquals(now + day, UpdaterTransitions.nextAttemptAtMillis(far, RS, now))
        val near = record.copy(sources = mapOf(RS to verified.copy(backoffUntilMillis = now + day)))
        assertEquals(now + day, UpdaterTransitions.nextAttemptAtMillis(near, RS, now))
        assertEquals(now + day - 1, UpdaterTransitions.nextAttemptAtMillis(near, RS, now - 1))
        assertEquals(now + 400 * day, UpdaterTransitions.nextAttemptAtMillis(far, RS, Long.MAX_VALUE))
    }

    @Test
    fun `signedSourceFailing is 3 failures or more than signedSourceFailingAfter since the last verified data`() {
        val lv = now - day

        fun source(
            failures: Int,
            lastVerified: Long?,
            seed: Long? = null,
        ) = UpdaterRecord(
            seedInstalledAtMillis = seed,
            sources = mapOf(RS to SourceRecord(lastVerifiedAtMillis = lastVerified, consecutiveFailures = failures)),
        )
        assertFalse(UpdaterTransitions.signedSourceFailing(source(2, now), RS, now, day))
        assertTrue(UpdaterTransitions.signedSourceFailing(source(3, now), RS, now, day))
        assertFalse(UpdaterTransitions.signedSourceFailing(source(0, lv), RS, now, day))
        assertTrue(UpdaterTransitions.signedSourceFailing(source(0, lv - 1), RS, now, day))
        // No verified changeset from this source: measured from the seed's install, else not failing by time.
        assertFalse(UpdaterTransitions.signedSourceFailing(source(0, null, seed = lv), RS, now, day))
        assertTrue(UpdaterTransitions.signedSourceFailing(source(0, null, seed = lv - 1), RS, now, day))
        assertFalse(UpdaterTransitions.signedSourceFailing(source(0, null), RS, now, day))
        assertFalse(UpdaterTransitions.signedSourceFailing(UpdaterRecord(), RS, now, day))
        assertTrue(UpdaterTransitions.signedSourceFailing(UpdaterRecord(seedInstalledAtMillis = lv - 1), RS, now, day))
        // The sum saturates rather than wrapping into the past.
        assertFalse(UpdaterTransitions.signedSourceFailing(source(0, 1), RS, Long.MAX_VALUE, Long.MAX_VALUE))
        assertTrue(UpdaterTransitions.signedSourceFailing(source(0, now), RS, now + 1, 0))
        assertFailsWith<IllegalArgumentException> { UpdaterTransitions.signedSourceFailing(record, RS, now, -1) }
    }

    @Test
    fun `ROLLBACK_REFUSED on every poll for longer than signedSourceFailingAfter sets signedSourceFailing`() {
        val start = now
        var r =
            UpdaterTransitions.after(UpdaterRecord(watermarkMillis = start), RS, SyncOutcome.INSTALLED, start, start)
        // Refused every 6 h: never a feed failure, so only the time since the last verified changeset can fire.
        var t = start
        while (t + 6 * hour <= start + day) {
            t += 6 * hour
            r = UpdaterTransitions.after(r, RS, SyncOutcome.ROLLBACK_REFUSED, t)
            assertEquals(0, r.rs().consecutiveFailures)
            assertFalse(UpdaterTransitions.signedSourceFailing(r, RS, t, day), "at +${(t - start) / hour} h")
        }
        r = UpdaterTransitions.after(r, RS, SyncOutcome.ROLLBACK_REFUSED, start + day + 1)
        assertTrue(UpdaterTransitions.signedSourceFailing(r, RS, start + day + 1, day))
    }

    @Test
    fun `the inputs are checked`() {
        assertFailsWith<IllegalArgumentException> { after(SyncOutcome.INSTALLED) }
        assertFailsWith<IllegalArgumentException> { after(SyncOutcome.UNCHANGED, ts = now) }
        assertFailsWith<IllegalArgumentException> { after(SyncOutcome.FAILED, clockBehind = true) }
        assertFailsWith<IllegalArgumentException> { after(SyncOutcome.FAILED, server = -1) }
        assertFailsWith<IllegalArgumentException> { after(SyncOutcome.BLOCKED_BY_SELF) }
    }

    @Test
    fun `a malformed updater json, a dropped source and a malformed sources member each count a store failure`() {
        assertEquals(0, LoadedUpdater.of(StoreRead.Absent).storeFailures)
        assertEquals(UpdaterRecord(), LoadedUpdater.of(StoreRead.Absent).record)
        assertEquals(1, LoadedUpdater.of(StoreRead.Malformed).storeFailures)
        assertEquals(UpdaterRecord(), LoadedUpdater.of(StoreRead.Malformed).record)
        val found = LoadedUpdater.of(StoreRead.Found(UpdaterRead(record, setOf("a", "b"), sourcesMalformed = false)))
        assertEquals(record, found.record)
        assertEquals(2, found.storeFailures)
        assertEquals(1, LoadedUpdater.of(StoreRead.Found(UpdaterRead(record, sourcesMalformed = true))).storeFailures)
        assertEquals(0, LoadedUpdater.of(StoreRead.Found(UpdaterRead(record))).storeFailures)
    }

    private companion object {
        const val RS = "remote-settings"
    }
}
