// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.RevoktLimits
import dev.revokt.SyncFailure
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
        server: Long? = null,
        from: UpdaterRecord = record,
        at: Long = now,
        failure: SyncFailure? = null,
    ): UpdaterRecord {
        // The transition reads the outcome from the failure, else from whether a <ts> was installed.
        assertEquals(outcome, failure?.outcome ?: if (ts != null) SyncOutcome.INSTALLED else SyncOutcome.UNCHANGED)
        return UpdaterTransitions.after(from, RS, failure, at, ts, server)
    }

    /** The transition after a sync that stopped with [failure]. */
    private fun after(
        failure: SyncFailure,
        server: Long? = null,
        from: UpdaterRecord = record,
        at: Long = now,
    ) = after(failure.outcome, null, server, from, at, failure)

    /** A `FAILED` sync's code, for the tests that need one: every `FAILED` code transitions alike. */
    private val failed = SyncFailure.CHANGESET_FETCH

    private fun UpdaterRecord.rs(): SourceRecord = sources.getValue(RS)

    @Test
    fun `every outcome sets both attempt fields and leaves the other sources and the seed field`() {
        val cases =
            listOf(
                after(SyncOutcome.INSTALLED, ts = now - hour),
                after(SyncOutcome.INSTALLED, ts = now + 2 * day),
                after(SyncOutcome.UNCHANGED),
            ) + SyncFailure.entries.map { after(it) }
        for (r in cases) {
            assertEquals(now, r.datasetLastAttemptAtMillis)
            assertEquals(now, r.rs().lastAttemptAtMillis)
            assertEquals(other, r.sources.getValue("mirror"))
            assertEquals(record.seedInstalledAtMillis, r.seedInstalledAtMillis)
        }
        // A source with no entry yet gets one.
        val fresh = UpdaterTransitions.after(UpdaterRecord(), RS, failed, now)
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
        // The watermark is a high-water mark: an older install (no generation loaded, §7.1) keeps it, and the cursor
        // follows the install.
        val older = after(SyncOutcome.INSTALLED, ts = now - 3 * hour)
        assertEquals(record.watermarkMillis, older.watermarkMillis)
        assertEquals(now - 3 * hour, older.rs().lastVerifiedLastModified)
        assertEquals(record.watermarkMillis, after(SyncOutcome.INSTALLED, ts = now - 2 * hour).watermarkMillis)
        assertEquals(now - 2 * hour + 1, after(SyncOutcome.INSTALLED, ts = now - 2 * hour + 1).watermarkMillis)
        // The first install of a dataset sets it.
        val first = after(SyncOutcome.INSTALLED, ts = Long.MIN_VALUE, from = record.copy(watermarkMillis = null))
        assertEquals(Long.MIN_VALUE, first.watermarkMillis)
    }

    @Test
    fun `a far-future install advances the cursor and the watermark like any other`() {
        val r = after(SyncOutcome.INSTALLED, ts = now + 2 * day)
        assertEquals(now + 2 * day, r.watermarkMillis)
        assertEquals(now + 2 * day, r.rs().lastVerifiedLastModified)
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
    fun `every FAILED code counts a failure and waits the computed backoff, advancing nothing`() {
        for (outcome in SyncFailure.entries.filter { it.outcome == SyncOutcome.FAILED }) {
            val r = after(outcome)
            assertEquals(record.watermarkMillis, r.watermarkMillis, "$outcome")
            assertEquals(verified.lastVerifiedLastModified, r.rs().lastVerifiedLastModified, "$outcome")
            assertEquals(verified.lastVerifiedAtMillis, r.rs().lastVerifiedAtMillis, "$outcome")
            assertEquals(3, r.rs().consecutiveFailures, "$outcome")
            assertEquals(now + 60 * minute, r.rs().backoffUntilMillis, "$outcome")
        }
        // The count saturates.
        val most = record.copy(sources = mapOf(RS to verified.copy(consecutiveFailures = Int.MAX_VALUE)))
        val r = after(failed, from = most)
        assertEquals(Int.MAX_VALUE, r.rs().consecutiveFailures)
        assertEquals(now + UpdaterTransitions.POLL_INTERVAL_MILLIS, r.rs().backoffUntilMillis)
    }

    /**
     * Every failure value before #222 (the old `SyncOutcome` values beyond `INSTALLED` and `UNCHANGED`, and the
     * internal `ClientFailure`, `SignatureFailure` and `IndexRefusal` values and the install's failures), with the
     * outcome it gave then and the code it is now. A fetch failure of the exchange itself (throw, timeout, status,
     * oversize body, header) is the code of its fetch: shown here for the changeset, and the same for the x5u
     * (`X5U_FETCH`), an attachment (`ATTACHMENT_FETCH`) and the server root (`ATTACHMENT_BASE`).
     */
    private val before222 =
        listOf(
            Triple("SyncOutcome.BACKOFF", "BACKOFF", SyncFailure.BACKOFF),
            Triple("SyncOutcome.ROLLBACK_REFUSED", "ROLLBACK_REFUSED", SyncFailure.ROLLBACK_REFUSED),
            Triple("SyncOutcome.CLOCK_SKEW", "CLOCK_SKEW", SyncFailure.CLOCK_SKEW),
            Triple("SyncOutcome.STORE_FAILED", "STORE_FAILED", SyncFailure.STORE_FAILED),
            Triple("ClientFailure.HEADER_VALUE", "FAILED", SyncFailure.CHANGESET_FETCH),
            Triple("ClientFailure.QUERY_VALUE", "FAILED", SyncFailure.CHANGESET_FETCH),
            Triple("ClientFailure.FETCHER_THREW", "FAILED", SyncFailure.CHANGESET_FETCH),
            Triple("ClientFailure.TIMEOUT", "FAILED", SyncFailure.CHANGESET_FETCH),
            Triple("ClientFailure.HTTP_STATUS", "FAILED", SyncFailure.CHANGESET_FETCH),
            Triple("ClientFailure.BODY_TOO_LARGE", "FAILED", SyncFailure.CHANGESET_FETCH),
            Triple(
                "ClientFailure.HTTP_STATUS (or another exchange failure) at ATTACHMENT",
                "FAILED",
                SyncFailure.ATTACHMENT_FETCH,
            ),
            Triple("ClientFailure.MALFORMED", "FAILED", SyncFailure.CHANGESET_MALFORMED),
            Triple("ClientFailure.X5U_URL", "FAILED", SyncFailure.X5U_URL),
            Triple("ClientFailure.ATTACHMENT_OVER_CAP", "FAILED", SyncFailure.ATTACHMENT_OVER_CAP),
            Triple("ClientFailure.ATTACHMENT_SIZE", "FAILED", SyncFailure.ATTACHMENT_MISMATCH),
            Triple("ClientFailure.ATTACHMENT_HASH", "FAILED", SyncFailure.ATTACHMENT_MISMATCH),
            Triple("ClientFailure.ATTACHMENT_BASE", "FAILED", SyncFailure.ATTACHMENT_BASE),
            Triple("ClientFailure.SCHEMA", "FAILED", SyncFailure.SCHEMA_REJECTED),
            Triple("ClientFailure.TOO_MANY_RECORDS", "FAILED", SyncFailure.TOO_MANY_RECORDS),
            Triple("SignatureFailure.NO_SIGNATURES", "FAILED", SyncFailure.NO_SIGNATURE),
            Triple("SignatureFailure.NONE_TRIED", "FAILED", SyncFailure.NO_SIGNATURE),
            Triple("SignatureFailure.NULL_ENTRY", "FAILED", SyncFailure.NO_SIGNATURE),
            Triple("SignatureFailure.X5U_FETCH", "FAILED", SyncFailure.X5U_FETCH),
            Triple("SignatureFailure.X5U_PEM", "FAILED", SyncFailure.X5U_CHAIN),
            Triple("SignatureFailure.X5U_CHAIN", "FAILED", SyncFailure.X5U_CHAIN),
            Triple("SignatureFailure.X5U_VALIDITY", "CLOCK_SKEW", SyncFailure.CLOCK_SKEW),
            Triple("SignatureFailure.CONTENT_SIGNATURE", "FAILED", SyncFailure.SIGNATURE_INVALID),
            Triple("IndexRefusal.NAME_COLLISION", "FAILED", SyncFailure.INDEX_INCONSISTENT),
            Triple("IndexRefusal.FULL_COUNT", "FAILED", SyncFailure.INDEX_INCONSISTENT),
            Triple("IndexRefusal.OVER_CAP", "FAILED", SyncFailure.INDEX_INCONSISTENT),
            Triple("IndexRefusal.FILTER_UNREADABLE", "FAILED", SyncFailure.FILTER_UNREADABLE),
            Triple("install: index.bin over the cap", "FAILED", SyncFailure.INDEX_INCONSISTENT),
            Triple("FORMAT_UNSUPPORTED at PREPARE", "FAILED", SyncFailure.FORMAT_UNSUPPORTED),
            Triple("a throw at PREPARE or ACTIVATE", "FAILED", SyncFailure.ENGINE_FAILED),
            Triple("a fatal throw at STORE, any throw at another stage", "FAILED", SyncFailure.INTERNAL_ERROR),
        )

    @Test
    fun `every failure before 222 keeps its outcome class, failure count and backoff under its new code`() {
        // Every code is in the table, so a new code needs its row (and a reading of what it was before, if anything).
        assertEquals(SyncFailure.entries.toSet(), before222.map { it.third }.toSet())
        val waiting = record.copy(sources = mapOf(RS to verified.copy(backoffUntilMillis = now + hour)))
        for ((old, oldOutcome, code) in before222) {
            // SKIPPED is exactly what the Android worker maps to success before and after (§5.2).
            val skippedBefore = oldOutcome == "BACKOFF" || oldOutcome == "ROLLBACK_REFUSED"
            assertEquals(if (skippedBefore) SyncOutcome.SKIPPED else SyncOutcome.FAILED, code.outcome, old)
            val r = after(code, from = waiting).rs()
            // The transitions as UpdaterTransitions wrote them per old outcome.
            val expected =
                when (oldOutcome) {
                    "BACKOFF" -> {
                        verified.copy(backoffUntilMillis = now + hour, lastAttemptAtMillis = now)
                    }

                    "ROLLBACK_REFUSED" -> {
                        verified.copy(lastAttemptAtMillis = now)
                    }

                    else -> {
                        verified.copy(
                            lastAttemptAtMillis = now,
                            consecutiveFailures = verified.consecutiveFailures + 1,
                            backoffUntilMillis = now + UpdaterTransitions.failureBackoffMillis(3),
                        )
                    }
                }
            assertEquals(expected, r, old)
        }
    }

    @Test
    fun `ROLLBACK_REFUSED is not a feed failure`() {
        val r = after(SyncFailure.ROLLBACK_REFUSED)
        assertEquals(verified.copy(lastAttemptAtMillis = now), r.rs())
        assertEquals(record.watermarkMillis, r.watermarkMillis)
    }

    @Test
    fun `data-path (a) a refused rollback leaves consecutiveFailures and lastVerified unchanged`() {
        val refused = after(SyncFailure.ROLLBACK_REFUSED)
        assertEquals(verified.consecutiveFailures, refused.rs().consecutiveFailures)
        assertEquals(verified.lastVerifiedAtMillis, refused.rs().lastVerifiedAtMillis)
        assertEquals(verified.lastVerifiedLastModified, refused.rs().lastVerifiedLastModified)
        assertEquals(record.watermarkMillis, refused.watermarkMillis)
    }

    @Test
    fun `BACKOFF fetched nothing and keeps the backoff and the count`() {
        val waiting = record.copy(sources = mapOf(RS to verified.copy(backoffUntilMillis = now + hour)))
        val r = after(SyncFailure.BACKOFF, server = 5, from = waiting)
        assertEquals(verified.copy(backoffUntilMillis = now + hour, lastAttemptAtMillis = now), r.rs())
        assertEquals(record.watermarkMillis, r.watermarkMillis)
    }

    @Test
    fun `data-path (a) Backoff 100000000 gives a next poll within 24 h and backoffUntilMillis at most now + 24 h`() {
        val server = Backoff.read(response(503, headers = arrayOf("Backoff" to "100000000")))
        assertEquals(RevoktLimits.MAX_BACKOFF, server)
        for ((outcome, failure) in listOf(SyncOutcome.FAILED to failed, SyncOutcome.UNCHANGED to null) +
            (SyncOutcome.SKIPPED to SyncFailure.ROLLBACK_REFUSED)) {
            val r = after(outcome, server = server, failure = failure)
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
        assertEquals(now + day, after(failed, server = Long.MAX_VALUE).rs().backoffUntilMillis)
        val end = after(failed, server = day, at = Long.MAX_VALUE - 1)
        assertEquals(Long.MAX_VALUE, end.rs().backoffUntilMillis)
    }

    @Test
    fun `a server wait wins over the computed backoff even when shorter, and a success without one clears it`() {
        assertEquals(now + 1_000, after(failed, server = 1_000).rs().backoffUntilMillis)
        assertEquals(now, after(failed, server = 0).rs().backoffUntilMillis)
        assertEquals(now + 7_000, after(SyncOutcome.INSTALLED, ts = now, server = 7_000).rs().backoffUntilMillis)
        val waiting = record.copy(sources = mapOf(RS to verified.copy(backoffUntilMillis = now + hour)))
        assertNull(after(SyncOutcome.UNCHANGED, from = waiting).rs().backoffUntilMillis)
        assertNull(after(SyncFailure.ROLLBACK_REFUSED, from = waiting).rs().backoffUntilMillis)
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
                r = UpdaterTransitions.after(r, RS, failed, now)
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
            UpdaterTransitions.after(UpdaterRecord(watermarkMillis = start), RS, null, start, start)
        // Refused every 6 h: never a feed failure, so only the time since the last verified changeset can fire.
        var t = start
        while (t + 6 * hour <= start + day) {
            t += 6 * hour
            r = UpdaterTransitions.after(r, RS, SyncFailure.ROLLBACK_REFUSED, t)
            assertEquals(0, r.rs().consecutiveFailures)
            assertFalse(UpdaterTransitions.signedSourceFailing(r, RS, t, day), "at +${(t - start) / hour} h")
        }
        r =
            UpdaterTransitions.after(
                r,
                RS,
                SyncFailure.ROLLBACK_REFUSED,
                start + day + 1,
            )
        assertTrue(UpdaterTransitions.signedSourceFailing(r, RS, start + day + 1, day))
    }

    @Test
    fun `the inputs are checked`() {
        // A sync that stopped installed nothing, so it has no <ts>.
        for (f in SyncFailure.entries) {
            assertFailsWith<IllegalArgumentException>("$f") {
                UpdaterTransitions.after(record, RS, f, now, signedTimestampMillis = now)
            }
        }
        assertFailsWith<IllegalArgumentException> { after(failed, server = -1) }
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
