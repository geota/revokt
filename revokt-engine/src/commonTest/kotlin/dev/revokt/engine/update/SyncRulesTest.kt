// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.SyncOutcome
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Spec §7.1's rollback guard: the decision for a verified signed changeset, the §9 data-path fixture (a) and the
 * decision half of the §9 content-signature far-future item. The floor is the higher of the stored watermark and the
 * live `<ts>` when a generation is live, and nothing when none is (Firefox imports when its local data does not
 * verify). Every boundary is tested at the edge and one millisecond either side.
 */
class SyncRulesTest {
    private val now = 1_800_000_000_000
    private val hour = 3_600_000L
    private val day = 24 * hour

    /** The live generation's `<ts>`: one hour ago. */
    private val live = now - hour

    private fun decide(
        ts: Long,
        watermark: Long? = live,
        liveTs: Long? = live,
    ) = SyncRules.decide(ts, watermark, liveTs)

    @Test
    fun `data-path (a) a changeset older than the floor is ROLLBACK_REFUSED, however little older`() {
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(live - 1))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(live - day))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(Long.MIN_VALUE))
        assertEquals(SyncDecision.UNCHANGED, decide(live))
        assertEquals(SyncDecision.INSTALL, decide(live + 1))
        assertEquals(SyncDecision.INSTALL, decide(Long.MAX_VALUE))
    }

    @Test
    fun `the floor is the higher of the stored watermark and the live ts`() {
        // A stored watermark above the live ts is the floor; equal to it installs (Firefox's strict <).
        val higher = live + day
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(higher - 1, watermark = higher))
        assertEquals(SyncDecision.INSTALL, decide(higher, watermark = higher))
        assertEquals(SyncDecision.INSTALL, decide(higher + 1, watermark = higher))
        // Between the live ts and a higher watermark is refused, the live ts itself is UNCHANGED first.
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(live + 1, watermark = higher))
        assertEquals(SyncDecision.UNCHANGED, decide(live, watermark = higher))
        // A stored watermark below the live ts is raised to it.
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(live - 1, watermark = live - day))
        assertEquals(SyncDecision.INSTALL, decide(live + 1, watermark = live - day))
    }

    @Test
    fun `data-path (a) a lost watermark is floored at the live generation, so an older changeset is refused`() {
        // A malformed or absent updater.json reads as no watermark (a store failure for a malformed one, #178).
        for (read in listOf(StoreRead.Malformed, StoreRead.Absent)) {
            val lost = LoadedUpdater.of(read).record.watermarkMillis
            assertNull(lost)
            assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(live - 1, watermark = lost), "$read")
            assertEquals(SyncDecision.UNCHANGED, decide(live, watermark = lost), "$read")
            assertEquals(SyncDecision.INSTALL, decide(live + 1, watermark = lost), "$read")
        }
    }

    @Test
    fun `with no generation loaded the stored watermark is not read, and anything installs`() {
        val high = now + 30 * day
        for (watermark in listOf(null, high, Long.MAX_VALUE, Long.MIN_VALUE)) {
            for (ts in listOf(Long.MIN_VALUE, 0, now - day, high - 1, high, high + 1, Long.MAX_VALUE)) {
                assertEquals(SyncDecision.INSTALL, decide(ts, watermark, liveTs = null), "$ts under $watermark")
            }
        }
    }

    @Test
    fun `content-signature far future - a ts ahead of the clock installs, and the next server ts passes it`() {
        // No rule reads local time: a ts a year ahead installs and raises the watermark.
        val ahead = now + 365 * day
        assertEquals(SyncDecision.INSTALL, decide(ahead))
        val record = UpdaterTransitions.after(updater(), RS, SyncOutcome.INSTALLED, now, signedTimestampMillis = ahead)
        assertEquals(ahead, record.watermarkMillis)
        assertEquals(ahead, record.sources.getValue(RS).lastVerifiedLastModified)
        // Kinto's timestamps are monotonic per collection, so the next changeset is newer and installs.
        assertEquals(SyncDecision.UNCHANGED, decide(ahead, record.watermarkMillis, ahead))
        assertEquals(SyncDecision.INSTALL, decide(ahead + 1, record.watermarkMillis, ahead))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(now, record.watermarkMillis, ahead))
    }

    @Test
    fun `an install keeps the watermark a high-water mark, so an older install never lowers it`() {
        // With no generation loaded an older changeset installs; the cursor moves back with it, the watermark stays.
        val before = updater(watermark = live + day, cursor = live + day)
        val after = UpdaterTransitions.after(before, RS, SyncOutcome.INSTALLED, now, signedTimestampMillis = live)
        assertEquals(live + day, after.watermarkMillis)
        assertEquals(live, after.sources.getValue(RS).lastVerifiedLastModified)
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(live + 1, after.watermarkMillis, live))
        assertEquals(SyncDecision.INSTALL, decide(live + day, after.watermarkMillis, live))
    }

    @Test
    fun `ROLLBACK_REFUSED is not a feed failure, and saturatingAdd checks its addend`() {
        val before = updater(watermark = live + day)
        val after = UpdaterTransitions.after(before, RS, SyncOutcome.ROLLBACK_REFUSED, now)
        assertEquals(before.watermarkMillis, after.watermarkMillis)
        assertEquals(0, after.sources.getValue(RS).consecutiveFailures)
        assertEquals(before.sources.getValue(RS).lastVerifiedAtMillis, after.sources.getValue(RS).lastVerifiedAtMillis)
        assertFailsWith<IllegalArgumentException> { saturatingAdd(1, -1) }
        assertEquals(Long.MAX_VALUE, saturatingAdd(Long.MAX_VALUE, 0))
        assertEquals(Long.MAX_VALUE, saturatingAdd(1, Long.MAX_VALUE))
        assertEquals(Long.MAX_VALUE - 1, saturatingAdd(-1, Long.MAX_VALUE))
    }

    private fun updater(
        watermark: Long? = live,
        cursor: Long? = live,
    ) = UpdaterRecord(
        watermarkMillis = watermark,
        sources = mapOf(RS to SourceRecord(lastVerifiedLastModified = cursor, lastVerifiedAtMillis = now - hour)),
    )

    private companion object {
        const val RS = "remote-settings"
    }
}
