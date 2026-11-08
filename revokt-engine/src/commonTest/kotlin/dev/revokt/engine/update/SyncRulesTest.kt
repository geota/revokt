// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.UpdaterRecord
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §6.3 coverage sanity at install and §7.1's rollback guard (#131): the decision for a verified `SIGNED`
 * changeset, the §9 data-path fixtures (a) and (b) and the decision half of the §9 content-signature clock items. Every
 * boundary is tested at the edge and one millisecond either side.
 */
class SyncRulesTest {
    private val now = 1_800_000_000_000
    private val hour = 3_600_000L
    private val day = 24 * hour
    private val clock = SyncClock(now, clockSkewMillis = day, rollbackWindowMillis = day)

    /** The watermark: one hour ago, the live generation's own timestamp unless a test says otherwise. */
    private val watermark = now - hour
    private val coverage = now - 2 * hour

    private fun live(
        ts: Long = watermark,
        maxCoverage: Long? = coverage,
        trustClass: TrustClass = TrustClass.SIGNED,
    ) = LiveGeneration(trustClass, ts, maxCoverage)

    /** One filter whose latest `high` is [high], carried by a record of [lastModified] (default: [now]). */
    private fun filter(
        high: Long?,
        lastModified: Long? = now,
    ) = FilterCoverage(high?.toULong(), lastModified)

    private fun decide(
        ts: Long,
        filters: List<FilterCoverage>,
        live: LiveGeneration? = live(),
        watermark: Long? = this.watermark,
        clock: SyncClock = this.clock,
    ) = SyncRules.decide(ts, watermark, live, filters, clock)

    private fun admit(
        ts: Long,
        live: LiveGeneration? = live(),
        watermark: Long? = this.watermark,
        clock: SyncClock = this.clock,
    ) = SyncRules.admit(ts, watermark, live, clock)

    @Test
    fun `data-path (a) a changeset older than the watermark by the window or more is ROLLBACK_REFUSED`() {
        // An older changeset with more coverage than the live one: only the window decides.
        val more = listOf(filter(coverage + hour))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(watermark - day, more))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(watermark - day - 1, more))
        assertEquals(SyncDecision.INSTALL, decide(watermark - day + 1, more))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, admit(watermark - day))
        assertEquals(SyncDecision.INSTALL, admit(watermark - day + 1))
        // A window of 0 admits nothing older than the watermark, and nothing equal to it but the live generation.
        val noWindow = SyncClock(now, day, 0)
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(watermark, more, live(ts = watermark - 1), clock = noWindow))
        assertEquals(SyncDecision.INSTALL, decide(watermark + 1, more, clock = noWindow))
        // The difference overflows Long: older than any window, never wrapped into a "newer" one.
        val wide = SyncClock(now, day, Long.MAX_VALUE)
        assertEquals(SyncDecision.ROLLBACK_REFUSED, admit(Long.MIN_VALUE, live(ts = 0), Long.MAX_VALUE, wide))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, admit(-1, live(ts = 0), Long.MAX_VALUE, wide))
        assertEquals(SyncDecision.INSTALL, admit(0, live(ts = 1), Long.MAX_VALUE - 1, wide))
    }

    @Test
    fun `data-path (a) inside the window a lower maximum coverage is ROLLBACK_REFUSED and an equal one installs`() {
        val older = watermark - hour
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(older, listOf(filter(coverage - 1))))
        assertEquals(SyncDecision.INSTALL, decide(older, listOf(filter(coverage))))
        assertEquals(SyncDecision.INSTALL, decide(older, listOf(filter(coverage + 1))))
        // The maximum over every filter counts, not the first or the last.
        assertEquals(SyncDecision.INSTALL, decide(older, listOf(filter(1), filter(coverage), filter(2))))
        assertEquals(
            SyncDecision.ROLLBACK_REFUSED,
            decide(older, listOf(filter(1), filter(coverage - 1), filter(null))),
        )
        // A candidate that covers no log is below any live coverage.
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(older, listOf(filter(null))))
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(older, emptyList()))
        // At the watermark itself (`timestamp ≤ watermark`), still inside the window.
        assertEquals(SyncDecision.ROLLBACK_REFUSED, decide(watermark, listOf(filter(coverage - 1)), live(ts = older)))
        assertEquals(SyncDecision.INSTALL, decide(watermark, listOf(filter(coverage)), live(ts = older)))
        // The bound is the live SIGNED generation's: none for a MIRROR live generation or an unknown coverage.
        val low = listOf(filter(1))
        assertEquals(SyncDecision.INSTALL, decide(older, low, live(trustClass = TrustClass.MIRROR)))
        assertEquals(SyncDecision.INSTALL, decide(older, low, live(maxCoverage = null)))
        assertEquals(SyncDecision.INSTALL, decide(older, low, live = null))
        // A live coverage at Long.MAX_VALUE (an open-ended window, clamped) is reached only by a filter as high.
        val open = live(maxCoverage = Long.MAX_VALUE)
        val farClock = SyncClock(now, Long.MAX_VALUE, day)
        assertEquals(SyncDecision.INSTALL, decide(older, listOf(filter(Long.MAX_VALUE)), open, clock = farClock))
        assertEquals(
            SyncDecision.ROLLBACK_REFUSED,
            decide(older, listOf(filter(Long.MAX_VALUE - 1)), open, clock = farClock),
        )
    }

    @Test
    fun `data-path (a) a newer changeset with lower coverage installs and advances the watermark`() {
        val newer = watermark + 1
        assertEquals(SyncDecision.INSTALL, decide(newer, listOf(filter(1))))
        assertEquals(SyncDecision.INSTALL, decide(newer, listOf(filter(null))))
        val record = UpdaterTransitions.after(updater(), RS, SyncOutcome.INSTALLED, now, signedTimestampMillis = newer)
        assertEquals(newer, record.watermarkMillis)
        assertEquals(newer, record.sources.getValue(RS).lastVerifiedLastModified)
        // No watermark yet (no seed, nothing installed): every changeset is newer.
        assertEquals(SyncDecision.INSTALL, decide(Long.MIN_VALUE, listOf(filter(1)), watermark = null))
    }

    @Test
    fun `data-path (b) SIGNED coverage high beyond last_modified + clockSkew is FAILED at stage INDEX`() {
        val lm = now - 3 * hour
        assertEquals(SyncDecision.INSTALL, decide(watermark + 1, listOf(filter(lm + day, lm))))
        assertEquals(SyncDecision.FAILED, decide(watermark + 1, listOf(filter(lm + day + 1, lm))))
        assertEquals(SyncStage.INDEX, SyncDecision.FAILED.stage)
        assertTrue(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(filter(lm + day, lm)), clock))
        assertFalse(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(filter(lm + day + 1, lm)), clock))
        // Each filter against its own record: a full from an older record cannot borrow a delta's later last_modified.
        val full = filter(lm + day + 1, lm)
        val delta = filter(lm + day + 1, lm + hour)
        assertTrue(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(delta), clock))
        assertFalse(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(delta, full), clock))
        // The bound precedes the coverage-monotonic rule inside the window.
        assertEquals(SyncDecision.FAILED, decide(watermark - hour, listOf(filter(coverage - 1), full)))
        // A filter that covers no log has nothing to bound; a SIGNED filter without its record's last_modified fails.
        assertTrue(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(filter(null, null)), clock))
        assertFalse(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(filter(0, null)), clock))
        // The sum saturates; a high past Long.MAX_VALUE, compared unsigned, is beyond it.
        val top = Long.MAX_VALUE - 5
        assertTrue(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(filter(Long.MAX_VALUE, top)), clock))
        val past = FilterCoverage(Long.MAX_VALUE.toULong() + 1u, top)
        assertFalse(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(past), clock))
        assertFalse(
            SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(FilterCoverage(ULong.MAX_VALUE, top)), clock),
        )
        // A bound below 0 (a record before 1970 − clockSkew) admits no coverage at all.
        assertFalse(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(filter(0, -day - 1)), clock))
        assertTrue(SyncRules.coverageWithinBound(TrustClass.SIGNED, listOf(filter(0, -day)), clock))
        assertTrue(SyncRules.coverageWithinBound(TrustClass.SIGNED, emptyList(), clock))
    }

    @Test
    fun `data-path (b) MIRROR coverage beyond now + clockSkew is FAILED, asserted on the coverage function`() {
        // Maintainer decision (2026-11-05): no MIRROR source before 0.3, so this is asserted at the function.
        for (trustClass in listOf(TrustClass.MIRROR, TrustClass.SYSTEM)) {
            // The record's last_modified plays no part: a mirror's bound is local now + clockSkew.
            assertTrue(SyncRules.coverageWithinBound(trustClass, listOf(filter(now + day, now - 9 * day)), clock))
            assertFalse(SyncRules.coverageWithinBound(trustClass, listOf(filter(now + day + 1, null)), clock))
            assertTrue(SyncRules.coverageWithinBound(trustClass, listOf(filter(null, null), filter(now, null)), clock))
            assertFalse(
                SyncRules.coverageWithinBound(trustClass, listOf(filter(now, null), filter(now + day + 1)), clock),
            )
            val saturated = SyncClock(Long.MAX_VALUE - 1, day, day)
            assertTrue(SyncRules.coverageWithinBound(trustClass, listOf(filter(Long.MAX_VALUE, null)), saturated))
            val past = FilterCoverage(Long.MAX_VALUE.toULong() + 1u, null)
            assertFalse(SyncRules.coverageWithinBound(trustClass, listOf(past), saturated))
            assertFalse(
                SyncRules.coverageWithinBound(trustClass, listOf(filter(0, null)), SyncClock(-day - 1, day, day)),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            SyncRules.coverageWithinBound(
                TrustClass.BUNDLED,
                emptyList(),
                clock,
            )
        }
    }

    @Test
    fun `a changeset 25 h ahead of a live generation that is not clockBehind is CLOCK_SKEW until within clockSkew`() {
        val ahead = now + 25 * hour
        val good = listOf(filter(coverage, ahead))
        assertEquals(SyncDecision.CLOCK_SKEW, decide(ahead, good))
        assertEquals(SyncDecision.CLOCK_SKEW, admit(ahead))
        assertEquals(SyncStage.CHANGESET, SyncDecision.CLOCK_SKEW.stage)
        // Watermark, cursor and lastVerified* unchanged (a failure-path write).
        val before = updater(lastVerified = now - hour)
        val after = UpdaterTransitions.after(before, RS, SyncOutcome.CLOCK_SKEW, now)
        assertEquals(before.watermarkMillis, after.watermarkMillis)
        assertEquals(
            before.sources.getValue(RS).lastVerifiedLastModified,
            after.sources.getValue(RS).lastVerifiedLastModified,
        )
        assertEquals(before.sources.getValue(RS).lastVerifiedAtMillis, after.sources.getValue(RS).lastVerifiedAtMillis)
        // The next poll, once the clock has moved so the changeset is within clockSkew, installs.
        val later = SyncClock(now + hour, day, day)
        assertEquals(SyncDecision.INSTALL, decide(ahead, good, clock = later))
        assertEquals(SyncDecision.CLOCK_SKEW, decide(ahead, good, clock = SyncClock(now + hour - 1, day, day)))
        // The edge: exactly now + clockSkew is not ahead.
        assertEquals(SyncDecision.INSTALL, admit(now + day))
        assertEquals(SyncDecision.CLOCK_SKEW, admit(now + day + 1))
        // now + clockSkew saturates: nothing is ahead of a clock at the end of time.
        assertEquals(SyncDecision.INSTALL, admit(Long.MAX_VALUE, clock = SyncClock(Long.MAX_VALUE - 1, day, day)))
    }

    @Test
    fun `the same changeset against no generation installs with clockBehind, watermark and cursor unchanged`() {
        val ahead = now + 25 * hour
        val good = listOf(filter(coverage, ahead))
        assertEquals(SyncDecision.INSTALL_CLOCK_BEHIND, decide(ahead, good, live = null, watermark = null))
        assertEquals(SyncDecision.INSTALL_CLOCK_BEHIND, decide(ahead, good, live = null))
        assertNull(SyncDecision.INSTALL_CLOCK_BEHIND.stage)
        val before = updater(lastVerified = null, cursor = null, watermark = null)
        val after =
            UpdaterTransitions.after(
                before,
                RS,
                SyncOutcome.INSTALLED,
                now,
                signedTimestampMillis = ahead,
                clockBehind = true,
            )
        assertNull(after.watermarkMillis)
        assertNull(after.sources.getValue(RS).lastVerifiedLastModified)
        assertEquals(now, after.sources.getValue(RS).lastVerifiedAtMillis)
        // The next poll of the same changeset finds it UNCHANGED, the live generation now being it.
        assertEquals(SyncDecision.UNCHANGED, decide(ahead, good, live(ts = ahead), watermark = null))
        // The carve-out is still under the rollback guard and the coverage rules.
        assertEquals(SyncDecision.ROLLBACK_REFUSED, admit(ahead, live = null, watermark = ahead + day))
        assertEquals(SyncDecision.FAILED, decide(ahead, listOf(filter(ahead + day + 1, ahead)), live = null))
    }

    @Test
    fun `a changeset whose ts equals the live sourceTimestampMillis is UNCHANGED even when ahead of the clock`() {
        val ahead = now + 25 * hour
        assertEquals(
            SyncDecision.UNCHANGED,
            decide(ahead, listOf(filter(coverage)), live(ts = ahead), watermark = ahead),
        )
        assertEquals(SyncDecision.UNCHANGED, admit(ahead, live(ts = ahead), watermark = null))
        assertEquals(SyncDecision.UNCHANGED, admit(watermark))
        assertNull(SyncDecision.UNCHANGED.stage)
        // UNCHANGED precedes the window and the coverage tests too: the live generation was checked at its install.
        assertEquals(SyncDecision.UNCHANGED, decide(watermark - day, emptyList(), live(ts = watermark - day)))
        // One millisecond either side is not the live generation.
        assertEquals(SyncDecision.CLOCK_SKEW, admit(ahead + 1, live(ts = ahead + 2)))
        assertEquals(SyncDecision.INSTALL_CLOCK_BEHIND, admit(ahead + 1, live(ts = ahead)))
        // Only a SIGNED live generation matches: a SIGNED changeset evicts a MIRROR one of the same timestamp.
        assertEquals(SyncDecision.INSTALL, admit(watermark, live(trustClass = TrustClass.MIRROR)))
    }

    @Test
    fun `a live generation that is itself clockBehind admits a newer future changeset with clockBehind`() {
        val liveTs = now + day + 1
        val behind = live(ts = liveTs, maxCoverage = null)
        assertEquals(SyncDecision.INSTALL_CLOCK_BEHIND, admit(liveTs + 1, behind, watermark = null))
        assertEquals(SyncDecision.INSTALL_CLOCK_BEHIND, admit(now + 30 * hour, behind))
        // Not newer than the live generation: CLOCK_SKEW, so an older future changeset cannot pin anything.
        assertEquals(SyncDecision.CLOCK_SKEW, admit(liveTs + 1, behind.copy(liveTs + 5)))
        // clockBehind is recomputed here: live at exactly now + clockSkew is not behind, so the carve-out is closed.
        assertEquals(SyncDecision.CLOCK_SKEW, admit(now + 30 * hour, live(ts = now + day)))
        // A clock corrected since the last publish closes it at once.
        assertEquals(SyncDecision.CLOCK_SKEW, admit(liveTs + 2 * day, behind, clock = SyncClock(now + hour, day, day)))
        // A changeset within clockSkew of a clockBehind live generation is an ordinary install or refusal.
        assertEquals(SyncDecision.INSTALL, admit(now, behind, watermark = now - 1))
    }

    @Test
    fun `the rollback guard precedes CLOCK_SKEW, and the inputs are checked`() {
        // Future-dated and beyond the window below an even later watermark: ROLLBACK_REFUSED, not a feed failure.
        assertEquals(SyncDecision.ROLLBACK_REFUSED, admit(now + 25 * hour, live(ts = now), watermark = now + 49 * hour))
        assertFailsWith<IllegalArgumentException> { SyncClock(now, -1, day) }
        assertFailsWith<IllegalArgumentException> { SyncClock(now, day, -1) }
        assertFailsWith<IllegalArgumentException> { saturatingAdd(1, -1) }
        assertEquals(Long.MAX_VALUE, saturatingAdd(Long.MAX_VALUE, 0))
        assertEquals(Long.MAX_VALUE, saturatingAdd(1, Long.MAX_VALUE))
        assertEquals(Long.MAX_VALUE - 1, saturatingAdd(-1, Long.MAX_VALUE))
        assertEquals(Long.MAX_VALUE, clock.copy(nowMillis = Long.MAX_VALUE).futureBoundMillis)
        assertEquals(now + day, clock.futureBoundMillis)
    }

    private fun LiveGeneration.copy(ts: Long) = LiveGeneration(trustClass, ts, maxCoverageMillis)

    private fun SyncClock.copy(nowMillis: Long) = SyncClock(nowMillis, clockSkewMillis, rollbackWindowMillis)

    private fun updater(
        lastVerified: Long? = now - hour,
        cursor: Long? = this.watermark,
        watermark: Long? = this.watermark,
    ) = UpdaterRecord(
        watermarkMillis = watermark,
        sources =
            mapOf(
                RS to
                    SourceRecord(
                        lastVerifiedLastModified = cursor,
                        lastVerifiedAtMillis = lastVerified,
                    ),
            ),
    )

    private companion object {
        const val RS = "remote-settings"
    }
}
