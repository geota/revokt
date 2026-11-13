// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.SyncStage
import dev.revokt.TrustClass

/**
 * What [SyncRules] decides for a verified `SIGNED` changeset (spec §6.3 "Coverage sanity at install", §7.1 "Rollback
 * guard"). [stage] is the `SyncResult.stage` of a refusal that has one.
 */
internal enum class SyncDecision(
    val stage: SyncStage?,
) {
    /** Install, then advance the cursor, `lastVerified*` and the watermark (to the higher of it and `<ts>`). */
    INSTALL(null),

    /**
     * The §6.3 bootstrap and clock-behind carve-out: install with `clockBehind`, then advance `lastVerifiedAtMillis`
     * only, never the watermark or the cursor.
     */
    INSTALL_CLOCK_BEHIND(null),

    /** `<ts>` is the live generation's: nothing to install; the attempt fields only. */
    UNCHANGED(null),

    /** `<ts>` is beyond local now + `clockSkew` and the carve-out does not apply: nothing advances. */
    CLOCK_SKEW(SyncStage.CHANGESET),

    /** Older than the watermark by the window or more, or inside it with a lower maximum coverage: not a feed failure. */
    ROLLBACK_REFUSED(null),

    /** A filter's coverage is beyond the trust-class bound ([SyncRules.coverageWithinBound]): cursor and watermark stay. */
    FAILED(SyncStage.INDEX),
}

/**
 * The dataset's live generation as the published snapshot holds it, for [SyncRules]: its [trustClass], its
 * `sourceTimestampMillis`, and its maximum coverage `high` (`GenerationSnapshot.coverageEndMillis`, clamped as there),
 * null when the engine cannot tell. Never read from `updater.json` (§6.5).
 */
internal class LiveGeneration(
    val trustClass: TrustClass,
    val sourceTimestampMillis: Long,
    val maxCoverageMillis: Long?,
) {
    override fun toString(): String =
        "LiveGeneration($trustClass at $sourceTimestampMillis, maxCoverage=$maxCoverageMillis)"
}

/**
 * The clock and policy inputs of [SyncRules]: local [nowMillis] and the policy's `clockSkew` and `rollbackWindow`
 * (`RevoktPolicy`, §4), each a non-negative duration.
 */
internal class SyncClock(
    val nowMillis: Long,
    val clockSkewMillis: Long,
    val rollbackWindowMillis: Long,
) {
    init {
        require(clockSkewMillis >= 0) { "clockSkew is negative" }
        require(rollbackWindowMillis >= 0) { "rollbackWindow is negative" }
    }

    /** `now + clockSkew`, saturating at [Long.MAX_VALUE]. */
    val futureBoundMillis: Long get() = saturatingAdd(nowMillis, clockSkewMillis)

    override fun toString(): String =
        "SyncClock(now=$nowMillis, clockSkew=$clockSkewMillis, rollbackWindow=$rollbackWindowMillis)"
}

/**
 * Spec §6.3's coverage sanity at install and §7.1's rollback guard, for one verified `SIGNED` changeset of a dataset and
 * channel. Every input is a value the caller passes: the changeset's signed `<ts>` ([signedTimestampMillis], the
 * verified envelope `timestamp` the client returns in `Changeset`, #181; never `pollChanges`' `last_modified`), the
 * dataset's watermark from `updater.json`, the [LiveGeneration] from the published snapshot (null when the dataset has
 * none: no stored generation, no seed) and the [SyncClock]. The candidate generation's coverage is `coverageHighs`:
 * the latest coverage `high` of each filter, unsigned as decoded; a filter that covers no log contributes none. Nothing
 * here reads the snapshot, the store or the engine.
 *
 * The coverage tests need the filter bodies, so the decision runs in two phases: [admit] before any body is fetched,
 * and [decide] once every filter's coverage is known, which repeats [admit] and adds the coverage tests. Their order:
 * 1. `UNCHANGED`-by-timestamp: `<ts>` equals the live `SIGNED` generation's `sourceTimestampMillis`. It precedes the
 *    `CLOCK_SKEW` test (§6.3). Only a `SIGNED` live generation matches, so a `SIGNED` changeset always evicts a `MIRROR`
 *    or `SYSTEM` one.
 * 2. The rollback guard: `<ts>` older than the watermark by `rollbackWindow` or more is `ROLLBACK_REFUSED` (§7.1: older
 *    by less than the window may still install).
 * 3. `CLOCK_SKEW`: `<ts>` beyond local now + `clockSkew`, unless the dataset has no generation or its live generation
 *    is itself `clockBehind` (recomputed here as `sourceTimestampMillis > now + clockSkew`, never read from the last
 *    publish) and `<ts>` is newer than it, which is [SyncDecision.INSTALL_CLOCK_BEHIND].
 * 4. ([decide] only) The trust-class coverage bound, [coverageWithinBound]: `FAILED` at stage `INDEX`.
 * 5. ([decide] only) Inside the window (`<ts> ≤ watermark`), a maximum coverage below the live `SIGNED` generation's is
 *    `ROLLBACK_REFUSED`; equal or above installs. A changeset newer than the watermark installs whatever its coverage.
 *
 * **The watermark floor** (revision 56, #188): the watermark both phases compare against is the higher of the stored one
 * and the live generation's `sourceTimestampMillis`, when the live generation is `SIGNED` and not itself `clockBehind`
 * ([floored]). A malformed or absent `updater.json` beside a live `SIGNED` generation (#178: it reads as an empty
 * record, a store failure) therefore cannot reopen a rollback to anything older than what is installed, while a
 * far-future live generation installed under the carve-out never pins the watermark, so it cannot freeze the feed.
 *
 * Every sum saturates and every difference is checked, so no input overflows into a wrong answer.
 */
internal object SyncRules {
    /**
     * The decision for a changeset before its bodies are fetched: [SyncDecision.UNCHANGED],
     * [SyncDecision.ROLLBACK_REFUSED] beyond the window, [SyncDecision.CLOCK_SKEW], or one of the two installs, which
     * [decide] then confirms against the coverage.
     */
    fun admit(
        signedTimestampMillis: Long,
        watermarkMillis: Long?,
        live: LiveGeneration?,
        clock: SyncClock,
    ): SyncDecision {
        if (live != null && live.trustClass == TrustClass.SIGNED &&
            signedTimestampMillis == live.sourceTimestampMillis
        ) {
            return SyncDecision.UNCHANGED
        }
        val watermark = floored(watermarkMillis, live, clock)
        if (watermark != null && beyondWindow(signedTimestampMillis, watermark, clock.rollbackWindowMillis)) {
            return SyncDecision.ROLLBACK_REFUSED
        }
        val bound = clock.futureBoundMillis
        if (signedTimestampMillis <= bound) return SyncDecision.INSTALL
        val carveOut =
            live == null || (live.sourceTimestampMillis > bound && signedTimestampMillis > live.sourceTimestampMillis)
        return if (carveOut) SyncDecision.INSTALL_CLOCK_BEHIND else SyncDecision.CLOCK_SKEW
    }

    /**
     * The decision for a changeset whose candidate generation's coverage is [coverageHighs]: [admit], then the `SIGNED`
     * coverage bound, then the coverage-monotonic rule inside the window.
     */
    fun decide(
        signedTimestampMillis: Long,
        watermarkMillis: Long?,
        live: LiveGeneration?,
        coverageHighs: List<ULong>,
        clock: SyncClock,
    ): SyncDecision {
        val admitted = admit(signedTimestampMillis, watermarkMillis, live, clock)
        if (admitted != SyncDecision.INSTALL && admitted != SyncDecision.INSTALL_CLOCK_BEHIND) return admitted
        if (!coverageWithinBound(TrustClass.SIGNED, coverageHighs, signedTimestampMillis, clock)) {
            return SyncDecision.FAILED
        }
        val watermark = floored(watermarkMillis, live, clock)
        val insideWindow = watermark != null && signedTimestampMillis <= watermark
        if (insideWindow && live != null && live.trustClass == TrustClass.SIGNED) {
            val liveMax = live.maxCoverageMillis
            if (liveMax != null && !coverageAtLeast(coverageHighs, liveMax)) return SyncDecision.ROLLBACK_REFUSED
        }
        return admitted
    }

    /**
     * Spec §6.3's coverage bound for a generation of [trustClass], one function for every class: `SIGNED`, no coverage
     * `high` is later than the changeset's signed `<ts>` ([signedTimestampMillis]) + `clockSkew` ("the timestamp compared
     * everywhere here (…, coverage bound, `CLOCK_SKEW`) is the signed `<ts>`"); `MIRROR` and `SYSTEM`, none is later
     * than local now + `clockSkew`, with no [signedTimestampMillis]. A `high` is compared unsigned, so one past
     * [Long.MAX_VALUE] is beyond every bound. `BUNDLED` has no source in this dataset and is refused.
     *
     * The `MIRROR` and `SYSTEM` branch has no caller in 0.2 (no such source before 0.3, §11): it is kept, tested here,
     * and must survive the dead-code pass (#150).
     */
    fun coverageWithinBound(
        trustClass: TrustClass,
        coverageHighs: List<ULong>,
        signedTimestampMillis: Long?,
        clock: SyncClock,
    ): Boolean {
        require(trustClass != TrustClass.BUNDLED) { "no BUNDLED source carries CRLite coverage" }
        require((trustClass == TrustClass.SIGNED) == (signedTimestampMillis != null)) {
            "the signed <ts> is given exactly for SIGNED"
        }
        val bound =
            if (signedTimestampMillis != null) {
                saturatingAdd(signedTimestampMillis, clock.clockSkewMillis)
            } else {
                clock.futureBoundMillis
            }
        return coverageHighs.all { bound >= 0 && it <= bound.toULong() }
    }

    /**
     * Whether the candidate's maximum coverage is at least [liveMaxMillis]: some `high`, clamped to [Long.MAX_VALUE] as
     * `coverageEndMillis` is, reaches it. A candidate that covers no log is below any live coverage.
     */
    private fun coverageAtLeast(
        coverageHighs: List<ULong>,
        liveMaxMillis: Long,
    ): Boolean = coverageHighs.any { minOf(it, Long.MAX_VALUE.toULong()).toLong() >= liveMaxMillis }

    /**
     * The watermark the rules compare against: [watermarkMillis] raised to the live generation's
     * `sourceTimestampMillis` when that generation is `SIGNED` and not `clockBehind` (`sourceTimestampMillis ≤ now +
     * clockSkew`, recomputed here), else [watermarkMillis] as stored; null when neither gives one.
     */
    private fun floored(
        watermarkMillis: Long?,
        live: LiveGeneration?,
        clock: SyncClock,
    ): Long? {
        if (live == null || live.trustClass != TrustClass.SIGNED ||
            live.sourceTimestampMillis > clock.futureBoundMillis
        ) {
            return watermarkMillis
        }
        return maxOf(watermarkMillis ?: Long.MIN_VALUE, live.sourceTimestampMillis)
    }

    /**
     * Whether [timestamp] is older than [watermark] by [window] or more (§7.1: "older by less than `rollbackWindow`
     * may still install"). A difference past [Long.MAX_VALUE] is beyond every window.
     */
    private fun beyondWindow(
        timestamp: Long,
        watermark: Long,
        window: Long,
    ): Boolean {
        if (timestamp > watermark) return false
        val older = watermark - timestamp
        // timestamp ≤ watermark, so a negative difference is an overflow: older than any window.
        return older < 0 || older >= window
    }
}

/** [a] + [b] for a non-negative [b], saturating at [Long.MAX_VALUE]. */
internal fun saturatingAdd(
    a: Long,
    b: Long,
): Long {
    require(b >= 0) { "the addend is negative" }
    return if (a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b
}
