// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

/** What [SyncRules] decides for a verified changeset (spec §7.1 "Rollback guard"). */
internal enum class SyncDecision {
    /** Install, then advance the cursor, `lastVerified*` and the watermark (to the higher of it and `<ts>`). */
    INSTALL,

    /** `<ts>` is the live generation's: nothing to install; the attempt fields only. */
    UNCHANGED,

    /** `<ts>` is older than the floor: not installed, and not a feed failure. */
    ROLLBACK_REFUSED,
}

/**
 * Spec §7.1's rollback guard, for one verified changeset of a dataset and channel, as Firefox's
 * `RemoteSettingsClient.sys.mjs` (`cac25a6`, lines 1203 to 1231) compares a changeset's timestamp with its local data's.
 * Every input is a value the caller passes: the changeset's signed `<ts>` ([signedTimestampMillis], the verified envelope
 * `timestamp` the client returns in `Changeset`; never `pollChanges`' `last_modified`), the dataset's watermark from
 * `updater.json`, and the live generation's `sourceTimestampMillis` as the published snapshot holds it
 * ([liveTimestampMillis], null when no generation loaded: none stored or none readable, and no seed). Nothing here reads
 * the snapshot, the store, the engine or a clock: no rule on signed data reads local time (§7.1).
 *
 * 1. No live generation: install, whatever the stored watermark says. Firefox imports older data when its local data
 *    does not verify, and a dataset with none to serve has nothing to protect.
 * 2. `<ts>` equals the live generation's: `UNCHANGED`.
 * 3. `<ts>` older than the floor, the higher of the stored watermark and the live `<ts>`: `ROLLBACK_REFUSED`. So a
 *    malformed or absent `updater.json` beside a live generation cannot reopen a rollback to anything older than what
 *    is installed. A `<ts>` equal to the floor, which can only be the watermark here, installs (Firefox's strict `<`).
 * 4. Anything else installs.
 */
internal object SyncRules {
    fun decide(
        signedTimestampMillis: Long,
        watermarkMillis: Long?,
        liveTimestampMillis: Long?,
    ): SyncDecision {
        val live = liveTimestampMillis ?: return SyncDecision.INSTALL
        if (signedTimestampMillis == live) return SyncDecision.UNCHANGED
        val floor = maxOf(watermarkMillis ?: live, live)
        return if (signedTimestampMillis < floor) SyncDecision.ROLLBACK_REFUSED else SyncDecision.INSTALL
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
