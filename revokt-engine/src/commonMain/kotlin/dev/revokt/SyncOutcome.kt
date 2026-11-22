// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * How one sync ended (spec §4, §5.1). Growable. Persist `name`, never `ordinal`. A [SKIPPED] or [FAILED] sync carries
 * its [SyncFailure] on [SyncResult.failure].
 */
public enum class SyncOutcome {
    /** The sync installed a generation. */
    INSTALLED,

    /** The collection is at the live generation: a 304, or a verified `<ts>` equal to the live one. */
    UNCHANGED,

    /** The sync stopped short of an install, and not as a feed failure: [SyncFailure.BACKOFF], `ROLLBACK_REFUSED`. */
    SKIPPED,

    /** A feed failure: `consecutiveFailures` advances and the failure backoff applies (§7.1). */
    FAILED,
}
