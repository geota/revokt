// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** How one sync ended (spec §4, §5.1). Growable. Persist `name`, never `ordinal`. */
public enum class SyncOutcome {
    INSTALLED,
    UNCHANGED,
    FAILED,

    /** An x5u link outside its validity window at the local clock, at stage [SyncStage.X5U] (§7.1). */
    CLOCK_SKEW,
    ROLLBACK_REFUSED,
    BACKOFF,
    STORE_FAILED,
    STORE_LOCKED,
}
