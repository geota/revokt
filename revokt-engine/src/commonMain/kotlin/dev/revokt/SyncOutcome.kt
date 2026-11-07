// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** How one sync ended (spec §4, §5.1). Growable. Persist `name`, never `ordinal`. */
public enum class SyncOutcome {
    INSTALLED,
    UNCHANGED,

    /** A metered-deferred full download (§7.2); not [UNCHANGED], which reads as healthy. */
    DEFERRED,
    FAILED,
    CLOCK_SKEW,
    ROLLBACK_REFUSED,
    BACKOFF,
    STORE_FAILED,
    STORE_LOCKED,

    /** The §8 fetcher policy found evidence against the source's own host chain; produced from 0.3. */
    BLOCKED_BY_SELF,
}
