// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Where a sync failed (spec §4): [SyncResult.stage] of a `FAILED`, `STORE_FAILED` or `CLOCK_SKEW` sync. Growable.
 * Persist `name`, never `ordinal`. Each producing bullet of the spec names its stage; a fetcher-policy reject and a 401
 * or 407 carry the stage of the fetch they interrupted, [CHANGESET], [X5U] or [ATTACHMENT] (§3).
 */
public enum class SyncStage {
    /** The §5.1 fetcher trust manager build retry failed; nothing was fetched. */
    FETCHER_TRUST,

    /** The changeset fetch, or its `last_modified` `CLOCK_SKEW`. */
    CHANGESET,

    /** The x5u fetch, or a validity `CLOCK_SKEW`. */
    X5U,

    /** A body fetch, or the over-cap signed record. */
    ATTACHMENT,
    SIGNATURE,
    SCHEMA,
    INDEX,
    PREPARE,
    SELF_CHECK,
    ACTIVATE,
    STORE,
}
