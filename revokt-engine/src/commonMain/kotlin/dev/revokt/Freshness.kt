// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What a generation's `sourceTimestamp` means, per dataset and source (spec §4, §7.2). Growable: a value joins when its
 * producer is built (M2 adds the OneCRL, CRLSet and denylist meanings).
 */
public enum class Freshness {
    /** CRLite: the filter record's `last_modified`. */
    RECORD_LAST_MODIFIED,

    /** A seed's signed timestamp. */
    SEED_SIGNED_TIME,
}
