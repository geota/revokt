// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** What a generation's `sourceTimestamp` means, per dataset and source (spec §4, §7.2). Growable. */
public enum class Freshness {
    /** CRLite: the filter record's `last_modified`. */
    RECORD_LAST_MODIFIED,

    /** M2 OneCRL and intermediates: the last verified poll. */
    LAST_VERIFIED_POLL,

    /** A C2SP manifest's last modification (`MIRROR`, `SYSTEM`). */
    MANIFEST_LAST_MODIFIED,

    /** A seed's signed timestamp. */
    SEED_SIGNED_TIME,

    /** M2 CRLSet: its sequence time. */
    SEQUENCE_TIME,

    /** M2 denylist: the artifact date. */
    ARTIFACT_DATE,
}
