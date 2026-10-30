// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * A dataset a policy can require (spec §4). Growable: M2 adds `INTERMEDIATES`, `ONECRL`, `CRLSET` and `DENYLIST`, M3
 * `CT_LOGS`, M4 `DISTRUST`. A new dataset never joins a preset's `requiredDatasets` or staleness map within a major.
 */
public enum class Dataset {
    CRLITE,
}
