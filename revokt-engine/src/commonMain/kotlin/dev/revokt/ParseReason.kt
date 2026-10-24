// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Why a leaf is `PARSE_FAILED` (spec §4, §5.1 decision step 3). Growable; `parseReason != null` exactly when
 * `path.status == PARSE_FAILED`.
 */
public enum class ParseReason {
    /** Not a structurally valid `Certificate` (spec §9.2: definite lengths, well-formed tags, no trailing bytes). */
    STRUCTURE,

    /** Larger than `RevoktLimits.MAX_CERT_BYTES`; checked before the parse. */
    OVERSIZE,

    /** Parsed, but Mozilla's producer could not key it, so it is in no filter (spec §9.2 D8). */
    PRODUCER_UNKEYABLE,
}
