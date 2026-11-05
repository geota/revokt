// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** Why decision step 6 evaluated no PKIX fallback path, carried on `Finding.FallbackNotUsed` (spec §4, §5.1). Growable. */
public enum class FallbackReason {
    /** The fallback is enabled, but the presented chain is over `RevoktLimits.FALLBACK_MAX_PRESENTED`. */
    SKIPPED,

    /** The fallback is disabled: `pkixFallback(false)`, or the walker-only harness's disabled path. */
    DISABLED,

    /** The fallback ran and found no path: its build returned null or threw. */
    FAILED,
}
