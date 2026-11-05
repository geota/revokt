// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Why a path is `NO_ISSUER` (spec §4, §5.1 walker step 6). Growable; `noIssuerReason != null` exactly when
 * `path.status == NO_ISSUER`.
 */
public enum class NoIssuerReason {
    /** The candidate index held no related candidate for the leaf. */
    NO_CANDIDATE,

    /** Related candidates existed at the leaf, but none verified. */
    ALL_CANDIDATES_INVALID,

    /** A candidate verified at the leaf, but no walk reached an anchor. */
    UNANCHORED,

    /** On a trust-manager binding: the walker found no path and the PKIX fallback failed too (`walkerReason` keeps why). */
    PLATFORM_ONLY,
}
