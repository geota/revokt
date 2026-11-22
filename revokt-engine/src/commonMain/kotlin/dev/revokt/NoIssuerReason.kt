// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Why the walk found no path (spec §4, §5.1 walker step 6): the walker's own reason, on the evaluation's `DEBUG` line
 * as `walkerReason`; the reported one is `Finding.Path.reason`, a [PathReason]. Growable.
 */
public enum class NoIssuerReason {
    /** The candidate index held no related candidate for the leaf. */
    NO_CANDIDATE,

    /** Related candidates existed at the leaf, but none that may issue (an anchor, or a CA) verified it. */
    ALL_CANDIDATES_INVALID,

    /** A candidate verified at the leaf, but no walk reached an anchor. */
    UNANCHORED,

    /**
     * In the walker-only harness and `Evaluator.evaluate`: the walk found no path and met an own signature OID the
     * verifier cannot verify (spec §5.1 decision step 6). Each such OID is in an `UnsupportedAlgorithm` finding with
     * `outcomeDepended = true`.
     */
    UNSUPPORTED_ALGORITHM,

    /** On a trust-manager binding: the walker found no path and the PKIX fallback failed too. */
    PLATFORM_ONLY,
}
