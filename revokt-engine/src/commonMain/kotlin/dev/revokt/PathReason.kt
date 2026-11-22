// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Why a path is `NO_ISSUER`, `PARSE_FAILED` or `PATH_BUDGET_EXCEEDED` (spec §4, §5.1): `Finding.Path.reason`, set
 * exactly for those statuses, and a reason of that [status]. Growable: a reason may be added in a minor, so a `when`
 * over reasons needs an `else` branch. Persist `name`, never `ordinal`.
 */
public enum class PathReason(
    /** The status this reason explains. */
    public val status: PathStatus,
) {
    /** `NO_ISSUER`: the candidate index held no related candidate for the leaf. */
    NO_CANDIDATE(PathStatus.NO_ISSUER),

    /** `NO_ISSUER`: related candidates existed at the leaf, but none that may issue (an anchor, or a CA) verified it. */
    ALL_CANDIDATES_INVALID(PathStatus.NO_ISSUER),

    /** `NO_ISSUER`: a candidate verified at the leaf, but no walk reached an anchor. */
    UNANCHORED(PathStatus.NO_ISSUER),

    /**
     * `NO_ISSUER`, in the walker-only harness and `Evaluator.evaluate`: the walk found no path and met an own signature
     * OID the verifier cannot verify (decision step 6). Each such OID is in an `UnsupportedAlgorithm` finding with
     * `outcomeDepended = true`.
     */
    UNSUPPORTED_ALGORITHM(PathStatus.NO_ISSUER),

    /** `NO_ISSUER`, on a trust-manager binding: the walker found no path and the PKIX fallback failed too. */
    PLATFORM_ONLY(PathStatus.NO_ISSUER),

    /** `PARSE_FAILED`: not a structurally valid `Certificate` (spec §9.2: definite lengths, well-formed tags). */
    STRUCTURE(PathStatus.PARSE_FAILED),

    /** `PARSE_FAILED`: larger than `RevoktLimits.MAX_CERT_BYTES`; checked before the parse. */
    OVERSIZE(PathStatus.PARSE_FAILED),

    /** `PARSE_FAILED`: parsed, but Mozilla's producer could not key it, so it is in no filter (spec §9.2 D8). */
    PRODUCER_UNKEYABLE(PathStatus.PARSE_FAILED),

    /**
     * `PATH_BUDGET_EXCEEDED`: the walk spent its work budget (`RevoktLimits.MAX_EXPLORED` candidates explored, or the
     * name-constraint comparison bound) before it found a path, or the presented chain is over `MAX_PRESENTED` or
     * `MAX_PRESENTED_BYTES` and was not walked.
     */
    EXPLORATION_BUDGET(PathStatus.PATH_BUDGET_EXCEEDED),

    /**
     * `PATH_BUDGET_EXCEEDED`: the walk completed without a path on a chain of more than
     * `RevoktLimits.FALLBACK_MAX_PRESENTED` certificates, which the PKIX fallback never runs on (§5.1 decision step 6).
     */
    FALLBACK_LIMIT(PathStatus.PATH_BUDGET_EXCEEDED),
}
