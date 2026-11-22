// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The walker's own counters for one walk (spec §5.1), on the decision's `PathDetail` and so on the evaluation's `DEBUG`
 * line. A value type: equality is by content.
 */
internal class WalkStats(
    /** Verifier calls, memo hits excluded (`RevoktLimits.MAX_VERIFICATIONS`). */
    val verifications: Int,
    /** Candidates for which verification was requested, memo hits included (`RevoktLimits.MAX_EXPLORED`). */
    val candidatesExplored: Int,
    /** Related candidates (the candidate index's `related`) explored at the leaf. */
    val relatedExploredAtLeaf: Int,
    /** Unrelated candidates (the candidate index's `unrelated`) explored at the leaf. */
    val unrelatedExploredAtLeaf: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is WalkStats &&
            verifications == other.verifications &&
            candidatesExplored == other.candidatesExplored &&
            relatedExploredAtLeaf == other.relatedExploredAtLeaf &&
            unrelatedExploredAtLeaf == other.unrelatedExploredAtLeaf

    override fun hashCode(): Int =
        listOf(verifications, candidatesExplored, relatedExploredAtLeaf, unrelatedExploredAtLeaf).hashCode()

    override fun toString(): String =
        "WalkStats(verifications=$verifications, candidatesExplored=$candidatesExplored, " +
            "relatedExploredAtLeaf=$relatedExploredAtLeaf, unrelatedExploredAtLeaf=$unrelatedExploredAtLeaf)"
}
