// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The walker's own counters for one walk (spec §4, §5.1), carried on `Finding.Path.walkStats`. Walker internals:
 * opt-in at class level, so the type stays out of the API dump. A value type: equality is by content.
 */
@RevoktInternalApi
public class WalkStats(
    /** Verifier calls, memo hits excluded (`RevoktLimits.MAX_VERIFICATIONS`). */
    public val verifications: Int,
    /** Candidates for which verification was requested, memo hits included (`RevoktLimits.MAX_EXPLORED`). */
    public val candidatesExplored: Int,
    /** Related candidates (the candidate index's `related`) explored at the leaf. */
    public val relatedExploredAtLeaf: Int,
    /** Unrelated candidates (the candidate index's `unrelated`) explored at the leaf. */
    public val unrelatedExploredAtLeaf: Int,
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
