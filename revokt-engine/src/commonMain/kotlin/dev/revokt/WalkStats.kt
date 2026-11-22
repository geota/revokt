// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The walker's own counters for one walk (spec §5.1), on the decision's `PathDetail` and so on the evaluation's `DEBUG`
 * line. A value type: equality is by content.
 */
internal class WalkStats(
    /** Verifier calls, memo hits excluded; at most one per exploration. */
    val verifications: Int,
    /** Candidates explored, the walk's work budget (`RevoktLimits.MAX_EXPLORED`): memo hits included, loops not. */
    val candidatesExplored: Int,
) {
    override fun equals(other: Any?): Boolean =
        other is WalkStats && verifications == other.verifications && candidatesExplored == other.candidatesExplored

    override fun hashCode(): Int = 31 * verifications + candidatesExplored

    override fun toString(): String = "WalkStats(verifications=$verifications, candidatesExplored=$candidatesExplored)"
}
