// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.KeyabilityClause
import dev.revokt.NoIssuerReason
import dev.revokt.TerminalKind
import dev.revokt.WalkStats
import okio.ByteString

/**
 * How decision steps 1 to 6 reached a `Finding.Path` beyond its one reason (spec §5.1): the walker's counters and
 * detail, which the evaluation writes to its one `DEBUG` log line ([toString]) and the tests read, and nothing public
 * carries.
 *
 * - [walkerReason]: the walker's own `NoIssuerReason`, before the `UNSUPPORTED_ALGORITHM` label or `PLATFORM_ONLY`
 *   promotion; [keyabilityClause]: the first failing §9.2 clause of a `PRODUCER_UNKEYABLE` leaf.
 * - [reportedPathSha256s]: the reported path's DER hashes, leaf to terminal (the walker's path, else the fallback
 *   path), and [terminalKind], null when it is empty.
 * - [anchorSnapshotId]: the `AnchorSnapshot` the decision read, 0 when none was consulted.
 * - [usedFallback], [pathsFound] (1 when the decision found a path: step 2, the walk, or the fallback after a walk
 *   `NotFound`; else 0), [candidatesDropped] (presented certificates the parser rejected) and [walkStats].
 */
@Suppress("LongParameterList") // One parameter per field of the DEBUG line, each defaulted.
internal class PathDetail(
    val walkerReason: NoIssuerReason? = null,
    val keyabilityClause: KeyabilityClause? = null,
    val anchorSnapshotId: Long = 0,
    val usedFallback: Boolean = false,
    val pathsFound: Int = 0,
    val reportedPathSha256s: List<ByteString> = emptyList(),
    val candidatesDropped: Int = 0,
    val walkStats: WalkStats = WalkStats(0, 0),
) {
    /** The reported path's terminal: every M1 terminal is an anchor; M2's preload-only terminal will need its own. */
    val terminalKind: TerminalKind? get() = if (reportedPathSha256s.isEmpty()) null else TerminalKind.ANCHOR

    /** Every field, named, in declaration order: equality, hashing and [toString] (the `DEBUG` line) read this list. */
    private fun fields(): List<Pair<String, Any?>> =
        listOf(
            "walkerReason" to walkerReason,
            "keyabilityClause" to keyabilityClause,
            "terminalKind" to terminalKind,
            "anchorSnapshotId" to anchorSnapshotId,
            "usedFallback" to usedFallback,
            "pathsFound" to pathsFound,
            "reportedPathSha256s" to reportedPathSha256s.map { it.hex() },
            "candidatesDropped" to candidatesDropped,
            "walkStats" to walkStats,
        )

    override fun equals(other: Any?): Boolean = other is PathDetail && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    override fun toString(): String = fields().joinToString { (name, value) -> "$name=$value" }
}
