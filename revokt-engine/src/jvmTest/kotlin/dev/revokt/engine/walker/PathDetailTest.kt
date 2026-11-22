// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.KeyabilityClause
import dev.revokt.NoIssuerReason
import dev.revokt.TerminalKind
import dev.revokt.WalkEnd
import dev.revokt.WalkStats
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/** [PathDetail], the evaluation's `DEBUG` line (spec §4, §5.1): a value type whose text names every field. */
class PathDetailTest {
    private val hash = ByteArray(32) { 3 }.toByteString()

    private fun full() =
        PathDetail(
            walkerReason = NoIssuerReason.UNANCHORED,
            keyabilityClause = KeyabilityClause.TIME,
            endReason = WalkEnd.RELATED_BUDGET,
            endDepth = 2,
            anchorSnapshotId = 7,
            usedFallback = true,
            pathsFound = 3,
            reportedPathSha256s = listOf(hash),
            candidatesDropped = 1,
            walkStats = WalkStats(1, 2, 3, 4),
        )

    @Test
    fun `a detail is equal by content and every field takes part`() {
        assertEquals(full(), full())
        assertEquals(full().hashCode(), full().hashCode())
        val changed =
            listOf(
                PathDetail(walkerReason = NoIssuerReason.NO_CANDIDATE),
                PathDetail(keyabilityClause = KeyabilityClause.KEY),
                PathDetail(endReason = WalkEnd.COMPLETE),
                PathDetail(endDepth = 1),
                PathDetail(anchorSnapshotId = 1),
                PathDetail(usedFallback = true),
                PathDetail(pathsFound = 1),
                PathDetail(reportedPathSha256s = listOf(hash)),
                PathDetail(candidatesDropped = 1),
                PathDetail(walkStats = WalkStats(1, 0, 0, 0)),
            )
        for (c in changed) assertNotEquals(PathDetail(), c, "$c")
        assertNotEquals<Any>(PathDetail(), "detail")
    }

    @Test
    fun `the DEBUG text names every field in order, the hashes in hex`() {
        assertEquals(
            "walkerReason=UNANCHORED, keyabilityClause=TIME, terminalKind=ANCHOR, endReason=RELATED_BUDGET, " +
                "endDepth=2, anchorSnapshotId=7, usedFallback=true, pathsFound=3, " +
                "reportedPathSha256s=[${"03".repeat(32)}], candidatesDropped=1, " +
                "walkStats=WalkStats(verifications=1, candidatesExplored=2, relatedExploredAtLeaf=3, " +
                "unrelatedExploredAtLeaf=4)",
            full().toString(),
        )
    }
}
