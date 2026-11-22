// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.RevoktInternalApi
import dev.revokt.TerminalKind
import dev.revokt.WalkStats
import okio.ByteString

/**
 * The path [reconstruct] returns (spec §5.1 declarations): [certs] is leaf → … → terminal, every link `VERIFIED` under
 * the next certificate's key, and [terminal] says what the last certificate is. Distinct from `Finding.Path`.
 */
internal class WalkPath(
    val certs: List<Cert>,
    val terminal: TerminalKind,
) {
    override fun toString(): String = "WalkPath(${certs.joinToString(" → ") { it.bytesHash.hex().take(8) }}, $terminal)"
}

/**
 * What [reconstruct] found (spec §5.1 declarations). Every variant carries [unsupportedOids] (the probe-listed own
 * signature OIDs of the explored non-anchor candidates, and the leaf's once it had a candidate), the walk's [findings]
 * and its [stats].
 */
@OptIn(RevoktInternalApi::class)
internal sealed interface Walk {
    val unsupportedOids: Set<String>
    val findings: List<Finding>
    val stats: WalkStats

    /** The walk found [path], the first sound one; [leafKey] is its leaf-issuer SPKI hash. */
    class Found(
        val path: WalkPath,
        val leafKey: ByteString,
        override val unsupportedOids: Set<String>,
        override val findings: List<Finding>,
        override val stats: WalkStats,
    ) : Walk {
        override fun toString(): String = "Found(path=$path, stats=$stats, unsupportedOids=$unsupportedOids)"
    }

    /** The walk completed without a path; [reason] comes from the leaf level only. */
    class NotFound(
        val reason: NoIssuerReason,
        override val unsupportedOids: Set<String>,
        override val findings: List<Finding>,
        override val stats: WalkStats,
    ) : Walk {
        override fun toString(): String = "NotFound($reason, stats=$stats, unsupportedOids=$unsupportedOids)"
    }

    /** The work budget ran out before a path was found; the walk stops at its first path, so none was. */
    class Budget(
        override val unsupportedOids: Set<String>,
        override val findings: List<Finding>,
        override val stats: WalkStats,
    ) : Walk {
        override fun toString(): String = "Budget(stats=$stats, unsupportedOids=$unsupportedOids)"
    }
}
