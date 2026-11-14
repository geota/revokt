// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.RevoktInternalApi
import dev.revokt.TerminalKind
import dev.revokt.WalkEnd
import dev.revokt.WalkStats
import okio.ByteString

/**
 * One path [reconstruct] returns (spec §5.1 declarations): [certs] is leaf → … → terminal, every link `VERIFIED` under
 * the next certificate's key, and [terminal] says what the last certificate is. Distinct from `Finding.Path`.
 */
internal class WalkPath(
    val certs: List<Cert>,
    val terminal: TerminalKind,
) {
    override fun toString(): String = "WalkPath(${certs.joinToString(" → ") { it.bytesHash.hex().take(8) }}, $terminal)"
}

/**
 * What [reconstruct] found (spec §5.1 declarations). Every variant carries [unsupportedOids] (the own signature OIDs
 * of the visited nodes that the verifier's probe lists), the walk's [findings] and its [stats].
 */
@OptIn(RevoktInternalApi::class)
internal sealed interface Walk {
    val unsupportedOids: Set<String>
    val findings: List<Finding>
    val stats: WalkStats

    /** The walk completed and found [paths]; [leafKeys] are their leaf-issuer SPKI hashes. */
    class Found(
        val paths: List<WalkPath>,
        val leafKeys: Set<ByteString>,
        override val unsupportedOids: Set<String>,
        override val findings: List<Finding>,
        override val stats: WalkStats,
    ) : Walk {
        override fun toString(): String = "Found(paths=$paths, stats=$stats, unsupportedOids=$unsupportedOids)"
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

    /**
     * A limit stopped the walk: [end] is the limit, [endDepth] the path size at the node where it was detected, and
     * [partialPaths] the paths found before it, with their leaf-issuer keys [partialLeafKeys].
     */
    class Budget(
        val end: WalkEnd,
        val endDepth: Int,
        val partialPaths: List<WalkPath>,
        val partialLeafKeys: Set<ByteString>,
        override val unsupportedOids: Set<String>,
        override val findings: List<Finding>,
        override val stats: WalkStats,
    ) : Walk {
        override fun toString(): String =
            "Budget($end, endDepth=$endDepth, partialPaths=$partialPaths, stats=$stats, unsupportedOids=$unsupportedOids)"
    }
}
