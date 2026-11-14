// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.AnchorSnapshot
import dev.revokt.ChainSource
import dev.revokt.Finding
import dev.revokt.KeyabilityClause
import dev.revokt.ParseReason
import dev.revokt.PathStatus
import dev.revokt.RevoktTestingApi
import dev.revokt.TerminalKind
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString.Companion.toByteString

/**
 * The decision for `EvaluationRequest.verifiedPath` (spec §4): the one path, leaf to anchor, is trusted without
 * re-verification, so no walk and no fallback run (`source = PLATFORM`, `endReason` null). The path is both the
 * reported path and the chain the exemptions see.
 *
 * - **Step 2, one-certificate paths only:** the caller's path does not make its leaf an anchor. A leaf byte-equal to
 *   an anchor of [snapshot] (the one read at entry, through [index]) is `FOUND`, keyed by its own SPKI, before step 3's
 *   keyability check, as decide's step 2 does; any other leaf is gated like every leaf (the maintainer's decision on
 *   #195). This is the only route that consults the snapshot, so `anchorSnapshotId` is [snapshot]'s id for a
 *   one-certificate path and 0 for a longer one.
 * - **Step 3's leaf checks** run on the path's leaf: unparseable or over `MAX_CERT_BYTES` is `PARSE_FAILED`, outside
 *   the §9.2 keyability profile `PARSE_FAILED(PRODUCER_UNKEYABLE)`, never queried. The `MAX_PRESENTED` cut is over a
 *   presented chain that is walked, so it does not apply. The leaf carries `AlgorithmIdMismatch` at index 0 when its
 *   signature algorithms differ.
 * - **The leaf-issuer key** is the path's second certificate's SPKI hash, or the leaf's own for a one-certificate path
 *   (as step 2 and §5.1 step 4 do). When revokt cannot parse the second certificate there is no key, since step 7
 *   could not query under it, and the `FOUND` decision with no key is the boundary's error in `evaluate`, never a
 *   clean answer.
 */
@OptIn(RevoktTestingApi::class)
internal fun decideVerified(
    path: List<ByteArray>,
    index: CandidateIndex,
    snapshot: AnchorSnapshot,
): PathDecision {
    require(path.isNotEmpty()) { "a verified path runs leaf to anchor: it is not empty" }
    val parses = arrayOfNulls<ParsedCertificate>(path.size)
    val base =
        Finding.Path
            .Builder()
            .source(ChainSource.PLATFORM)
            .anchorSnapshotId(verifiedAnchorSnapshotId(path, snapshot))
    val leafParse =
        when (val r = CertificateParser.parse(path[0])) {
            is CertificateParse.Failed -> return parseFailed(base, r.reason, null, emptyList(), parses)
            is CertificateParse.Parsed -> r.certificate.also { parses[0] = it }
        }
    val leaf = index.cert(leafParse)
    val findings =
        if (leaf.algorithmIdMismatch) {
            listOf(
                Finding.AlgorithmIdMismatch
                    .Builder()
                    .certIndex(0)
                    .build(),
            )
        } else {
            emptyList()
        }
    // Step 2: only a leaf that is an anchor by bytes in the snapshot read at entry skips the keyability check.
    if (!(path.size == 1 && index.isAnchorBytes(leaf))) {
        leaf.keyabilityClause?.let { return parseFailed(base, ParseReason.PRODUCER_UNKEYABLE, it, findings, parses) }
    }
    val key =
        if (path.size == 1) {
            leaf.spkiHash
        } else {
            (CertificateParser.parse(path[1]) as? CertificateParse.Parsed)?.certificate?.let { issuer ->
                parses[1] = issuer
                issuer.rawSpki().toByteString().sha256()
            }
        }
    val keys = listOfNotNull(key)
    val hashes = path.map { it.toByteString().sha256() }
    base
        .status(PathStatus.FOUND)
        .pathsFound(1)
        .issuerSpkiSha256s(keys.map { it.toByteArray() })
        .reportedPathSha256s(hashes.map { it.toByteArray() })
        .terminalKind(TerminalKind.ANCHOR)
        .anchorSha256(hashes.last().toByteArray())
    return PathDecision(base.build(), keys, leaf.serial, leaf.scts, findings, false, parses.toList())
}

/** A `PARSE_FAILED` decision for the verified leaf: no key, no reported path, nothing queried. */
@OptIn(RevoktTestingApi::class)
private fun parseFailed(
    base: Finding.Path.Builder,
    reason: ParseReason,
    clause: KeyabilityClause?,
    findings: List<Finding>,
    parses: Array<ParsedCertificate?>,
): PathDecision =
    PathDecision(
        base
            .status(PathStatus.PARSE_FAILED)
            .parseReason(reason)
            .keyabilityClause(clause)
            .build(),
        emptyList(),
        null,
        emptyList(),
        findings,
        false,
        parses.toList(),
    )

/**
 * `anchorSnapshotId` on the verified-path route: [snapshot]'s id for a one-certificate path, whose leaf step 2 compares
 * with the snapshot's anchors, and 0 for a longer path, which consults no snapshot (spec §4 `Finding.Path`).
 */
internal fun verifiedAnchorSnapshotId(
    path: List<ByteArray>,
    snapshot: AnchorSnapshot,
): Long = if (path.size == 1) snapshot.id else 0
