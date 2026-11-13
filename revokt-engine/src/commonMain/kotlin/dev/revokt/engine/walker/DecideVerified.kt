// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

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
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * The decision for `EvaluationRequest.verifiedPaths` (spec §4): the paths are trusted without re-verification, so no
 * walk, no fallback and no anchor snapshot is consulted (`source = PLATFORM`, `anchorSnapshotId = 0`, `endReason` null).
 * [chain] is the chain the exemptions see: the presented one when the request has it, else the first verified path.
 *
 * - **Step 3's leaf checks** run on the leaf, the first path's first certificate: unparseable or over `MAX_CERT_BYTES`
 *   is `PARSE_FAILED`, outside the §9.2 keyability profile `PARSE_FAILED(PRODUCER_UNKEYABLE)`, never queried. The
 *   `MAX_PRESENTED` cut is over a presented chain that is walked, so it does not apply. The leaf carries
 *   `AlgorithmIdMismatch` at index 0 when its signature algorithms differ.
 * - **The leaf-issuer keys** are each path's second certificate's SPKI hash, or the leaf's own for a one-certificate
 *   path (as step 2 and §5.1 step 4 do), distinct, in path order. A path whose second certificate revokt cannot parse
 *   gives no key, since step 7 could not query under it; with no key at all the `FOUND` decision is the boundary's error
 *   in `evaluate`, never a clean answer.
 * - **The reported path** is the first path that gave a key (so `issuerSpkiSha256s[0]` is its key), else the first.
 *   `pathsFound` counts every verified path.
 */
internal fun decideVerified(
    paths: List<List<ByteArray>>,
    chain: List<ByteArray>,
): PathDecision = VerifiedDecider(paths, chain).run()

/** One verified-paths decision's state: every certificate parsed so far, by its bytes, and the findings. */
@OptIn(RevoktTestingApi::class)
private class VerifiedDecider(
    private val paths: List<List<ByteArray>>,
    private val chain: List<ByteArray>,
) {
    private val parsed = HashMap<ByteString, ParsedCertificate>()
    private val findings = ArrayList<Finding>()

    fun run(): PathDecision {
        require(
            paths.isNotEmpty() && paths.none { it.isEmpty() },
        ) { "verified paths run leaf to anchor: none is empty" }
        val leafDer = paths[0][0]
        val leafParse =
            when (val r = CertificateParser.parse(leafDer)) {
                is CertificateParse.Failed -> return parseFailed(r.reason, null)
                is CertificateParse.Parsed -> r.certificate
            }
        parsed[leafDer.toByteString()] = leafParse
        // No index is consulted, so the leaf needs no canonical subject.
        val leaf = Cert.of(leafParse) { null }
        if (leaf.algorithmIdMismatch) {
            findings +=
                Finding.AlgorithmIdMismatch
                    .Builder()
                    .certIndex(0)
                    .build()
        }
        leaf.keyabilityClause?.let { return parseFailed(ParseReason.PRODUCER_UNKEYABLE, it) }
        val keys = LinkedHashSet<ByteString>()
        var reported: List<ByteArray>? = null
        for (path in paths) {
            keys += issuerKey(path, leaf) ?: continue
            if (reported == null) reported = path
        }
        return result(
            base(PathStatus.FOUND).pathsFound(paths.size),
            keys.toList(),
            reported ?: paths[0],
            leaf,
        )
    }

    /** [path]'s leaf-issuer key: its second certificate's SPKI hash, the [leaf]'s own alone; null when unreadable. */
    private fun issuerKey(
        path: List<ByteArray>,
        leaf: Cert,
    ): ByteString? {
        if (path.size == 1) return leaf.spkiHash
        val issuer = CertificateParser.parse(path[1]) as? CertificateParse.Parsed ?: return null
        parsed[path[1].toByteString()] = issuer.certificate
        return issuer.certificate
            .rawSpki()
            .toByteString()
            .sha256()
    }

    private fun base(status: PathStatus): Finding.Path.Builder =
        Finding.Path
            .Builder()
            .status(status)
            .source(ChainSource.PLATFORM)
            .anchorSnapshotId(0)

    private fun parseFailed(
        reason: ParseReason,
        clause: KeyabilityClause?,
    ): PathDecision =
        result(
            base(PathStatus.PARSE_FAILED).parseReason(reason).keyabilityClause(clause),
            emptyList(),
            emptyList(),
            null,
        )

    /** The decision; the exemptions' chain carries the parse of each of its certificates decided here, by bytes. */
    private fun result(
        builder: Finding.Path.Builder,
        keys: List<ByteString>,
        reported: List<ByteArray>,
        leaf: Cert?,
    ): PathDecision {
        val hashes = reported.map { it.toByteString().sha256() }
        val path =
            builder
                .issuerSpkiSha256s(keys.map { it.toByteArray() })
                .reportedPathSha256s(hashes.map { it.toByteArray() })
                .terminalKind(if (hashes.isEmpty()) null else TerminalKind.ANCHOR)
                .anchorSha256(hashes.lastOrNull()?.toByteArray())
                .build()
        val parses = chain.map { parsed[it.toByteString()] }
        return PathDecision(path, keys, leaf?.serial, leaf?.scts.orEmpty(), findings.toList(), false, parses)
    }
}
