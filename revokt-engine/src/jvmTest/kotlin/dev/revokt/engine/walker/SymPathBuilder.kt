// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.walker

import dev.revokt.AnchorSnapshot
import dev.revokt.PathBuilderFallback
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.VerifyResult
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.testing.CertId
import dev.revokt.testing.KeyId
import dev.revokt.testing.ReferenceWalker
import dev.revokt.testing.SymVerifier
import okio.ByteString

/**
 * The walker-only harness's PKIX fallback on the enabled path (spec §9 walker fixtures, §9.1's fake, #136): a
 * [PathBuilderFallback] whose provider model is [SymVerifier]'s over the fixture's [ok] links and [unsupported] OIDs.
 * It is an uncapped reference path builder: breadth first from the leaf over related candidates (the store's anchors,
 * then the presented certificates), every link `VERIFIED`, every certificate between the leaf and the anchor able to
 * issue, at most `MAX_DEPTH + 1` certificates, and no budget. It returns the shortest such path, leaf → anchor, the
 * leaf's presented bytes first and the snapshot's bytes last, or null. So it finds a path exactly where the reference
 * walker does and never one a real provider could not verify; [agreed] records that each answer matched
 * [ReferenceWalker], and the runner asserts it.
 *
 * [canonicaliser] is the delegate's: the platform's by default, a custom delegate's in rows (ac) and (ad), whose
 * honest issuer only a custom delegate relates to the leaf.
 */
internal class SymPathBuilder(
    private val ok: Set<Pair<CertId, KeyId>>,
    private val unsupported: Set<String>,
    private val canonicaliser: (ByteArray) -> String? = ::canonicalSubject,
) : PathBuilderFallback {
    var calls = 0
        private set

    /** False once an answer disagreed with [ReferenceWalker] over the same links and canonicaliser. */
    var agreed = true
        private set

    override fun build(
        chainDer: List<ByteArray>,
        anchors: AnchorSnapshot,
        nowMillis: Long,
    ): List<ByteArray>? {
        calls++
        val verifier = SymVerifier(ok, unsupported)
        val path = shortest(chainDer, CandidateIndex(anchors.anchors, canonicaliser), verifier)
        val reference = ReferenceWalker(anchors.anchors, verifier, canonicaliser).walk(chainDer)
        val key = path?.let { WalkerCerts.cert(it[1]).spkiHash.hex() }
        if (if (key == null) reference.isNotEmpty() else key !in reference) agreed = false
        return path
    }

    private fun shortest(
        chainDer: List<ByteArray>,
        index: CandidateIndex,
        verifier: SymVerifier,
    ): List<ByteArray>? {
        // Decide calls the fallback only once the leaf parsed; another certificate the parser rejects is dropped.
        val leaf = index.cert(WalkerCerts.parse(chainDer[0]))
        val presented = chainDer.drop(1).mapNotNull { parsedOrNull(it) }.map { index.cert(it) }
        val visited = hashSetOf(leaf.bytesHash)
        var frontier = listOf(listOf(leaf))
        while (frontier.isNotEmpty()) {
            val next = ArrayList<List<Cert>>()
            // [path + anchor] holds at most MAX_DEPTH + 1 certificates.
            val extended =
                frontier.filter { it.size <= RevoktLimits.MAX_DEPTH }.flatMap { path ->
                    issuers(index, presented, path, verifier).map { path + it }.toList()
                }
            extended.firstOrNull { index.isAnchorBytes(it.last()) }?.let { path ->
                return listOf(chainDer[0]) + path.drop(1).map { it.der }
            }
            for (path in extended) if (visited.add(path.last().bytesHash)) next += path
            frontier = next
        }
        return null
    }

    /**
     * The certificates that issue [path]'s last one: related, not a loop of the leaf, an anchor or able to issue there,
     * and `VERIFIED` under their key.
     */
    private fun issuers(
        index: CandidateIndex,
        presented: List<Cert>,
        path: List<Cert>,
        verifier: SymVerifier,
    ): Sequence<Cert> {
        val child = path.last()
        return index
            .related(presented, child, path.mapTo(HashSet()) { it.bytesHash })
            .filterNot { repeats(it, path.first()) }
            .filter { index.isAnchorBytes(it) || it.issuer.mayIssue(path.size - 1, RequiredEku.SERVER_AUTH) }
            .filter { verifier.verify(child.tbsSigAlg, it.spki, child.tbs, child.sig) == VerifyResult.VERIFIED }
    }

    private fun parsedOrNull(der: ByteArray): ParsedCertificate? =
        when (val r = CertificateParser.parse(der)) {
            is CertificateParse.Parsed -> r.certificate
            is CertificateParse.Failed -> null
        }

    /** [candidate] has [leaf]'s raw subject and raw SPKI: a loop on every path (RFC 4158 §5.2). */
    private fun repeats(
        candidate: Cert,
        leaf: Cert,
    ): Boolean = candidate.subjectRaw.contentEquals(leaf.subjectRaw) && candidate.spki.contentEquals(leaf.spki)
}
