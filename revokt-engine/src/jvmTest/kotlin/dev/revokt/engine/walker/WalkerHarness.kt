// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.TerminalKind
import dev.revokt.VerifyResult
import dev.revokt.WalkEnd
import dev.revokt.WalkStats
import dev.revokt.testing.CertId
import dev.revokt.testing.KeyId
import dev.revokt.testing.SymOids
import dev.revokt.testing.SymVerifier
import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * One row of the §9 walker fixture table, as the walker-only harness reads it: `id | presented (ordered) | snapshot |
 * preload | verifier.unsupported | expected Walk | …`. The verifier is the §9.1 [SymVerifier] over [ok];
 * [unsupported] is both its startup probe and the probe the walk reads. [variant] names one of a row's cases (an order,
 * a count). [preload] is M2's column (spec §7.4), empty in every 0.2 row. The other columns (path status,
 * `Finding.Path` fields, verdict) are added by #136 and #140.
 */
internal class WalkerFixture(
    val id: String,
    val variant: String,
    val presented: List<ByteArray>,
    val snapshot: List<ByteArray>,
    val ok: Set<Pair<CertId, KeyId>>,
    val walk: ExpectedWalk,
    val unsupported: Set<String> = SymOids.UNSUPPORTED,
    val customCanonicaliser: Boolean = false,
    val label: (ByteString) -> String = { it.hex().take(8) },
) {
    val preload: List<ByteArray> get() = emptyList()

    override fun toString(): String = "walker ($id)${if (variant.isEmpty()) "" else " $variant"}"
}

/**
 * The expected Walk column. [kind] is the variant; [paths] are `Found`'s paths or `Budget`'s partial paths, each as
 * the certificates' bytes hashes, and the leaf keys are their second certificates' SPKI hashes unless [leafKeys] is
 * given. [unsupportedOids] and [findings] are always compared; a null count is not.
 */
internal data class ExpectedWalk(
    val kind: Kind,
    val paths: List<List<ByteString>>? = null,
    val leafKeys: Set<ByteString>? = null,
    val reason: NoIssuerReason? = null,
    val end: WalkEnd? = null,
    val endDepth: Int? = null,
    val unsupportedOids: Set<String> = emptySet(),
    val findings: List<Finding> = emptyList(),
    val verifications: Int? = null,
    val maxVerifications: Int? = null,
    val candidatesExplored: Int? = null,
    val relatedExploredAtLeaf: Int? = null,
    val unrelatedExploredAtLeaf: Int? = null,
) {
    enum class Kind { FOUND, NOT_FOUND, BUDGET }

    companion object {
        fun found(vararg paths: List<FixtureCert>): ExpectedWalk = ExpectedWalk(Kind.FOUND, hashes(paths.toList()))

        fun notFound(reason: NoIssuerReason): ExpectedWalk = ExpectedWalk(Kind.NOT_FOUND, reason = reason)

        fun budget(
            end: WalkEnd,
            endDepth: Int?,
            vararg partialPaths: List<FixtureCert>,
        ): ExpectedWalk = ExpectedWalk(Kind.BUDGET, hashes(partialPaths.toList()), end = end, endDepth = endDepth)

        private fun hashes(paths: List<List<FixtureCert>>): List<List<ByteString>> =
            paths.map { p -> p.map { it.bytesHash } }
    }
}

/** The walker-only harness (spec §9): [reconstruct] over one fixture row, with the cross-call memo cleared. */
@OptIn(RevoktInternalApi::class)
internal object WalkerHarness {
    fun walk(
        f: WalkerFixture,
        crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult> =
            LruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
    ): Walk {
        val index = CandidateIndex(f.snapshot, customCanonicaliser = f.customCanonicaliser)
        val presented = f.presented.map { index.cert(WalkerCerts.parse(it)) }
        val verifier = SymVerifier(f.ok, f.unsupported)
        return reconstruct(presented, index, verifier, verifier.unsupportedOids(), crossCallMemo)
    }

    /** Runs [f] and asserts its expected Walk column. */
    fun check(f: WalkerFixture): Walk {
        val walk = walk(f)
        check(f.walk, walk, f.label, f.toString())
        return walk
    }

    fun check(
        expected: ExpectedWalk,
        walk: Walk,
        label: (ByteString) -> String,
        at: String,
    ) {
        val shown = describe(walk, label)
        val (paths, keys) = variant(expected, walk, "$at: ", "; $shown")
        expected.paths?.let { want ->
            assertEquals(
                want.map { p -> p.map(label) },
                paths.map { p -> p.certs.map { label(it.bytesHash) } },
                "$at: paths; $shown",
            )
        }
        val wantKeys = expected.leafKeys ?: expected.paths?.let { keysOf(paths) }
        wantKeys?.let { assertEquals(it, keys, "$at: leaf keys; $shown") }
        assertEquals(keysOf(paths), keys, "$at: leaf keys are the paths' second certificates; $shown")
        paths.forEach { assertTrue(it.terminal == TerminalKind.ANCHOR, "$at: terminal; $shown") }
        assertEquals(expected.unsupportedOids, walk.unsupportedOids, "$at: unsupportedOids; $shown")
        assertEquals(expected.findings, walk.findings, "$at: findings; $shown")
        stats(expected, walk.stats, "$at: ", "; $shown")
    }

    /** Asserts the variant and its own fields; returns its paths (partial for `Budget`) and leaf keys. */
    private fun variant(
        expected: ExpectedWalk,
        walk: Walk,
        at: String,
        shown: String,
    ): Pair<List<WalkPath>, Set<ByteString>> =
        when (expected.kind) {
            ExpectedWalk.Kind.FOUND -> {
                if (walk !is Walk.Found) fail("${at}expected Found$shown")
                walk.paths to walk.leafKeys
            }

            ExpectedWalk.Kind.NOT_FOUND -> {
                if (walk !is Walk.NotFound) fail("${at}expected NotFound$shown")
                assertEquals(expected.reason, walk.reason, "${at}reason$shown")
                emptyList<WalkPath>() to emptySet()
            }

            ExpectedWalk.Kind.BUDGET -> {
                if (walk !is Walk.Budget) fail("${at}expected Budget$shown")
                assertEquals(expected.end, walk.end, "${at}end$shown")
                expected.endDepth?.let { assertEquals(it, walk.endDepth, "${at}endDepth$shown") }
                walk.partialPaths to walk.partialLeafKeys
            }
        }

    private fun stats(
        expected: ExpectedWalk,
        s: WalkStats,
        at: String,
        shown: String,
    ) {
        expected.verifications?.let { assertEquals(it, s.verifications, "${at}verifications$shown") }
        expected.maxVerifications?.let { assertTrue(s.verifications <= it, "${at}verifications ≤ $it$shown") }
        expected.candidatesExplored?.let { assertEquals(it, s.candidatesExplored, "${at}candidatesExplored$shown") }
        expected.relatedExploredAtLeaf?.let {
            assertEquals(it, s.relatedExploredAtLeaf, "${at}relatedExploredAtLeaf$shown")
        }
        expected.unrelatedExploredAtLeaf?.let {
            assertEquals(it, s.unrelatedExploredAtLeaf, "${at}unrelatedExploredAtLeaf$shown")
        }
        assertTrue(s.verifications <= RevoktLimits.MAX_VERIFICATIONS, "${at}MAX_VERIFICATIONS$shown")
        assertTrue(s.candidatesExplored <= RevoktLimits.MAX_EXPLORED, "${at}MAX_EXPLORED$shown")
    }

    private fun keysOf(paths: List<WalkPath>): Set<ByteString> = paths.mapTo(LinkedHashSet()) { it.certs[1].spkiHash }

    fun describe(
        walk: Walk,
        label: (ByteString) -> String,
    ): String {
        fun paths(p: List<WalkPath>) =
            p.joinToString(", ", "[", "]") { w -> w.certs.joinToString("→") { label(it.bytesHash) } }
        val head =
            when (walk) {
                is Walk.Found -> "Found(${paths(walk.paths)}"
                is Walk.NotFound -> "NotFound(${walk.reason}"
                is Walk.Budget -> "Budget(${walk.end}, endDepth=${walk.endDepth}, ${paths(walk.partialPaths)}"
            }
        return "$head, ${walk.stats}, unsupported=${walk.unsupportedOids}, findings=${walk.findings})"
    }

    /** SPKI hashes of [keys]. */
    fun keys(vararg keys: FixtureCert): Set<ByteString> = keys.mapTo(LinkedHashSet()) { it.keyHash }

    fun hex(hashes: Set<ByteString>): Set<String> = hashes.mapTo(LinkedHashSet()) { it.hex() }

    fun hash(der: ByteArray): ByteString = der.toByteString().sha256()
}
