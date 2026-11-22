// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.AnchorSnapshot
import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.PathBuilderFallback
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import dev.revokt.SignatureVerifier
import dev.revokt.TerminalKind
import dev.revokt.VerifyResult
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
    val label: (ByteString) -> String = { it.hex().take(8) },
) {
    val preload: List<ByteArray> get() = emptyList()

    override fun toString(): String = "walker ($id)${if (variant.isEmpty()) "" else " $variant"}"
}

/**
 * The expected Walk column. [kind] is the variant; [path] is `Found`'s one path, as the certificates' bytes hashes,
 * and the leaf key is its second certificate's SPKI hash unless [leafKey] is given. [unsupportedOids] and [findings]
 * are always compared; a null count is not.
 */
internal data class ExpectedWalk(
    val kind: Kind,
    val path: List<ByteString>? = null,
    val leafKey: ByteString? = null,
    val reason: NoIssuerReason? = null,
    val unsupportedOids: Set<String> = emptySet(),
    val findings: List<Finding> = emptyList(),
    val verifications: Int? = null,
    val maxVerifications: Int? = null,
    val candidatesExplored: Int? = null,
) {
    enum class Kind { FOUND, NOT_FOUND, BUDGET }

    companion object {
        fun found(path: List<FixtureCert>): ExpectedWalk = ExpectedWalk(Kind.FOUND, path.map { it.bytesHash })

        fun notFound(reason: NoIssuerReason): ExpectedWalk = ExpectedWalk(Kind.NOT_FOUND, reason = reason)

        fun budget(): ExpectedWalk = ExpectedWalk(Kind.BUDGET)
    }
}

/** The walker-only harness (spec §9): [reconstruct] over one fixture row, with the cross-call memo cleared. */
@OptIn(RevoktInternalApi::class, RevoktTestingApi::class)
internal object WalkerHarness {
    fun walk(
        f: WalkerFixture,
        crossCallMemo: LruMap<Pair<ByteString, ByteString>, VerifyResult> =
            lruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
    ): Walk {
        val index = CandidateIndex(f.snapshot)
        val presented = f.presented.map { index.cert(WalkerCerts.parse(it)) }
        val verifier = SymVerifier(f.ok, f.unsupported)
        return reconstruct(presented, index, verifier, verifier.unsupportedOids(), crossCallMemo)
    }

    /**
     * Decision steps 1 to 6 over [f] (spec §5.1, §9): [fallback] null is the harness's disabled path, [platformOnly]
     * the trust-manager bindings' `PLATFORM_ONLY` promotion (off in the harness), and [harness] false applies step
     * 3's `MAX_PRESENTED` cut as every trust-manager path does. [verifier] wraps the fixture's [SymVerifier];
     * [requiredEku] is the request's purpose (#237).
     */
    fun decide(
        f: WalkerFixture,
        fallback: PathBuilderFallback?,
        platformOnly: Boolean = false,
        harness: Boolean = true,
        requiredEku: RequiredEku = RequiredEku.SERVER_AUTH,
        verifier: (SignatureVerifier) -> SignatureVerifier = { it },
    ): PathDecision {
        val index = CandidateIndex(f.snapshot)
        val sym = SymVerifier(f.ok, f.unsupported)
        val context =
            DecideContext(
                verifier(sym),
                sym.unsupportedOids(),
                lruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
                fallback,
                NOW,
                platformOnly,
                requiredEku,
            )
        val snapshot = snapshot(f.snapshot)
        return if (harness) {
            decideWalkerHarness(f.presented, index, snapshot, context)
        } else {
            decide(f.presented, index, snapshot, context)
        }
    }

    /** The harness's snapshot of [anchors], id [SNAPSHOT_ID]. */
    @OptIn(RevoktTestingApi::class)
    fun snapshot(anchors: List<ByteArray>): AnchorSnapshot =
        AnchorSnapshot
            .Builder()
            .id(SNAPSHOT_ID)
            .sha256(ByteArray(32))
            .anchors(anchors)
            .createdMillis(NOW)
            .build()

    const val SNAPSHOT_ID: Long = 41
    const val NOW: Long = 1_780_000_000_000

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
        val found = variant(expected, walk, "$at: ", "; $shown")
        if (found != null) {
            expected.path?.let { want ->
                assertEquals(want.map(label), found.path.certs.map { label(it.bytesHash) }, "$at: path; $shown")
            }
            expected.leafKey?.let { assertEquals(it, found.leafKey, "$at: leaf key; $shown") }
            assertEquals(found.path.certs[1].spkiHash, found.leafKey, "$at: the leaf key is the path's second; $shown")
            assertTrue(found.path.terminal == TerminalKind.ANCHOR, "$at: terminal; $shown")
        }
        assertEquals(expected.unsupportedOids, walk.unsupportedOids, "$at: unsupportedOids; $shown")
        assertEquals(expected.findings, walk.findings, "$at: findings; $shown")
        stats(expected, walk.stats, "$at: ", "; $shown")
    }

    /** Asserts the variant and its own fields; returns the walk when it is `Found`. */
    private fun variant(
        expected: ExpectedWalk,
        walk: Walk,
        at: String,
        shown: String,
    ): Walk.Found? =
        when (expected.kind) {
            ExpectedWalk.Kind.FOUND -> {
                walk as? Walk.Found ?: fail("${at}expected Found$shown")
            }

            ExpectedWalk.Kind.NOT_FOUND -> {
                if (walk !is Walk.NotFound) fail("${at}expected NotFound$shown")
                assertEquals(expected.reason, walk.reason, "${at}reason$shown")
                null
            }

            ExpectedWalk.Kind.BUDGET -> {
                if (walk !is Walk.Budget) fail("${at}expected Budget$shown")
                null
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
        assertTrue(s.verifications <= s.candidatesExplored, "${at}one verification per exploration at most$shown")
        assertTrue(s.candidatesExplored <= RevoktLimits.MAX_EXPLORED, "${at}MAX_EXPLORED$shown")
    }

    fun describe(
        walk: Walk,
        label: (ByteString) -> String,
    ): String {
        val head =
            when (walk) {
                is Walk.Found -> "Found(${walk.path.certs.joinToString("→") { label(it.bytesHash) }}"
                is Walk.NotFound -> "NotFound(${walk.reason}"
                is Walk.Budget -> "Budget("
            }
        return "$head, ${walk.stats}, unsupported=${walk.unsupportedOids}, findings=${walk.findings})"
    }

    /** SPKI hashes of [keys]. */
    fun keys(vararg keys: FixtureCert): Set<ByteString> = keys.mapTo(LinkedHashSet()) { it.keyHash }

    fun hex(hashes: Set<ByteString>): Set<String> = hashes.mapTo(LinkedHashSet()) { it.hex() }

    fun hash(der: ByteArray): ByteString = der.toByteString().sha256()
}

/**
 * A fake [PathBuilderFallback] (spec §9 decide tests): [answer] gives the path for a chain, or null, or throws; [calls]
 * counts the `build` calls and [seen] keeps the last arguments.
 */
internal class FakeFallback(
    private val answer: (List<ByteArray>) -> List<ByteArray>?,
) : PathBuilderFallback {
    var calls = 0
        private set
    var seen: Triple<List<ByteArray>, AnchorSnapshot, Long>? = null
        private set

    override fun build(
        chainDer: List<ByteArray>,
        anchors: AnchorSnapshot,
        nowMillis: Long,
    ): List<ByteArray>? {
        calls++
        seen = Triple(chainDer, anchors, nowMillis)
        return answer(chainDer)
    }

    companion object {
        fun finds(vararg path: FixtureCert): FakeFallback = FakeFallback { path.map { it.der } }

        fun fails(): FakeFallback = FakeFallback { null }

        fun throws(t: Throwable): FakeFallback = FakeFallback { throw t }
    }
}
