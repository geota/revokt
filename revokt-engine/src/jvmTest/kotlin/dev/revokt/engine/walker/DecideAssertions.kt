// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.ChainSource
import dev.revokt.FallbackReason
import dev.revokt.Finding
import dev.revokt.KeyabilityClause
import dev.revokt.Layer
import dev.revokt.NoIssuerReason
import dev.revokt.ParseReason
import dev.revokt.PathBuilderFallback
import dev.revokt.PathReason
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktTestingApi
import dev.revokt.SignatureVerifier
import dev.revokt.TerminalKind
import dev.revokt.VerifyResult
import dev.revokt.WalkEnd
import dev.revokt.WalkStats
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.TestDer
import dev.revokt.testing.SymOids
import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/*
 * Assertions and fixtures shared by [DecideTest] and [DecideFallbackTest] (spec §5.1 decision steps 1 to 6, §4
 * `Finding.Path`).
 */

/**
 * The `Finding.Path` and `PathDetail` a decision should give, set as the old one-type builder was: [noIssuerReason] and
 * [parseReason] set the path's reason by name, and a `PATH_BUDGET_EXCEEDED` with no reason set takes the one its
 * [endReason] names (`COMPLETE`: the walk completed on a chain over `FALLBACK_MAX_PRESENTED`, `FALLBACK_LIMIT`).
 */
@OptIn(RevoktTestingApi::class)
internal class PathWant {
    private var status: PathStatus? = null
    private var source = ChainSource.RECONSTRUCTED
    private var reason: PathReason? = null
    private var walkerReason: NoIssuerReason? = null
    private var keyabilityClause: KeyabilityClause? = null
    internal var terminalKind: TerminalKind? = null
        private set
    private var endReason: WalkEnd? = null
    private var endDepth: Int? = null
    private var anchorSnapshotId = WalkerHarness.SNAPSHOT_ID
    private var usedFallback = false
    private var pathsFound = 0
    private var reported: List<ByteString> = emptyList()
    private var keys: List<ByteArray> = emptyList()
    private var candidatesDropped = 0
    private var anchor: ByteArray? = null
    internal var walkStats = WalkStats(0, 0, 0, 0)

    fun status(status: PathStatus) = apply { this.status = status }

    fun source(source: ChainSource) = apply { this.source = source }

    fun reason(reason: PathReason?) = apply { this.reason = reason }

    fun noIssuerReason(reason: NoIssuerReason?) = apply { this.reason = reason?.let { PathReason.valueOf(it.name) } }

    fun parseReason(reason: ParseReason?) = apply { this.reason = reason?.let { PathReason.valueOf(it.name) } }

    fun walkerReason(reason: NoIssuerReason?) = apply { walkerReason = reason }

    fun keyabilityClause(clause: KeyabilityClause?) = apply { keyabilityClause = clause }

    fun terminalKind(kind: TerminalKind?) = apply { terminalKind = kind }

    fun endReason(end: WalkEnd?) = apply { endReason = end }

    fun endDepth(depth: Int?) = apply { endDepth = depth }

    fun anchorSnapshotId(id: Long) = apply { anchorSnapshotId = id }

    fun usedFallback(used: Boolean) = apply { usedFallback = used }

    fun pathsFound(count: Int) = apply { pathsFound = count }

    fun reportedPathSha256s(sha256s: List<ByteArray>) = apply { reported = sha256s.map { it.toByteString() } }

    fun issuerSpkiSha256s(sha256s: List<ByteArray>) = apply { keys = sha256s }

    fun candidatesDropped(count: Int) = apply { candidatesDropped = count }

    fun anchorSha256(sha256: ByteArray?) = apply { anchor = sha256 }

    fun path(): Finding.Path {
        val s = checkNotNull(status) { "status is not set" }
        val budget =
            when (endReason) {
                WalkEnd.COMPLETE, null -> PathReason.FALLBACK_LIMIT
                else -> PathReason.valueOf(endReason!!.name)
            }
        return Finding.Path
            .Builder()
            .status(s)
            .source(source)
            .reason(reason ?: budget.takeIf { s == PathStatus.PATH_BUDGET_EXCEEDED })
            .issuerSpkiSha256s(keys)
            .anchorSha256(anchor)
            .build()
    }

    fun detail(): PathDetail =
        PathDetail(
            walkerReason,
            keyabilityClause,
            endReason,
            endDepth,
            anchorSnapshotId,
            usedFallback,
            pathsFound,
            reported,
            candidatesDropped,
            walkStats,
        )
}

/** Asserts [d]'s whole `Finding.Path` and `PathDetail`: the harness's source and snapshot id, [d]'s walk stats, then [fields]. */
internal fun assertPath(
    d: PathDecision,
    at: String,
    fields: PathWant.() -> Unit,
) {
    val want = PathWant().apply { walkStats = d.detail.walkStats }.apply(fields)
    assertEquals(want.path(), d.path, at)
    assertEquals(want.detail(), d.detail, "$at: detail")
    assertEquals(want.terminalKind, d.detail.terminalKind, "$at: terminalKind")
    assertEquals(d.path.issuerSpkiSha256s.map { it.toByteString() }, d.issuerKeys, "$at: issuerKeys")
}

/** The reported path [certs], leaf → anchor, with its terminal and anchor hash. */
internal fun PathWant.reported(vararg certs: FixtureCert): PathWant =
    reportedPathSha256s(certs.map { it.bytesHash.toByteArray() })
        .terminalKind(TerminalKind.ANCHOR)
        .anchorSha256(certs.last().bytesHash.toByteArray())

internal fun PathWant.keys(vararg certs: FixtureCert): PathWant =
    issuerSpkiSha256s(
        certs.map {
            it.keyHash.toByteArray()
        },
    )

@OptIn(RevoktTestingApi::class)
internal fun notUsed(reason: FallbackReason): Finding =
    Finding.FallbackNotUsed
        .Builder()
        .reason(reason)
        .build()

@OptIn(RevoktTestingApi::class)
internal fun unsupported(depended: Boolean): Finding =
    Finding.UnsupportedAlgorithm
        .Builder()
        .oid(SymOids.UNSUPPORTED_SIGNATURE)
        .where(Layer.PATH)
        .outcomeDepended(depended)
        .build()

@OptIn(RevoktTestingApi::class)
internal fun mismatch(index: Int): Finding =
    Finding.AlgorithmIdMismatch
        .Builder()
        .certIndex(index)
        .build()

/** Counts the verifier calls of a decision. */
internal class Counting(
    private val inner: SignatureVerifier,
) : SignatureVerifier {
    var calls = 0

    override fun verify(
        sigAlg: ByteArray,
        spki: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): VerifyResult {
        calls++
        return inner.verify(sigAlg, spki, message, signature)
    }

    override fun unsupportedOids(): Set<String> = inner.unsupportedOids()
}

/** A decision on the trust-manager paths' step 3 (the `MAX_PRESENTED` cut applies), counting verifier calls. */
internal fun cutDecision(
    f: WalkerFixture,
    fallback: PathBuilderFallback?,
): Pair<PathDecision, Int> {
    var counting: Counting? = null
    val d = WalkerHarness.decide(f, fallback, harness = false) { inner -> Counting(inner).also { counting = it } }
    return d to counting!!.calls
}

internal fun garbage(size: Int): ByteArray = ByteArray(size) { 0x30 }

/** A `Validity` whose `UTCTime` has no seconds: parseable, and outside §9.2's K6 (`KeyabilityClause.TIME`). */
internal val K6_VALIDITY: ByteArray =
    TestDer.seq(
        TestDer.tlv(0x17, TestDer.ascii("5001010000Z")),
        TestDer.tlv(0x18, TestDer.ascii("20500101000000Z")),
    )

/**
 * An SCT-list extension with one item (spec §6.1, §9.2): version 0, log id `0x11`×32, [timestamp], no extensions, an
 * empty signature. Outside K8's list, so a leaf carrying it stays keyable.
 */
internal fun sctExtension(timestamp: Long = 1_780_000_000_000): ByteArray {
    val item =
        TestDer.bytes(0) + ByteArray(32) { 0x11 } + ByteArray(8) { (timestamp ushr (56 - 8 * it)).toByte() } +
            TestDer.bytes(0, 0, 4, 3, 0, 0)
    val items = TestDer.bytes(item.size shr 8, item.size and 0xff) + item
    val list = TestDer.bytes(items.size shr 8, items.size and 0xff) + items
    return TestDer.extension(Oid.SCT_LIST, TestDer.tlv(0x04, list))
}

/** [d] carries [leaf]'s `serial` and its non-empty `scts`, what step 7 queries with. */
internal fun assertLeafQuery(
    d: PathDecision,
    leaf: FixtureCert,
    at: String,
) {
    val parsed = WalkerCerts.cert(leaf.der)
    assertTrue(parsed.scts.isNotEmpty(), "$at: the leaf carries an SCT")
    assertContentEquals(parsed.serial, d.serial, "$at: serial")
    assertEquals(parsed.scts, d.scts, "$at: scts")
}
