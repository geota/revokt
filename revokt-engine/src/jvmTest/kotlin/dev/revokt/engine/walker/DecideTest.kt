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
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import dev.revokt.SignatureVerifier
import dev.revokt.TerminalKind
import dev.revokt.VerifyResult
import dev.revokt.WalkEnd
import dev.revokt.WalkStats
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.budget
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.engine.walker.FixtureWorld.Companion.TELETEX_STRING
import dev.revokt.testing.SymOids
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Decision steps 1 to 3 and the parse findings (spec §5.1 decision list, revision 50's step 6; §4's `Finding.Path` fields; §5.5; §9.2 D8),
 * over the §9 walker fixtures and small worlds of their own.
 * Steps 5 and 6 are [DecideFallbackTest]. Each test asserts the whole `Finding.Path` the outcome
 * defines, the findings, whether the fallback ran and whether its `build` threw. The fallback is a [FakeFallback]
 * (found, failed, threw, skipped) or disabled (null), as in the walker-only harness.
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class DecideTest {
    // Step 2.

    @Test
    fun `walker (x) self-signed anchor as server certificate is Found with the leaf's own key`() {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val junk = List(RevoktLimits.MAX_PRESENTED) { w.cert("J$it", w.name("Junk $it"), w.name("Junk issuer $it")) }
        val cases = listOf("alone" to listOf(root), "ahead of 64 more certificates" to listOf(root) + junk)
        cases.forEach { (case, chain) ->
            val fallback = FakeFallback.fails()
            val f = w.fixture("x", case, chain, listOf(root), notFound(NoIssuerReason.NO_CANDIDATE))
            val (d, calls) = cutDecision(f, fallback)
            assertPath(d, case) { status(PathStatus.FOUND).pathsFound(1).reported(root).keys(root) }
            assertNull(d.path.endReason, case)
            assertEquals(WalkStats(0, 0, 0, 0), d.path.walkStats, case)
            assertEquals(emptyList(), d.findings, case)
            assertEquals(0, calls, "$case: no walk")
            assertEquals(0, fallback.calls, "$case: no fallback")
            assertContentEquals(WalkerCerts.cert(root.der).serial, d.serial, case)
            assertFalse(d.buildThrew, case)
        }
    }

    @Test
    fun `step 2 decides before step 3 for an anchor leaf outside the keyability profile`() {
        val w = FixtureWorld()
        val name = w.name("Unkeyable root")
        val key = w.key()
        val root = w.cert("R", name, name, key, signer = key)
        assertEquals(KeyabilityClause.KEY, WalkerCerts.cert(root.der).keyabilityClause)
        val d =
            WalkerHarness.decide(
                w.fixture("x", "", listOf(root), listOf(root), notFound(NoIssuerReason.NO_CANDIDATE)),
                null,
            )
        assertPath(d, "unkeyable anchor leaf") { status(PathStatus.FOUND).pathsFound(1).reported(root).keys(root) }
    }

    // Step 3.

    @Test
    fun `step 3 checks MAX_CERT_BYTES before the parse`() {
        listOf(
            "over the cap" to (RevoktLimits.MAX_CERT_BYTES + 1 to ParseReason.OVERSIZE),
            "at the cap" to (RevoktLimits.MAX_CERT_BYTES to ParseReason.STRUCTURE),
            "short" to (3 to ParseReason.STRUCTURE),
        ).forEach { (case, input) ->
            val (size, reason) = input
            val h = Honest()
            val fallback = FakeFallback.fails()
            val f = h.fixture("step3", case, listOf(h.leaf), notFound(NoIssuerReason.NO_CANDIDATE))
            val presented = listOf(garbage(size), h.intermediate.der)
            val d = WalkerHarness.decide(WalkerFixture(f.id, case, presented, f.snapshot, f.ok, f.walk), fallback)
            assertPath(d, case) { status(PathStatus.PARSE_FAILED).parseReason(reason) }
            assertNull(d.serial, case)
            assertEquals(emptyList(), d.scts, case)
            assertEquals(emptyList(), d.findings, case)
            assertEquals(0, fallback.calls, case)
        }
    }

    @Test
    fun `a K6 leaf is PRODUCER_UNKEYABLE with clause TIME and never walked, and an unkeyable issuer is not dropped`() {
        // §9 Rule model item (the verdict half, crlite == null, is #133's): UTCTime without seconds fails K6.
        with(Honest()) {
            val leaf6 =
                w.withValidity(K6_VALIDITY) {
                    w.cert(
                        "L6",
                        w.name("leaf.example"),
                        intermediate.subject,
                        signer = intermediate.key,
                        key = w.leafKey(),
                    )
                }
            assertEquals(KeyabilityClause.TIME, WalkerCerts.cert(leaf6.der).keyabilityClause)
            val fallback = FakeFallback.finds(leaf6, intermediate, root)
            val (d, calls) =
                cutDecision(
                    fixture("k6", "leaf", listOf(leaf6, intermediate), notFound(NoIssuerReason.NO_CANDIDATE)),
                    fallback,
                )
            assertPath(d, "K6 leaf") {
                status(
                    PathStatus.PARSE_FAILED,
                ).parseReason(ParseReason.PRODUCER_UNKEYABLE).keyabilityClause(KeyabilityClause.TIME)
            }
            assertEquals(0, calls, "never walked")
            assertEquals(0, fallback.calls, "no fallback")
            assertNull(d.serial, "never queried")
            assertEquals(emptyList(), d.findings)
        }
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val i6 = w.withValidity(K6_VALIDITY) { w.cert("I6", w.name("Intermediate"), root.subject, signer = root.key) }
        val leaf = w.cert("L", w.name("leaf.example"), i6.subject, signer = i6.key, key = w.leafKey())
        assertEquals(KeyabilityClause.TIME, WalkerCerts.cert(i6.der).keyabilityClause)
        val d =
            WalkerHarness.decide(
                w.fixture("k6", "issuer", listOf(leaf, i6), listOf(root), notFound(NoIssuerReason.NO_CANDIDATE)),
                null,
            )
        assertPath(d, "K6 issuer") {
            status(PathStatus.FOUND)
                .endReason(WalkEnd.COMPLETE)
                .pathsFound(1)
                .reported(leaf, i6, root)
                .keys(i6)
        }
    }

    @Test
    fun `walker (ag) more than MAX_PRESENTED certificates is EXPLORATION_BUDGET at endDepth 0 without a walk`() {
        val sizes = listOf(RevoktLimits.MAX_PRESENTED to false, RevoktLimits.MAX_PRESENTED + 1 to true, 70 to true)
        sizes.forEach { (size, cut) ->
            with(Honest()) {
                val presented = listOf(leaf) + junk(size - 2) + intermediate
                val fallback = FakeFallback.fails()
                val f = fixture("ag", "$size presented", presented, notFound(NoIssuerReason.NO_CANDIDATE))
                val (d, calls) = cutDecision(f, fallback)
                val at = "$size presented"
                if (cut) {
                    assertPath(d, at) {
                        status(PathStatus.PATH_BUDGET_EXCEEDED).endReason(WalkEnd.EXPLORATION_BUDGET).endDepth(0)
                    }
                    assertEquals(0, calls, "$at: no walk")
                    assertEquals(emptyList(), d.findings, "$at: no FallbackNotUsed")
                    assertContentEquals(WalkerCerts.cert(leaf.der).serial, d.serial, at)
                } else {
                    assertEquals(PathStatus.FOUND, d.path.status, at)
                }
                assertEquals(0, fallback.calls, at)
            }
        }
    }

    @Test
    fun `MAX_PRESENTED_BYTES counts the raw chain before any candidate is dropped`() {
        listOf(0L to false, 1L to true).forEach { (over, cut) ->
            with(Honest()) {
                val head = leaf.der.size + intermediate.der.size
                val rest = RevoktLimits.MAX_PRESENTED_BYTES + over - head
                val blobs = List(4) { n -> garbage((rest / 4 + if (n < rest % 4) 1 else 0).toInt()) }
                val presented = listOf(leaf.der, intermediate.der) + blobs
                assertEquals(RevoktLimits.MAX_PRESENTED_BYTES + over, presented.sumOf { it.size.toLong() })
                val f = fixture("bytes", "", listOf(leaf), notFound(NoIssuerReason.NO_CANDIDATE))
                val d =
                    WalkerHarness.decide(
                        WalkerFixture("bytes", "", presented, f.snapshot, f.ok, f.walk),
                        null,
                        harness = false,
                    )
                if (cut) {
                    assertPath(d, "over") {
                        status(PathStatus.PATH_BUDGET_EXCEEDED).endReason(WalkEnd.EXPLORATION_BUDGET).endDepth(0)
                    }
                } else {
                    assertPath(d, "at the cap") {
                        status(PathStatus.FOUND)
                            .endReason(WalkEnd.COMPLETE)
                            .pathsFound(1)
                            .reported(*path.toTypedArray())
                            .keys(intermediate)
                            .candidatesDropped(4)
                    }
                }
            }
        }
    }

    @Test
    fun `the leaf's checks precede the MAX_PRESENTED cut`() {
        with(Honest()) {
            val presented = listOf(garbage(10)) + (junk(68) + intermediate).map { it.der }
            val f = fixture("cut", "", listOf(leaf), notFound(NoIssuerReason.NO_CANDIDATE))
            val d =
                WalkerHarness.decide(
                    WalkerFixture("cut", "", presented, f.snapshot, f.ok, f.walk),
                    null,
                    harness = false,
                )
            assertPath(
                d,
                "unparseable leaf of 70",
            ) { status(PathStatus.PARSE_FAILED).parseReason(ParseReason.STRUCTURE) }
            // A leaf outside the keyability profile is PRODUCER_UNKEYABLE before the cut, too.
            val leaf6 =
                w.withValidity(K6_VALIDITY) {
                    w.cert("L6", w.name("leaf.example"), intermediate.subject, key = w.leafKey())
                }
            val g = fixture("cut", "K6", listOf(leaf6) + junk(68) + intermediate, notFound(NoIssuerReason.NO_CANDIDATE))
            val d6 = WalkerHarness.decide(g, null, harness = false)
            assertEquals(ParseReason.PRODUCER_UNKEYABLE, d6.path.parseReason, "K6 leaf of 70")
        }
    }

    @Test
    fun `the walk's VerifierError findings ride on every walked exit`() {
        val f = WalkerFixturesS1ToAj.ae().single()
        val throwing = { _: SignatureVerifier ->
            object : SignatureVerifier {
                override fun verify(
                    sigAlg: ByteArray,
                    spki: ByteArray,
                    message: ByteArray,
                    signature: ByteArray,
                ): VerifyResult = error("boom")

                override fun unsupportedOids(): Set<String> = emptySet()
            }
        }
        val d = WalkerHarness.decide(f, FakeFallback.fails(), verifier = throwing)
        assertEquals(PathStatus.NO_ISSUER, d.path.status)
        assertEquals(NoIssuerReason.ALL_CANDIDATES_INVALID, d.path.walkerReason)
        val errors = d.findings.filterIsInstance<Finding.VerifierError>()
        assertEquals(listOf(SymOids.SIGNATURE), errors.map { it.oid })
        assertEquals(notUsed(FallbackReason.FAILED), d.findings.last())
    }

    @Test
    fun `an unparseable candidate is dropped and counted, and AlgorithmIdMismatch keeps the presented index`() {
        with(Honest()) {
            val outer = TestDer.seq(TestDer.oid("1.3.6.1.4.1.99999.91.99"))
            val mismatched = w.withOuterAlgorithm(intermediate, outer)
            val presented = listOf(leaf.der, garbage(40), mismatched.der)
            val f = fixture("drop", "", listOf(leaf), notFound(NoIssuerReason.NO_CANDIDATE))
            val d = WalkerHarness.decide(WalkerFixture("drop", "", presented, f.snapshot, f.ok, f.walk), null)
            assertPath(d, "dropped") {
                status(PathStatus.FOUND)
                    .endReason(WalkEnd.COMPLETE)
                    .pathsFound(1)
                    .reported(leaf, mismatched, root)
                    .keys(intermediate)
                    .candidatesDropped(1)
            }
            assertEquals(listOf(mismatch(2)), d.findings)
        }
    }
}
