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
 * Decision steps 1 to 6 (spec §5.1 decision list, revision 50's step 6; §4's `Finding.Path` fields; §5.5; §9.2 D8),
 * over the §9 walker fixtures and small worlds of their own. Each test asserts the whole `Finding.Path` the outcome
 * defines, the findings, whether the fallback ran and whether its `build` threw. The fallback is a [FakeFallback]
 * (found, failed, threw, skipped) or disabled (null), as in the walker-only harness.
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class DecideTest {
    /** Asserts [d]'s whole `Finding.Path`: the harness's source and snapshot id, [d]'s walk stats, then [fields]. */
    private fun assertPath(
        d: PathDecision,
        at: String,
        fields: Finding.Path.Builder.() -> Unit,
    ) {
        val want =
            Finding.Path
                .Builder()
                .source(ChainSource.RECONSTRUCTED)
                .anchorSnapshotId(WalkerHarness.SNAPSHOT_ID)
                .walkStats(d.path.walkStats)
                .apply(fields)
                .build()
        assertEquals(want, d.path, at)
        assertEquals(d.path.issuerSpkiSha256s.map { it.toByteString() }, d.issuerKeys, "$at: issuerKeys")
    }

    /** The reported path [certs], leaf → anchor, with its terminal and anchor hash. */
    private fun Finding.Path.Builder.reported(vararg certs: FixtureCert): Finding.Path.Builder =
        reportedPathSha256s(certs.map { it.bytesHash.toByteArray() })
            .terminalKind(TerminalKind.ANCHOR)
            .anchorSha256(certs.last().bytesHash.toByteArray())

    private fun Finding.Path.Builder.keys(vararg certs: FixtureCert): Finding.Path.Builder =
        issuerSpkiSha256s(certs.map { it.keyHash.toByteArray() })

    private fun notUsed(reason: FallbackReason): Finding =
        Finding.FallbackNotUsed
            .Builder()
            .reason(reason)
            .build()

    private fun unsupported(depended: Boolean): Finding =
        Finding.UnsupportedAlgorithm
            .Builder()
            .oid(SymOids.UNSUPPORTED_SIGNATURE)
            .where(Layer.PATH)
            .outcomeDepended(depended)
            .build()

    private fun mismatch(index: Int): Finding =
        Finding.AlgorithmIdMismatch
            .Builder()
            .certIndex(index)
            .build()

    /** Counts the verifier calls of a decision. */
    private class Counting(
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
    private fun cutDecision(
        f: WalkerFixture,
        fallback: PathBuilderFallback?,
    ): Pair<PathDecision, Int> {
        var counting: Counting? = null
        val d = WalkerHarness.decide(f, fallback, harness = false) { inner -> Counting(inner).also { counting = it } }
        return d to counting!!.calls
    }

    private fun garbage(size: Int): ByteArray = ByteArray(size) { 0x30 }

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
        val k6 =
            TestDer.seq(
                TestDer.tlv(0x17, TestDer.ascii("5001010000Z")),
                TestDer.tlv(0x18, TestDer.ascii("20500101000000Z")),
            )
        with(Honest()) {
            val leaf6 =
                w.cert(
                    "L6",
                    w.name("leaf.example"),
                    intermediate.subject,
                    signer = intermediate.key,
                    key = w.leafKey(),
                    validity = k6,
                )
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
        val i6 = w.cert("I6", w.name("Intermediate"), root.subject, signer = root.key, validity = k6)
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
        }
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

    // Step 5.

    @Test
    fun `a walk Found is final, the fallback never runs, and the first issuer key is the reported path's`() {
        val rows = WalkerFixturesAToR.o() + WalkerFixturesAToR.k()
        for (f in rows) {
            val fallback = FakeFallback.fails()
            val d = WalkerHarness.decide(f, fallback)
            val walk = WalkerHarness.walk(f) as Walk.Found
            assertPath(d, f.toString()) {
                status(PathStatus.FOUND)
                    .endReason(WalkEnd.COMPLETE)
                    .pathsFound(walk.paths.size)
                    .reportedPathSha256s(walk.paths[0].certs.map { it.bytesHash.toByteArray() })
                    .terminalKind(TerminalKind.ANCHOR)
                    .anchorSha256(
                        walk.paths[0]
                            .certs
                            .last()
                            .bytesHash
                            .toByteArray(),
                    ).issuerSpkiSha256s(walk.leafKeys.map { it.toByteArray() })
            }
            assertEquals(walk.paths[0].certs[1].spkiHash, d.issuerKeys[0], "$f: first key")
            assertEquals(0, fallback.calls, f.toString())
            assertEquals(emptyList(), d.findings, f.toString())
            assertContentEquals(WalkerCerts.cert(f.presented[0]).serial, d.serial, f.toString())
        }
        // (o): the attacker sub-CA's path is first, so its key leads.
        assertEquals(2, WalkerHarness.decide(WalkerFixturesAToR.o()[0], null).issuerKeys.size)
    }

    @Test
    fun `walker (r) the algorithm mismatch finding comes from the parser's flag`() {
        val (oid, nullAbsent) = WalkerFixturesAToR.r()
        assertEquals(listOf(mismatch(0)), WalkerHarness.decide(oid, null).findings)
        assertEquals(emptyList(), WalkerHarness.decide(nullAbsent, null).findings)
    }

    @Test
    fun `walker (n) an unsupported OID on a Found is reported with outcomeDepended false`() {
        for (f in WalkerFixturesAToR.n() + WalkerFixturesAToR.d()) {
            val d = WalkerHarness.decide(f, FakeFallback.fails())
            assertEquals(PathStatus.FOUND, d.path.status, f.toString())
            assertEquals(listOf(unsupported(false)), d.findings, f.toString())
        }
    }

    // Step 6, walk NotFound.

    @Test
    fun `walker (ae) fallback failed is NO_ISSUER with the walker's reason, PLATFORM_ONLY on a binding`() {
        val f = WalkerFixturesS1ToAj.ae().single()
        listOf(false, true).forEach { platformOnly ->
            val fallback = FakeFallback.fails()
            val d = WalkerHarness.decide(f, fallback, platformOnly = platformOnly)
            val at = "platformOnly=$platformOnly"
            assertPath(d, at) {
                status(PathStatus.NO_ISSUER)
                    .noIssuerReason(if (platformOnly) NoIssuerReason.PLATFORM_ONLY else NoIssuerReason.UNANCHORED)
                    .walkerReason(NoIssuerReason.UNANCHORED)
                    .endReason(WalkEnd.COMPLETE)
            }
            assertEquals(listOf(notUsed(FallbackReason.FAILED)), d.findings, at)
            assertEquals(1, fallback.calls, at)
            assertFalse(d.buildThrew, at)
        }
    }

    @Test
    fun `a throwing build is a failed fallback that is cached nowhere, and a fatal error propagates`() {
        val f = WalkerFixturesS1ToAj.ae().single()
        listOf(IllegalStateException("x"), StackOverflowError(), NotImplementedError(), AssertionError()).forEach { t ->
            val d = WalkerHarness.decide(f, FakeFallback.throws(t))
            val at = t::class.simpleName.orEmpty()
            assertPath(d, at) {
                status(PathStatus.NO_ISSUER)
                    .noIssuerReason(NoIssuerReason.UNANCHORED)
                    .walkerReason(NoIssuerReason.UNANCHORED)
                    .endReason(WalkEnd.COMPLETE)
            }
            assertEquals(listOf(notUsed(FallbackReason.FAILED)), d.findings, at)
            assertTrue(d.buildThrew, at)
        }
        assertFailsWith<OutOfMemoryError> { WalkerHarness.decide(f, FakeFallback.throws(OutOfMemoryError())) }
        assertFailsWith<InternalError> { WalkerHarness.decide(f, FakeFallback.throws(InternalError())) }
    }

    @Test
    fun `walk NotFound and a fallback path is Found with usedFallback and the fallback key`() {
        with(Honest()) {
            val fake = w.cert("F", intermediate.subject, w.name("Attacker"))
            w.verifies(leaf, fake.key)
            val f = fixture("fb", presented = listOf(leaf, fake), walk = notFound(NoIssuerReason.UNANCHORED))
            val fallback = FakeFallback.finds(leaf, intermediate, root)
            val d = WalkerHarness.decide(f, fallback, platformOnly = true)
            assertPath(d, "fallback found") {
                status(PathStatus.FOUND)
                    .walkerReason(NoIssuerReason.UNANCHORED)
                    .endReason(WalkEnd.COMPLETE)
                    .usedFallback(true)
                    .pathsFound(1)
                    .reported(leaf, intermediate, root)
                    .keys(intermediate)
            }
            assertEquals(emptyList(), d.findings)
            val (chain, snapshot, now) = fallback.seen!!
            assertEquals(
                f.presented.map { it.toByteString() },
                chain.map { it.toByteString() },
                "the raw presented chain",
            )
            assertEquals(WalkerHarness.SNAPSHOT_ID, snapshot.id)
            assertEquals(WalkerHarness.NOW, now)

            // The leaf alone is keyed by its own SPKI; an empty path or an unparseable issuer is a failed fallback.
            val alone = WalkerHarness.decide(f, FakeFallback.finds(leaf))
            assertEquals(listOf(leaf.keyHash), alone.issuerKeys)
            assertTrue(alone.path.usedFallback)
            for ((case, answer) in listOf(
                "empty" to emptyList(),
                "unparseable issuer" to listOf(leaf.der, garbage(9)),
            )) {
                val d2 = WalkerHarness.decide(f, FakeFallback { answer })
                assertEquals(PathStatus.NO_ISSUER, d2.path.status, case)
                assertEquals(listOf(notUsed(FallbackReason.FAILED)), d2.findings, case)
            }

            // The builder gets copies: changing them leaves the caller's chain as it was.
            val before = f.presented.map { it.copyOf() }
            WalkerHarness.decide(f, FakeFallback { chain2 -> chain2.forEach { it.fill(0) }.let { null } })
            assertEquals(before.map { it.toByteString() }, f.presented.map { it.toByteString() })
        }
    }

    @Test
    fun `ISSUER_UNVERIFIED needs the child's own signature OID unsupported against a related candidate`() {
        with(Honest()) {
            val leafU =
                w.cert(
                    "LU",
                    w.name("leaf.example"),
                    intermediate.subject,
                    sigOid = SymOids.UNSUPPORTED_SIGNATURE,
                    key = w.leafKey(),
                )
            w.verifies(leafU, intermediate.key)
            val f =
                fixture(
                    "iu",
                    presented = listOf(leafU, intermediate),
                    walk = notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                )
            val fallbacks = listOf(FakeFallback.fails() to FallbackReason.FAILED, null to FallbackReason.DISABLED)
            fallbacks.forEach { (fallback, reason) ->
                listOf(false, true).forEach { platformOnly ->
                    val at = "$reason platformOnly=$platformOnly"
                    val d = WalkerHarness.decide(f, fallback, platformOnly = platformOnly)
                    assertPath(d, at) {
                        status(PathStatus.ISSUER_UNVERIFIED)
                            .walkerReason(NoIssuerReason.ALL_CANDIDATES_INVALID)
                            .endReason(WalkEnd.COMPLETE)
                    }
                    assertEquals(listOf(unsupported(true), notUsed(reason)), d.findings, at)
                }
            }
            // Over FALLBACK_MAX_PRESENTED the chain length decides first: PATH_BUDGET_EXCEEDED, the OID reported.
            val fillers = List(7) { w.cert("F$it", w.name("Filler $it"), w.name("Filler issuer $it")) }
            val long =
                fixture(
                    "iu",
                    "9 presented",
                    listOf(leafU, intermediate) + fillers,
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                )
            val skipped = WalkerHarness.decide(long, FakeFallback.fails())
            assertPath(skipped, "9 presented") {
                status(PathStatus.PATH_BUDGET_EXCEEDED)
                    .walkerReason(NoIssuerReason.ALL_CANDIDATES_INVALID)
                    .endReason(WalkEnd.COMPLETE)
            }
            assertEquals(listOf(unsupported(false), notUsed(FallbackReason.SKIPPED)), skipped.findings)
            // A related candidate's own key OID is server-chosen and never relabels NO_ISSUER.
            val decoy =
                w.cert(
                    "D",
                    intermediate.subject,
                    root.subject,
                    w.key(SymOids.UNSUPPORTED_KEY),
                    signer = root.key,
                )
            val g = fixture("iu", "decoy", listOf(leaf, decoy), notFound(NoIssuerReason.ALL_CANDIDATES_INVALID))
            val d = WalkerHarness.decide(g, FakeFallback.fails())
            assertPath(d, "unsupported key decoy") {
                status(PathStatus.NO_ISSUER)
                    .noIssuerReason(NoIssuerReason.ALL_CANDIDATES_INVALID)
                    .walkerReason(NoIssuerReason.ALL_CANDIDATES_INVALID)
                    .endReason(WalkEnd.COMPLETE)
            }
            assertEquals(listOf(notUsed(FallbackReason.FAILED)), d.findings)
        }
        // (z): an unrelated unsupported key OID records nothing either.
        val z = WalkerHarness.decide(WalkerFixturesS1ToAj.z().single(), FakeFallback.fails())
        assertEquals(PathStatus.NO_ISSUER, z.path.status)
        assertEquals(listOf(notUsed(FallbackReason.FAILED)), z.findings)
    }

    @Test
    fun `walker (af) 9 presented and NotFound is PATH_BUDGET_EXCEEDED, SKIPPED or with the fallback off DISABLED`() {
        val f = WalkerFixturesS1ToAj.af().single()
        assertEquals(9, f.presented.size)
        val fallbacks = listOf(FakeFallback.finds() to FallbackReason.SKIPPED, null to FallbackReason.DISABLED)
        fallbacks.forEach { (fallback, reason) ->
            listOf(false, true).forEach { platformOnly ->
                listOf(true, false).forEach { harness ->
                    val at = "$reason platformOnly=$platformOnly harness=$harness"
                    val d = WalkerHarness.decide(f, fallback, platformOnly = platformOnly, harness = harness)
                    assertPath(d, at) {
                        status(PathStatus.PATH_BUDGET_EXCEEDED)
                            .walkerReason(NoIssuerReason.UNANCHORED)
                            .endReason(WalkEnd.COMPLETE)
                    }
                    assertEquals(listOf(notUsed(reason)), d.findings, at)
                }
            }
            assertEquals(0, fallback?.calls ?: 0, "a skipped fallback is never called")
        }
    }

    @Test
    fun `FALLBACK_MAX_PRESENTED presented certificates still run the fallback`() {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val i = w.cert("I", w.name("Intermediate"), root.subject)
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
        val fillers =
            List(
                RevoktLimits.FALLBACK_MAX_PRESENTED - 2,
            ) { w.cert("F$it", w.name("Filler $it"), w.name("Filler issuer $it")) }
        val f =
            w.fixture(
                "af",
                "8 presented",
                listOf(leaf, i) + fillers,
                listOf(root),
                notFound(NoIssuerReason.UNANCHORED),
            )
        val fallback = FakeFallback.fails()
        val d = WalkerHarness.decide(f, fallback)
        assertEquals(1, fallback.calls)
        assertEquals(PathStatus.NO_ISSUER, d.path.status)
        assertEquals(listOf(notUsed(FallbackReason.FAILED)), d.findings)
    }

    @Test
    fun `fallback disabled and NotFound within FALLBACK_MAX_PRESENTED is NO_ISSUER, PLATFORM_ONLY on a binding`() {
        val f = WalkerFixturesS1ToAj.ae().single()
        listOf(false, true).forEach { platformOnly ->
            val d = WalkerHarness.decide(f, null, platformOnly = platformOnly)
            assertPath(d, "platformOnly=$platformOnly") {
                status(PathStatus.NO_ISSUER)
                    .noIssuerReason(if (platformOnly) NoIssuerReason.PLATFORM_ONLY else NoIssuerReason.UNANCHORED)
                    .walkerReason(NoIssuerReason.UNANCHORED)
                    .endReason(WalkEnd.COMPLETE)
            }
            assertEquals(listOf(notUsed(FallbackReason.DISABLED)), d.findings)
        }
    }

    // Step 6, walk Budget.

    /**
     * (ad)'s shape for decide: the honest I unrelated to the leaf by encoding, six same-name, mutually cross-signing
     * junk ahead, `Budget(EXPLORATION_BUDGET)`. The harness row (ad) puts the TeletexString on the leaf's issuer and an
     * issuer-and-serial AKI on the leaf, which §9.2's K5 and K8 put outside the keyability profile, so through decide
     * that leaf is `PARSE_FAILED(PRODUCER_UNKEYABLE)`. Here the TeletexString is I's subject and the leaf has no AKI,
     * which keeps the leaf keyable and the relation test name-only.
     */
    private fun adShape(): Pair<WalkerFixture, Honest> {
        val w = FixtureWorld()
        val h =
            Honest(w, leafIssuer = w.name("Intermediate"), intermediateSubject = w.name("Intermediate", TELETEX_STRING))
        val name = w.name("Intermediate")
        val keys = List(6) { w.key() }
        val junk = keys.mapIndexed { n, k -> w.cert("J$n", name, name, k) }
        for ((n, j) in junk.withIndex()) {
            w.verifies(h.leaf, j.key)
            keys.forEachIndexed { m, k -> if (m != n) w.verifies(j, k) }
        }
        val walk = budget(WalkEnd.EXPLORATION_BUDGET, endDepth = 7).copy(candidatesExplored = RevoktLimits.MAX_EXPLORED)
        val f =
            w.fixture(
                "ad",
                "decide",
                listOf(h.leaf) + junk + h.intermediate,
                listOf(h.root),
                walk,
                customCanonicaliser = true,
            )
        WalkerHarness.check(f)
        return f to h
    }

    @Test
    fun `walker (ad) Budget with a fallback path appends the honest key last, and none with the fallback off`() {
        val (f, h) = adShape()
        assertEquals(RevoktLimits.FALLBACK_MAX_PRESENTED, f.presented.size)
        val fallback = FakeFallback.finds(*h.path.toTypedArray())
        val d = WalkerHarness.decide(f, fallback, platformOnly = true)
        assertPath(d, "enabled") {
            status(PathStatus.PATH_BUDGET_EXCEEDED)
                .endReason(WalkEnd.EXPLORATION_BUDGET)
                .endDepth(7)
                .usedFallback(true)
                .reported(*h.path.toTypedArray())
                .keys(h.intermediate)
        }
        assertEquals(RevoktLimits.MAX_EXPLORED, d.path.walkStats.candidatesExplored)
        assertEquals(emptyList(), d.findings)
        assertEquals(1, fallback.calls)
        listOf(null to FallbackReason.DISABLED, FakeFallback.fails() to FallbackReason.FAILED).forEach { (fb, reason) ->
            val off = WalkerHarness.decide(f, fb, platformOnly = true)
            assertPath(off, "$reason") {
                status(PathStatus.PATH_BUDGET_EXCEEDED).endReason(WalkEnd.EXPLORATION_BUDGET).endDepth(7)
            }
            assertEquals(listOf(notUsed(reason)), off.findings, "$reason")
        }
        val threw = WalkerHarness.decide(f, FakeFallback.throws(IllegalStateException()))
        assertEquals(PathStatus.PATH_BUDGET_EXCEEDED, threw.path.status)
        assertEquals(listOf(notUsed(FallbackReason.FAILED)), threw.findings)
        assertTrue(threw.buildThrew)
    }

    @Test
    fun `harness rows with a TeletexString leaf issuer and an issuer-and-serial AKI are unkeyable in decide`() {
        // Pins the reason adShape exists: on every path through decide, (ac) and (ad) as the harness writes them stop
        // at step 3.
        for (f in WalkerFixturesS1ToAj.ac() + WalkerFixturesS1ToAj.ad()) {
            val d = WalkerHarness.decide(f, null)
            assertEquals(ParseReason.PRODUCER_UNKEYABLE, d.path.parseReason, f.toString())
        }
    }

    @Test
    fun `Budget keys are the partial keys then the fallback key if new, and the reported path is the partial one`() {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val name = w.name("Intermediate")
        val sub = w.cert("S", name, root.subject, signer = root.key)
        val honest = w.cert("H", name, root.subject, signer = root.key)
        val leaf = w.cert("L", w.name("leaf.example"), name, signer = sub.key, key = w.leafKey())
        w.verifies(leaf, honest.key)
        // 64 store anchors named like the leaf's issuer: with S they are 65 related candidates at the leaf.
        val junk = List(RevoktLimits.MAX_RELATED_PER_LEVEL) { w.cert("A$it", name, w.name("Junk issuer $it")) }
        val f = w.fixture("budget", "", listOf(leaf, sub), listOf(root) + junk, notFound(NoIssuerReason.UNANCHORED))
        val cases =
            listOf(
                Triple("new key", FakeFallback.finds(leaf, honest, root) as PathBuilderFallback?, listOf(sub, honest)),
                Triple("same key", FakeFallback.finds(leaf, sub, root), listOf(sub)),
                Triple("failed", FakeFallback.fails(), listOf(sub)),
                Triple("disabled", null, listOf(sub)),
            )
        for ((case, fallback, keys) in cases) {
            val d = WalkerHarness.decide(f, fallback)
            val used = fallback is FakeFallback && case != "failed"
            assertPath(d, case) {
                status(PathStatus.PATH_BUDGET_EXCEEDED)
                    .endReason(WalkEnd.RELATED_BUDGET)
                    .endDepth(1)
                    .usedFallback(used)
                    .pathsFound(1)
                    .reported(leaf, sub, root)
                    .keys(*keys.toTypedArray())
            }
            val reason = if (fallback == null) FallbackReason.DISABLED else FallbackReason.FAILED
            assertEquals(if (used) emptyList() else listOf(notUsed(reason)), d.findings, case)
        }
    }

    @Test
    fun `walker (i) the harness walks a chain over MAX_PRESENTED, and its fallback is SKIPPED or DISABLED`() {
        val f = WalkerFixturesAToR.i().single()
        assertTrue(f.presented.size > RevoktLimits.MAX_PRESENTED)
        val fallbacks = listOf(FakeFallback.finds() to FallbackReason.SKIPPED, null to FallbackReason.DISABLED)
        fallbacks.forEach { (fallback, reason) ->
            val d = WalkerHarness.decide(f, fallback)
            assertPath(d, "$reason") {
                status(PathStatus.PATH_BUDGET_EXCEEDED).endReason(WalkEnd.RELATED_BUDGET).endDepth(1)
            }
            assertEquals(listOf(notUsed(reason)), d.findings)
            assertEquals(0, fallback?.calls ?: 0)
        }
        // On every trust-manager path the same chain is cut at step 3.
        val (cut, calls) = cutDecision(f, FakeFallback.fails())
        assertEquals(WalkEnd.EXPLORATION_BUDGET, cut.path.endReason)
        assertEquals(0, cut.path.endDepth)
        assertEquals(0, calls)
        assertEquals(emptyList(), cut.findings)
    }

    @Test
    fun `decide requires the leaf`() {
        val f = WalkerFixturesS1ToAj.ae().single()
        assertFailsWith<IllegalArgumentException> {
            WalkerHarness.decide(WalkerFixture("empty", "", emptyList(), f.snapshot, f.ok, f.walk), null)
        }
    }
}
