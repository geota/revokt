// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.WalkEnd
import dev.revokt.engine.walker.ExpectedWalk.Companion.budget
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.engine.walker.Honest
import dev.revokt.testing.SymOids
import dev.revokt.testing.SymVerifier
import okio.ByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame

/**
 * Spec §5.1 `reconstruct` beyond the §9 rows: each budget at N and N + 1, the memos, the `UNSUPPORTED` rule, the leaf
 * rules for unrelated candidates, the `NoIssuerReason` flags and the never-throw rule for verifiers (§5.5).
 */
@OptIn(RevoktInternalApi::class)
class ReconstructTest {
    /** [verifier] over [f]'s rows, counting its calls. */
    private class Counting(
        private val inner: SignatureVerifier,
    ) : SignatureVerifier by inner {
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
    }

    private fun walk(
        f: WalkerFixture,
        verifier: SignatureVerifier = SymVerifier(f.ok, f.unsupported),
        probe: Set<String> = verifier.unsupportedOids(),
        memo: LruMap<Pair<ByteString, ByteString>, VerifyResult> = LruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
    ): Walk {
        val index = CandidateIndex(f.snapshot, customCanonicaliser = f.customCanonicaliser)
        return reconstruct(f.presented.map { index.cert(WalkerCerts.parse(it)) }, index, verifier, probe, memo)
    }

    private fun check(
        f: WalkerFixture,
        walk: Walk = walk(f),
    ): Walk = walk.also { WalkerHarness.check(f.walk, it, f.label, f.toString()) }

    /**
     * leaf → I1 → … → I4 → R with `junk[k]` certificates named like node k's issuer ahead of it (node 0 is the leaf): a
     * walk that costs `sum(junk) + 5` verifications and as many explorations.
     */
    private fun levels(junk: List<Int>): Pair<Deep, List<FixtureCert>> {
        val d = Deep(4)
        val nodes = listOf(d.leaf) + d.intermediates
        val presented = mutableListOf(d.leaf)
        for ((k, n) in junk.withIndex()) {
            presented += List(n) { d.w.cert("J$k.$it", d.intermediates[k].subject, d.w.name("Junk issuer $k.$it")) }
            presented += nodes[k + 1]
        }
        return d to presented
    }

    @Test
    fun `walker MAX_VERIFICATIONS completes at 256 verifier calls and aborts at the 257th`() {
        // 251 junk: 256 verifications, Found.
        val (d256, at256) = levels(listOf(63, 63, 63, 62))
        val f256 = d256.w.fixture("budget", "256", at256, listOf(d256.root), found(d256.path).copy(verifications = 256))
        check(f256)
        // 252 junk: the last link, I4/R, is the 257th; it is explored but not verified, at the path size of I4.
        val (d257, at257) = levels(listOf(63, 63, 63, 63))
        val f257 =
            d257.w.fixture(
                "budget",
                "257",
                at257,
                listOf(d257.root),
                budget(WalkEnd.VERIFICATION_BUDGET, 5).copy(verifications = 256, candidatesExplored = 257),
            )
        check(f257)
    }

    /**
     * The leaf's issuer is absent, so every presented certificate is unrelated and explored (uncapped, revision 48):
     * [junk] of them share one key (one verification, then memo hits) ahead of U, an unrelated issuer under the root.
     */
    private fun unrelatedAtLeaf(junk: Int): Pair<Honest, List<FixtureCert>> {
        val h = Honest(leafIssuer = FixtureWorld().name("Missing issuer"))
        val shared = h.w.key()
        val js = List(junk) { h.w.cert("J$it", h.w.name("Junk $it"), h.w.name("Junk issuer"), shared) }
        return h to listOf(h.leaf) + js + h.intermediate
    }

    @Test
    fun `walker MAX_EXPLORED completes at 1024 explorations and aborts at the 1025th`() {
        val (h1024, p1024) = unrelatedAtLeaf(RevoktLimits.MAX_EXPLORED - 2)
        check(
            h1024.fixture(
                "budget",
                "1024",
                p1024,
                found(h1024.path).copy(verifications = 3, candidatesExplored = 1024, unrelatedExploredAtLeaf = 1023),
            ),
        )
        // One more junk: I/R would be the 1025th exploration, detected at I (path size 2).
        val (h1025, p1025) = unrelatedAtLeaf(RevoktLimits.MAX_EXPLORED - 1)
        check(
            h1025.fixture(
                "budget",
                "1025",
                p1025,
                budget(WalkEnd.EXPLORATION_BUDGET, 2).copy(verifications = 2, candidatesExplored = 1024),
            ),
        )
    }

    @Test
    fun `walker the related cap applies at the leaf after a path was found and keeps it as partial`() {
        with(Honest()) {
            check(
                fixture(
                    "cap",
                    presented = listOf(leaf, intermediate) + junk(RevoktLimits.MAX_RELATED_PER_LEVEL),
                    walk =
                        budget(WalkEnd.RELATED_BUDGET, 1, path).copy(
                            verifications = 65,
                            relatedExploredAtLeaf = 64,
                        ),
                ),
            )
        }
    }

    @Test
    fun `walker below the leaf a found path ends the related loop before the cap is reached`() {
        val d = Deep(2)
        val (i1, i2) = d.intermediates
        val before = List(63) { d.w.cert("J$it", i2.subject, d.w.name("Junk issuer $it")) }
        val after = List(5) { d.w.cert("K$it", i2.subject, d.w.name("Junk issuer K$it")) }
        // 64 related at I1, the 64th is I2 with a path; the 65th is never asked for a verification.
        check(
            d.w.fixture(
                "cap",
                "",
                listOf(d.leaf, i1) + before + i2 + after,
                listOf(d.root),
                found(d.path).copy(verifications = 66, candidatesExplored = 66),
            ),
        )
    }

    @Test
    fun `walker cross-call memo stores VERIFIED only, and a memo hit costs no verification but one exploration`() {
        with(Honest()) {
            val fake = w.cert("F", intermediate.subject, w.name("Attacker"))
            val f =
                fixture(
                    "memo",
                    presented = listOf(leaf, fake, intermediate),
                    walk = found(path).copy(verifications = 3, candidatesExplored = 3),
                )
            val memo = LruMap<Pair<ByteString, ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
            val first = Counting(SymVerifier(f.ok, f.unsupported))
            check(f, walk(f, first, memo = memo))
            assertEquals(3, first.calls)
            assertEquals(2, memo.size)
            assertEquals(VerifyResult.VERIFIED, memo[leaf.bytesHash to intermediate.keyHash])
            assertEquals(VerifyResult.VERIFIED, memo[intermediate.bytesHash to root.keyHash])
            assertNull(memo[leaf.bytesHash to fake.keyHash], "an INVALID result is not shared across calls")

            // The second walk: L/I and I/R are memo hits (explored, not verified); L/F is verified again.
            val second = Counting(SymVerifier(f.ok, f.unsupported))
            val again = walk(f, second, memo = memo)
            check(f.copyWith(found(path).copy(verifications = 1, candidatesExplored = 3)), again)
            assertEquals(1, second.calls)
        }
    }

    @Test
    fun `walker cross-call memo never stores UNSUPPORTED or a verifier throw`() {
        with(Honest()) {
            // F verifies the leaf; F's own signature is unsupported against R (related) and against I (unrelated).
            val fake =
                w.cert(
                    "F",
                    intermediate.subject,
                    root.subject,
                    signer = root.key,
                    sigOid = SymOids.UNSUPPORTED_SIGNATURE,
                )
            w.verifies(leaf, fake.key)
            val f =
                fixture(
                    "memo",
                    presented = listOf(leaf, fake, intermediate),
                    walk = found(path).copy(unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE)),
                )
            val memo = LruMap<Pair<ByteString, ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
            check(f, walk(f, memo = memo))
            assertEquals(VerifyResult.VERIFIED, memo[leaf.bytesHash to fake.keyHash])
            assertNull(memo[fake.bytesHash to root.keyHash])
            assertNull(memo[fake.bytesHash to intermediate.keyHash])
            assertEquals(3, memo.size)
        }
        with(Honest()) {
            val f =
                fixture(
                    "memo",
                    presented = listOf(leaf, intermediate),
                    walk = notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                )
            val memo = LruMap<Pair<ByteString, ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
            walk(f, Throwing { IllegalStateException("boom") }, memo = memo)
            assertEquals(0, memo.size)
        }
    }

    @Test
    fun `walker verifier calls equal WalkStats verifications on every fixture row`() {
        val rows =
            with(WalkerFixturesAToR) {
                listOf(a(), b(), c(), d(), e(), f(), g(), h(), i(), k(), k2(), l(), m(), n(), o(), p(), q(), r())
            }.flatten() +
                with(WalkerFixturesS1ToAj) {
                    listOf(
                        s1(),
                        s2(),
                        t(),
                        v(),
                        v2(),
                        w(),
                        y(),
                        y2(),
                        z(),
                        aa(),
                        ac(),
                        ad(),
                        ae(),
                        af(),
                        ah(),
                        ai(),
                        aj(),
                    )
                }.flatten()
        for (f in rows) {
            val counting = Counting(SymVerifier(f.ok, f.unsupported))
            val verifications = walk(f, counting).stats.verifications
            assertEquals(verifications, counting.calls, f.toString())
        }
    }

    /** A verifier that throws [error] for every call. */
    private class Throwing(
        private val error: () -> Throwable,
    ) : SignatureVerifier {
        var calls = 0

        override fun verify(
            sigAlg: ByteArray,
            spki: ByteArray,
            message: ByteArray,
            signature: ByteArray,
        ): VerifyResult {
            calls++
            throw error()
        }

        override fun unsupportedOids(): Set<String> = emptySet()
    }

    @Test
    fun `walker a verifier throw is INVALID plus one VerifierError per verified pair`() {
        with(Honest()) {
            // F shares I's key: the leaf's pair with that key is verified once, the second candidate is a memo hit. The
            // leaf's own signature OID differs from its candidates', so the finding names the child's.
            val own = "1.3.6.1.4.1.99999.91.7"
            val ownLeaf =
                w.cert(
                    "L",
                    w.name("leaf.example"),
                    intermediate.subject,
                    signer = intermediate.key,
                    sigOid = own,
                )
            val sameKey = w.cert("F", intermediate.subject, w.name("Attacker"), intermediate.key)
            val f =
                fixture(
                    "throw",
                    presented = listOf(ownLeaf, sameKey, intermediate),
                    walk = notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                )
            for (error in listOf<() -> Throwable>(
                { IllegalStateException("provider") },
                { StackOverflowError("deep") },
                { NotImplementedError("todo") },
                { AssertionError("assert") },
            )) {
                val verifier = Throwing(error)
                val walk = walk(f, verifier)
                assertIs<Walk.NotFound>(walk)
                assertEquals(NoIssuerReason.ALL_CANDIDATES_INVALID, walk.reason)
                assertEquals(1, verifier.calls)
                assertEquals(1, walk.stats.verifications)
                assertEquals(2, walk.stats.candidatesExplored)
                assertEquals(
                    listOf(Finding.VerifierError.of(own, error().message!!)),
                    walk.findings,
                )
            }
        }
    }

    @Test
    fun `walker a fatal verifier error propagates`() {
        with(Honest()) {
            val f =
                fixture("throw", presented = listOf(leaf, intermediate), walk = notFound(NoIssuerReason.NO_CANDIDATE))
            assertFailsWith<OutOfMemoryError> { walk(f, Throwing { OutOfMemoryError("fatal") }) }
            assertFailsWith<InternalError> { walk(f, Throwing { InternalError("fatal") }) }
        }
    }

    @Test
    fun `walker a verifier returning null, as a Java one can, is INVALID plus VerifierError`() {
        with(Honest()) {
            val f =
                fixture(
                    "null",
                    presented = listOf(leaf, intermediate),
                    walk = notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                )
            val nulling =
                object : SignatureVerifier {
                    override fun verify(
                        sigAlg: ByteArray,
                        spki: ByteArray,
                        message: ByteArray,
                        signature: ByteArray,
                    ): VerifyResult = nullResult()

                    override fun unsupportedOids(): Set<String> = emptySet()
                }
            val walk = walk(f, nulling)
            assertIs<Walk.NotFound>(walk)
            assertEquals(NoIssuerReason.ALL_CANDIDATES_INVALID, walk.reason)
            assertIs<Finding.VerifierError>(walk.findings.single())
        }
    }

    @Suppress("UNCHECKED_CAST") // erased: a null reaches the caller as a Java implementation's would
    private fun <T> unchecked(value: Any?): T = value as T

    private fun nullResult(): VerifyResult = unchecked<VerifyResult>(null)

    @Test
    fun `walker records a visited node's own unsupported OID with or without a related candidate`() {
        with(Honest()) {
            val other = w.name("Other")
            // The leaf's own signature OID is unsupported: recorded before any candidate is searched (issuer-independent),
            // so also when its only candidate is unrelated.
            val leaf2 =
                w.cert(
                    "L2",
                    w.name("leaf.example"),
                    intermediate.subject,
                    sigOid = SymOids.UNSUPPORTED_SIGNATURE,
                )
            val unrelated = w.cert("U", other, other)
            check(
                fixture(
                    "unsupported",
                    "unrelated candidate",
                    listOf(leaf2, unrelated),
                    notFound(NoIssuerReason.NO_CANDIDATE).copy(
                        unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE),
                        verifications = 1,
                    ),
                ),
            )
            check(
                fixture(
                    "unsupported",
                    "related candidate",
                    listOf(leaf2, intermediate),
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(
                        unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE),
                        verifications = 1,
                    ),
                ),
            )
            // A related candidate whose key OID is unsupported, under a supported child signature: nothing recorded.
            val badKey = w.cert("K", intermediate.subject, root.subject, w.key(SymOids.UNSUPPORTED_KEY))
            check(
                fixture(
                    "unsupported",
                    "candidate key OID",
                    listOf(leaf, badKey),
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 1),
                ),
            )
        }
    }

    @Test
    fun `walker UNSUPPORTED for an OID outside the probe is not recorded`() {
        with(Honest()) {
            val f =
                fixture(
                    "probe",
                    presented = listOf(leaf, intermediate),
                    walk = notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                )
            val unsupported =
                object : SignatureVerifier {
                    override fun verify(
                        sigAlg: ByteArray,
                        spki: ByteArray,
                        message: ByteArray,
                        signature: ByteArray,
                    ): VerifyResult = VerifyResult.UNSUPPORTED

                    override fun unsupportedOids(): Set<String> = emptySet()
                }
            check(f, walk(f, unsupported))
            check(
                f.copyWith(
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(unsupportedOids = setOf(SymOids.SIGNATURE)),
                ),
                walk(f, unsupported, probe = setOf(SymOids.SIGNATURE)),
            )
        }
    }

    private fun WalkerFixture.copyWith(walk: ExpectedWalk) =
        WalkerFixture(id, variant, presented, snapshot, ok, walk, unsupported, customCanonicaliser, label)

    @Test
    fun `walker NoIssuerReason comes from the leaf-level flags`() {
        with(Honest()) {
            val unanchored = w.cert("F", intermediate.subject, w.name("Attacker"))
            val other = w.name("Other")
            val unrelatedVerifier = w.cert("U", other, w.name("Attacker"))
            w.verifies(leaf, unrelatedVerifier.key)
            // No related candidate; an unrelated one verifies the leaf: still NO_CANDIDATE.
            check(
                fixture(
                    "reason",
                    "unrelated verifies",
                    listOf(leaf, unrelatedVerifier),
                    notFound(NoIssuerReason.NO_CANDIDATE),
                ),
            )
            // Related candidates all INVALID, an unrelated one verifies: the leaf verified, so UNANCHORED.
            check(
                fixture(
                    "reason",
                    "related invalid, unrelated verifies",
                    listOf(leaf, unanchored, unrelatedVerifier),
                    notFound(NoIssuerReason.UNANCHORED),
                ),
            )
            // Related candidates all INVALID and nothing else: ALL_CANDIDATES_INVALID.
            check(
                fixture(
                    "reason",
                    "related invalid",
                    listOf(leaf, unanchored),
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID),
                ),
            )
            // A deeper node whose candidates all fail does not change the leaf's UNANCHORED.
            w.verifies(leaf, unanchored.key)
            val belowUnanchored = w.cert("J", w.name("Attacker"), other)
            check(
                fixture(
                    "reason",
                    "deeper invalid",
                    listOf(leaf, unanchored, belowUnanchored),
                    notFound(NoIssuerReason.UNANCHORED),
                ),
            )
        }
    }

    @Test
    fun `walker at the leaf a related path stops the unrelated loop unless the canonicaliser is custom`() {
        // (ac)'s second case with the platform's own canonicaliser: the related decoy path hides the unrelated issuer.
        val custom = WalkerFixturesS1ToAj.ac()[1]
        val platform = custom.copyWithCanonicaliser(false)
        val walk = walk(platform)
        assertIs<Walk.Found>(walk)
        assertEquals(1, walk.paths.size)
        assertEquals(0, walk.stats.unrelatedExploredAtLeaf)
        assertEquals(2, walk.stats.verifications)
        val withCustom = walk(custom)
        assertIs<Walk.Found>(withCustom)
        assertEquals(2, withCustom.leafKeys.size)
    }

    private fun WalkerFixture.copyWithCanonicaliser(custom: Boolean) =
        WalkerFixture(id, variant, presented, snapshot, ok, walk, unsupported, custom, label)

    @Test
    fun `walker below the leaf a custom canonicaliser does not run the unrelated loop after a path`() {
        with(Honest()) {
            // U is unrelated to L and to I, verifies both and is certified by R.
            val u = w.cert("U", w.name("Unrelated"), root.subject, signer = root.key)
            w.verifies(intermediate, u.key)
            // At the leaf (custom): U is explored, L/U invalid. At I: R is found and U is never explored.
            check(
                fixture(
                    "custom",
                    presented = listOf(leaf, intermediate, u),
                    customCanonicaliser = true,
                    walk = found(path).copy(verifications = 3, candidatesExplored = 3, unrelatedExploredAtLeaf = 1),
                ),
            )
        }
    }

    @Test
    fun `walker below the leaf the unrelated loop stops once a path exists`() {
        val w = FixtureWorld()
        val absent = w.name("Absent issuer")
        val u1 = w.root("U1", "Unrelated 1")
        val u2 = w.root("U2", "Unrelated 2")
        // I's issuer is neither presented nor in the snapshot; U1 and U2 are anchors unrelated to I that both verify it.
        val i = w.cert("I", w.name("Intermediate"), absent).also { w.verifies(it, u1.key) }
        w.verifies(i, u2.key)
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key)
        // L/I, then I/U1 through I's unrelated loop; U2 is never explored, at I or (a related path exists) at the leaf.
        check(
            w.fixture(
                "unrelated",
                "",
                listOf(leaf, i, u1, u2),
                listOf(u1, u2),
                found(listOf(leaf, i, u1)).copy(verifications = 2, candidatesExplored = 2, unrelatedExploredAtLeaf = 0),
            ),
        )
    }

    @Test
    fun `walker an unrelated candidate at the leaf that trips MAX_EXPLORED is counted as explored at the leaf`() {
        // 1,024 unrelated junk at the leaf use the budget; I, the 1,025th unrelated candidate, trips it at the leaf.
        val (h, presented) = unrelatedAtLeaf(RevoktLimits.MAX_EXPLORED)
        check(
            h.fixture(
                "budget",
                "unrelated trip",
                presented,
                budget(WalkEnd.EXPLORATION_BUDGET, 1).copy(
                    verifications = 1,
                    candidatesExplored = RevoktLimits.MAX_EXPLORED,
                    unrelatedExploredAtLeaf = RevoktLimits.MAX_EXPLORED + 1,
                ),
            ),
        )
    }

    @Test
    fun `walker exact-byte duplicates and certificates on the path are explored once`() {
        with(Honest()) {
            check(
                fixture(
                    "duplicates",
                    presented = listOf(leaf, intermediate, intermediate, leaf, root, intermediate),
                    // L/I, I/R; the presented root is the store root's exact bytes, yielded once.
                    walk = found(path).copy(verifications = 2, candidatesExplored = 2, relatedExploredAtLeaf = 1),
                ),
            )
        }
    }

    @Test
    fun `walker reconstruct needs the leaf and leaves the presented chain unchanged`() {
        val index = CandidateIndex(emptyList())
        val verifier = SymVerifier(emptySet(), emptySet())
        assertFailsWith<IllegalArgumentException> {
            reconstruct(emptyList(), index, verifier, emptySet(), LruMap(1))
        }
        val f = WalkerFixturesAToR.h().single()
        val idx = CandidateIndex(f.snapshot)
        val presented = f.presented.map { idx.cert(WalkerCerts.parse(it)) }
        val copy = presented.toList()
        reconstruct(presented, idx, SymVerifier(f.ok, f.unsupported), SymOids.UNSUPPORTED, LruMap(16))
        assertEquals(copy.size, presented.size)
        copy.zip(presented).forEach { (a, b) -> assertSame(a, b) }
    }
}
