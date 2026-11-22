// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.engine.walker.ExpectedWalk.Companion.budget
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.engine.walker.FixtureWorld.Companion.PRINTABLE_STRING
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
 * Spec §5.1 `reconstruct` beyond the §9 rows: the work budget at N and N + 1, the first-path stop, the loop skip, the
 * memos, the `UNSUPPORTED` rule, unrelated certificates, the `NoIssuerReason` flags and the never-throw rule for
 * verifiers (§5.5).
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
        memo: LruMap<Pair<ByteString, ByteString>, VerifyResult> = lruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
    ): Walk {
        val index = CandidateIndex(f.snapshot)
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
    fun `walker MAX_EXPLORED completes at 256 explorations and aborts at the 257th, at any depth`() {
        // 251 junk: 256 explorations, each a verification, Found.
        val (d256, at256) = levels(listOf(63, 63, 63, 62))
        val f256 =
            d256.w.fixture(
                "budget",
                "256",
                at256,
                listOf(d256.root),
                found(d256.path).copy(verifications = 256, candidatesExplored = 256),
            )
        check(f256)
        // 252 junk: the last link, I4/R, would be the 257th exploration; it is not charged, and the whole walk ends.
        val (d257, at257) = levels(listOf(63, 63, 63, 63))
        val f257 =
            d257.w.fixture(
                "budget",
                "257",
                at257,
                listOf(d257.root),
                budget().copy(verifications = 256, candidatesExplored = 256),
            )
        check(f257)
    }

    /** [junk] certificates named like the intermediate that share one key ahead of it: one verification, then memo hits. */
    private fun sharedKeyJunk(junk: Int): Pair<Honest, List<FixtureCert>> {
        val h = Honest()
        val shared = h.w.key()
        val js = List(junk) { h.w.cert("J$it", h.intermediate.subject, h.w.name("Junk issuer $it"), shared) }
        return h to listOf(h.leaf) + js + h.intermediate
    }

    @Test
    fun `walker a memo hit costs no verification but one exploration of the budget`() {
        val (h256, p256) = sharedKeyJunk(RevoktLimits.MAX_EXPLORED - 2)
        check(
            h256.fixture(
                "budget",
                "memo hits, 256",
                p256,
                found(h256.path).copy(verifications = 3, candidatesExplored = RevoktLimits.MAX_EXPLORED),
            ),
        )
        // One more junk: I/R would be the 257th exploration.
        val (h257, p257) = sharedKeyJunk(RevoktLimits.MAX_EXPLORED - 1)
        check(
            h257.fixture(
                "budget",
                "memo hits, 257",
                p257,
                budget().copy(verifications = 2, candidatesExplored = RevoktLimits.MAX_EXPLORED),
            ),
        )
    }

    @Test
    fun `walker below the leaf the first path ends the walk`() {
        val d = Deep(2)
        val (i1, i2) = d.intermediates
        val before = List(63) { d.w.cert("J$it", i2.subject, d.w.name("Junk issuer $it")) }
        val after = List(5) { d.w.cert("K$it", i2.subject, d.w.name("Junk issuer K$it")) }
        // 64 related at I1, the 64th is I2 with a path; the five after it are never explored.
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
            val memo = lruMap<Pair<ByteString, ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
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
            // F verifies the leaf; F's own signature is unsupported against R, its one candidate.
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
            val memo = lruMap<Pair<ByteString, ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
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
            val memo = lruMap<Pair<ByteString, ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
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
    fun `walker the leaf's own unsupported OID is deferred until a related candidate is found`() {
        with(Honest()) {
            val other = w.name("Other")
            // The leaf's own signature OID is unsupported. As pkix defers an end-entity error, it counts only once an
            // issuer candidate was found: not alone, and not beside an unrelated certificate, which is no candidate.
            val leaf2 =
                w.cert(
                    "L2",
                    w.name("leaf.example"),
                    intermediate.subject,
                    sigOid = SymOids.UNSUPPORTED_SIGNATURE,
                )
            val unrelated = w.cert("U", other, other)
            check(fixture("unsupported", "no candidate", listOf(leaf2), notFound(NoIssuerReason.NO_CANDIDATE)))
            check(
                fixture(
                    "unsupported",
                    "unrelated candidate",
                    listOf(leaf2, unrelated),
                    notFound(NoIssuerReason.NO_CANDIDATE).copy(verifications = 0, candidatesExplored = 0),
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
        WalkerFixture(id, variant, presented, snapshot, ok, walk, unsupported, label)

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
            // Related candidates all INVALID, an unrelated one verifies: it is no candidate, so ALL_CANDIDATES_INVALID.
            check(
                fixture(
                    "reason",
                    "related invalid, unrelated verifies",
                    listOf(leaf, unanchored, unrelatedVerifier),
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 1, candidatesExplored = 1),
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
    fun `walker an unrelated certificate is never a candidate, below the leaf either`() {
        val w = FixtureWorld()
        val absent = w.name("Absent issuer")
        val u1 = w.root("U1", "Unrelated 1")
        val u2 = w.root("U2", "Unrelated 2")
        // I's issuer is neither presented nor in the snapshot; U1 and U2 are anchors unrelated to I that both verify it.
        val i = w.cert("I", w.name("Intermediate"), absent).also { w.verifies(it, u1.key) }
        w.verifies(i, u2.key)
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key)
        // L/I only: I has no candidate, so the walk is UNANCHORED, whatever the PKIX fallback then finds.
        check(
            w.fixture(
                "unrelated",
                "",
                listOf(leaf, i, u1, u2),
                listOf(u1, u2),
                notFound(NoIssuerReason.UNANCHORED).copy(verifications = 1, candidatesExplored = 1),
            ),
        )
    }

    /**
     * A and B cross-sign (A's issuer is B's subject and the reverse), and A2 is A's subject and key under the root:
     * leaf → A → B → A2 → R is a path of byte-distinct certificates, but A2 repeats A's raw subject and SPKI, so at B it
     * is skipped (RFC 4158 §5.2, webpki and mozilla::pkix), uncharged. The walk backtracks to the leaf and finds
     * leaf → A2 → R, L/A2 a memo hit of L/A.
     */
    private fun crossSigned(
        a2Subject: (FixtureWorld, ByteArray) -> ByteArray,
    ): Triple<FixtureWorld, List<FixtureCert>, List<FixtureCert>> {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val aName = w.name("A")
        val bName = w.name("B")
        val aKey = w.key()
        val bKey = w.key()
        val a = w.cert("A", aName, bName, aKey, signer = bKey)
        val b = w.cert("B", bName, aName, bKey, signer = aKey)
        val a2 = w.cert("A2", a2Subject(w, aName), root.subject, aKey, signer = root.key)
        val leaf = w.cert("L", w.name("leaf.example"), aName, signer = aKey, key = w.leafKey())
        return Triple(w, listOf(leaf, a, b, a2), listOf(root))
    }

    @Test
    fun `walker a candidate repeating the raw subject and SPKI of a certificate on the path is skipped uncharged`() {
        val (w, presented, snapshot) = crossSigned { _, name -> name }
        val leaf = presented.first()
        val a2 = presented.last()
        // L/A, A/B, then B/A2 skipped; L/A2 (memo hit), A2/R.
        check(
            w.fixture(
                "loop",
                "same raw subject",
                presented,
                snapshot,
                found(listOf(leaf, a2, snapshot[0])).copy(verifications = 3, candidatesExplored = 4),
            ),
        )
        // Only raw bytes count, as in both references: A2's subject as a PrintableString is canonically A's but not a
        // loop, so B/A2 is explored and the walk is leaf → A → B → A2 → R.
        val (w2, presented2, snapshot2) = crossSigned { world, _ -> world.name("A", PRINTABLE_STRING) }
        check(
            w2.fixture(
                "loop",
                "re-encoded subject",
                presented2,
                snapshot2,
                found(presented2 + snapshot2).copy(verifications = 4, candidatesExplored = 4),
            ),
        )
    }

    @Test
    fun `walker a copy of the leaf's subject and key is no candidate, so the leaf stays NO_CANDIDATE`() {
        val w = FixtureWorld()
        val name = w.name("Self-issued leaf")
        val key = w.leafKey()
        val leaf = w.cert("L", name, name, key, signer = w.key())
        val copy = w.cert("L2", name, name, key, signer = w.key())
        check(
            w.fixture(
                "loop",
                "leaf copy",
                listOf(leaf, copy),
                emptyList(),
                notFound(NoIssuerReason.NO_CANDIDATE).copy(verifications = 0, candidatesExplored = 0),
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
                    walk = found(path).copy(verifications = 2, candidatesExplored = 2),
                ),
            )
        }
    }

    @Test
    fun `walker reconstruct needs the leaf and leaves the presented chain unchanged`() {
        val index = CandidateIndex(emptyList())
        val verifier = SymVerifier(emptySet(), emptySet())
        assertFailsWith<IllegalArgumentException> {
            reconstruct(emptyList(), index, verifier, emptySet(), lruMap(1))
        }
        val f = WalkerFixturesAToR.h().single()
        val idx = CandidateIndex(f.snapshot)
        val presented = f.presented.map { idx.cert(WalkerCerts.parse(it)) }
        val copy = presented.toList()
        reconstruct(presented, idx, SymVerifier(f.ok, f.unsupported), SymOids.UNSUPPORTED, lruMap(16))
        assertEquals(copy.size, presented.size)
        copy.zip(presented).forEach { (a, b) -> assertSame(a, b) }
    }
}
