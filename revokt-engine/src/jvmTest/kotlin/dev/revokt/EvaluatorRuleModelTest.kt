// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.DAY
import dev.revokt.engine.evaluate.StubEngine
import dev.revokt.engine.evaluate.engineErrors
import dev.revokt.engine.evaluate.generation
import dev.revokt.engine.evaluate.noGeneration
import dev.revokt.engine.evaluate.snapshot
import dev.revokt.engine.update.DatasetGeneration
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.FixtureCert
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.K6_VALIDITY
import dev.revokt.engine.walker.WalkerCerts
import dev.revokt.engine.walker.fixture
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The §9 `Rule` model items tagged [0.2] (revision 49, §9 "`Rule` model tests"), end to end through
 * `Evaluator.evaluate`: #133 asserted each over `evaluate` alone, and these run the same items over
 * `EvaluationRequest`s of walker-fixture chains, with a stub engine and the generation each test hands the evaluator
 * (the system cache and the counters are 0.3). The golden fixture's "`ALLOW → REJECT` flip exactly once per rule and
 * preset" item is `RuleGoldenTest` with the build's `verifyRuleGrowability` (#73), not repeated here.
 */
@OptIn(RevoktTestingApi::class)
class EvaluatorRuleModelTest {
    private val h = Honest()

    private val honest =
        h.fixture("honest", presented = listOf(h.leaf, h.intermediate), walk = ExpectedWalk.found(h.path))

    private val chain = listOf(h.leaf.der, h.intermediate.der)

    private fun verdictOf(
        policy: RevoktPolicy = RevoktPolicy.DEFAULT,
        crlite: CrliteQueryResult = CrliteQueryResult.NOT_REVOKED,
        generation: DatasetGeneration? = generation(),
    ): Verdict = EvaluatorRig(honest, policy, snapshot(generation), StubEngine.always(crlite)).presented(chain)

    private fun anchorIn(vararg anchors: FixtureCert): Exemption =
        Exemption.anchorIn(anchors.map { it.bytesHash.toByteArray() })

    @Test
    fun `Verdict rule is the first fired, non-exempted REJECT rule`() {
        val bundled = generation(trustClass = TrustClass.BUNDLED)
        val strict = verdictOf(RevoktPolicy.STRICT, CrliteQueryResult.NO_SCTS, bundled)
        assertEquals(setOf(Rule.NO_SCTS, Rule.UNSIGNED_DATA), strict.rules)
        assertEquals(Rule.NO_SCTS, assertIs<Verdict.Rejected>(strict).rule)
        val exempting =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_SCTS, anchorIn(h.root))
                .build()
        val v = verdictOf(exempting, CrliteQueryResult.NO_SCTS, bundled)
        assertEquals(Rule.UNSIGNED_DATA, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(listOf(Rule.NO_SCTS), v.findings.filterIsInstance<Finding.Exempted>().map { it.rule })
        val both = exempting.newBuilder().exempt(Rule.UNSIGNED_DATA, anchorIn(h.root)).build()
        val accepted = verdictOf(both, CrliteQueryResult.NO_SCTS, bundled)
        assertIs<Verdict.Accepted>(accepted)
        assertNull(accepted.rule)
        assertEquals(setOf(Rule.NO_SCTS, Rule.UNSIGNED_DATA), accepted.rules, "exempted rules still fired")
    }

    @Test
    fun `a K6 leaf is PARSE_FAILED(PRODUCER_UNKEYABLE) with clause TIME and crlite null, and a K6 issuer is kept`() {
        val leaf6 =
            h.w.withValidity(K6_VALIDITY) {
                h.w.cert(
                    "L6",
                    h.w.name("leaf.example"),
                    h.intermediate.subject,
                    signer = h.intermediate.key,
                    key = h.w.leafKey(),
                )
            }
        val engine = StubEngine.always(CrliteQueryResult.REVOKED)
        val v =
            EvaluatorRig(honest, engine = engine)
                .presented(listOf(leaf6.der, h.intermediate.der))
        assertEquals(PathStatus.PARSE_FAILED, v.path.status)
        assertEquals(ParseReason.PRODUCER_UNKEYABLE, v.path.parseReason)
        assertEquals(KeyabilityClause.TIME, v.path.keyabilityClause)
        assertNull(v.crlite)
        assertEquals(emptyList(), engine.queries, "never queried")
        assertEquals(setOf(Rule.PARSE_FAILED), v.rules)
        assertIs<Verdict.Accepted>(v)
        // An issuer candidate outside the profile is not dropped: the path is found through it and queried under it.
        val w = h.w
        val i6 =
            w.withValidity(
                K6_VALIDITY,
            ) { w.cert("I6", w.name("Intermediate 6"), h.root.subject, signer = h.root.key) }
        val leaf = w.cert("L", w.name("leaf.example"), i6.subject, signer = i6.key, key = w.leafKey())
        assertEquals(KeyabilityClause.TIME, WalkerCerts.cert(i6.der).keyabilityClause)
        val f =
            w.fixture(
                "k6",
                "issuer",
                listOf(leaf, i6),
                listOf(h.root),
                ExpectedWalk.found(listOf(leaf, i6, h.root)),
            )
        val issuerEngine = StubEngine.always(CrliteQueryResult.REVOKED)
        val found = EvaluatorRig(f, engine = issuerEngine).presented(f.presented)
        assertEquals(PathStatus.FOUND, found.path.status)
        assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(found).rule)
        assertEquals(listOf(i6.keyHash), issuerEngine.queries.map { okio.ByteString.of(*it.issuerSpkiHash) })
    }

    @Test
    fun `DEFAULT with rule(STALE, REJECT) and 4-day-old data is Accepted, stale, with no rule`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.STALE, Outcome.REJECT)
                .build()
        val v = verdictOf(policy, generation = generation(4 * DAY))
        assertIs<Verdict.Accepted>(v)
        assertTrue(v.dataStates.getValue(Dataset.CRLITE).stale)
        assertEquals(emptySet(), v.rules)
    }

    @Test
    fun `rejectStaleAfter(CRLITE, 3 d) rejects STALE, and an anchorIn exemption accepts it`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.STALE, Outcome.REJECT)
                .rejectStaleAfterMillis(Dataset.CRLITE, 3 * DAY)
                .build()
        for ((case, gen) in listOf(
            "not from a seed" to generation(4 * DAY),
            "from a seed, a sync attempt completed since" to generation(4 * DAY, fromSeed = true, gateOpen = true),
        )) {
            val v = verdictOf(policy, generation = gen)
            assertEquals(Rule.STALE, assertIs<Verdict.Rejected>(v).rule, case)
            assertEquals(setOf(Rule.STALE), v.dataStates.getValue(Dataset.CRLITE).rules, case)
            val exempt = policy.newBuilder().exempt(Rule.STALE, anchorIn(h.root)).build()
            val e = verdictOf(exempt, generation = gen)
            assertIs<Verdict.Accepted>(e, case)
            assertEquals(listOf(Rule.STALE), e.findings.filterIsInstance<Finding.Exempted>().map { it.rule }, case)
            assertEquals(setOf(Rule.STALE), e.dataStates.getValue(Dataset.CRLITE).rules, case)
        }
    }

    @Test
    fun `a NO_SCTS chain under DEFAULT is Accepted`() {
        val v = verdictOf(crlite = CrliteQueryResult.NO_SCTS)
        assertIs<Verdict.Accepted>(v)
        assertEquals(setOf(Rule.NO_SCTS), v.rules)
    }

    @Test
    fun `a SYSTEM generation fires UNSIGNED_DATA under a SIGNED floor, and STRICT rejects it`() {
        val system = generation(trustClass = TrustClass.SYSTEM)
        val floor =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .minTrustClass(Dataset.CRLITE, TrustClass.SIGNED)
                .build()
        val v = verdictOf(floor, generation = system)
        assertIs<Verdict.Accepted>(v)
        assertTrue(Rule.UNSIGNED_DATA in v.rules)
        assertEquals(setOf(Rule.UNSIGNED_DATA), v.dataStates.getValue(Dataset.CRLITE).rules)
        val strict = verdictOf(RevoktPolicy.STRICT, generation = system)
        assertEquals(Rule.UNSIGNED_DATA, assertIs<Verdict.Rejected>(strict).rule)
    }

    @Test
    fun `no generation, not pending, and a walker that throws is Rejected(NO_DATA) with ENGINE_ERROR`() {
        val rig =
            EvaluatorRig(
                honest,
                generation = snapshot(noGeneration(pending = false)),
                decidePresented = { _, _, _, _ -> throw IllegalStateException("walker") },
            )
        val v = rig.presented(chain)
        assertEquals(Rule.NO_DATA, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(setOf(Rule.NO_DATA, Rule.ENGINE_ERROR), v.rules)
        assertEquals(PathStatus.NOT_WALKED, v.path.status)
        assertEquals(listOf(EngineErrorProducer.BOUNDARY), engineErrors(v).map { it.producer })
        assertNull(v.crlite)
    }
}
