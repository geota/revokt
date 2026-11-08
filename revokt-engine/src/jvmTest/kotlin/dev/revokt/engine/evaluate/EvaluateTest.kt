// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.EngineErrorProducer
import dev.revokt.Exemption
import dev.revokt.Finding
import dev.revokt.KeyabilityClause
import dev.revokt.KotlinRevocationEngine
import dev.revokt.NoIssuerReason
import dev.revokt.ParseReason
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktPolicy
import dev.revokt.RevoktTestingApi
import dev.revokt.Rule
import dev.revokt.TrustClass
import dev.revokt.Verdict
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.FixtureCert
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.K6_VALIDITY
import dev.revokt.engine.walker.WalkerFixture
import dev.revokt.engine.walker.garbage
import dev.revokt.engine.walker.subCa
import dev.revokt.testing.SymOids
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Decision steps 7 and 8 over real decisions and hand-made ones (spec §5.1, §4 "Status-to-rule mappings", "Key
 * aggregation", `Verdict`; §8): the §9 `Rule` model items tagged [0.2] that need only a verdict, walker fixture (ab),
 * the engine mapping, key aggregation and the no-keys contract.
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class EvaluateTest {
    private val h = Honest()

    private val honest: WalkerFixture =
        h.fixture("honest", presented = listOf(h.leaf, h.intermediate), walk = ExpectedWalk.found(h.path))

    private val intermediateKey = h.intermediate.keyHash

    private fun verdictOf(
        f: WalkerFixture = honest,
        policy: RevoktPolicy = RevoktPolicy.DEFAULT,
        crlite: CrliteQueryResult = CrliteQueryResult.NOT_REVOKED,
        generation: dev.revokt.engine.update.DatasetGeneration? = generation(),
    ): Verdict = Run.of(f, policy, snapshot(generation), StubEngine.always(crlite)).evaluate().verdict

    private fun anchorIn(vararg anchors: FixtureCert): Exemption =
        Exemption.anchorIn(
            anchors.map {
                it.bytesHash.toByteArray()
            },
        )

    // §9 Rule model [0.2] items.

    @Test
    fun `Verdict rule is the first fired, non-exempted REJECT rule`() {
        val bundled = generation(trustClass = TrustClass.BUNDLED)
        val strict = verdictOf(policy = RevoktPolicy.STRICT, crlite = CrliteQueryResult.NO_SCTS, generation = bundled)
        assertEquals(setOf(Rule.NO_SCTS, Rule.UNSIGNED_DATA), strict.rules)
        assertEquals(Rule.NO_SCTS, assertIs<Verdict.Rejected>(strict).rule)
        val exempting =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_SCTS, anchorIn(h.root))
                .build()
        val v = verdictOf(policy = exempting, crlite = CrliteQueryResult.NO_SCTS, generation = bundled)
        assertEquals(setOf(Rule.NO_SCTS, Rule.UNSIGNED_DATA), v.rules)
        assertEquals(Rule.UNSIGNED_DATA, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(listOf(Rule.NO_SCTS), v.findings.filterIsInstance<Finding.Exempted>().map { it.rule })
        val both = exempting.newBuilder().exempt(Rule.UNSIGNED_DATA, anchorIn(h.root)).build()
        val accepted = verdictOf(policy = both, crlite = CrliteQueryResult.NO_SCTS, generation = bundled)
        assertIs<Verdict.Accepted>(accepted)
        assertNull(accepted.rule)
        assertEquals(setOf(Rule.NO_SCTS, Rule.UNSIGNED_DATA), accepted.rules, "exempted rules still fired")
    }

    @Test
    fun `a K6 leaf is PARSE_FAILED(PRODUCER_UNKEYABLE) with clause TIME and crlite null`() {
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
        val run =
            Run.of(
                h.fixture("k6", presented = listOf(leaf6, h.intermediate), walk = ExpectedWalk.found()),
                engine = engine,
            )
        val v = run.evaluate().verdict
        assertEquals(PathStatus.PARSE_FAILED, v.path.status)
        assertEquals(ParseReason.PRODUCER_UNKEYABLE, v.path.parseReason)
        assertEquals(KeyabilityClause.TIME, v.path.keyabilityClause)
        assertNull(v.crlite)
        assertEquals(emptyList(), engine.queries, "never queried")
        assertEquals(setOf(Rule.PARSE_FAILED), v.rules)
        assertIs<Verdict.Accepted>(v)
    }

    @Test
    fun `DEFAULT with rule(STALE, REJECT) and 4-day-old data is Accepted, stale, with no rule`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.STALE, dev.revokt.Outcome.REJECT)
                .build()
        val v = verdictOf(policy = policy, generation = generation(4 * DAY))
        assertIs<Verdict.Accepted>(v)
        assertTrue(v.dataStates.getValue(Dataset.CRLITE).stale)
        assertEquals(emptySet(), v.rules)
    }

    @Test
    fun `rejectStaleAfter(CRLITE, 3 d) rejects STALE, unless exempted, and a shut seed gate never fires it`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.STALE, dev.revokt.Outcome.REJECT)
                .rejectStaleAfterMillis(Dataset.CRLITE, 3 * DAY)
                .build()
        for ((case, gen) in listOf(
            "not from a seed" to generation(4 * DAY),
            "from a seed, gate open" to generation(4 * DAY, fromSeed = true, gateOpen = true),
        )) {
            val v = verdictOf(policy = policy, generation = gen)
            assertEquals(Rule.STALE, assertIs<Verdict.Rejected>(v).rule, case)
            assertEquals(setOf(Rule.STALE), v.dataStates.getValue(Dataset.CRLITE).rules, case)
            val exempt = policy.newBuilder().exempt(Rule.STALE, anchorIn(h.root)).build()
            val e = verdictOf(policy = exempt, generation = gen)
            assertIs<Verdict.Accepted>(e, case)
            assertEquals(listOf(Rule.STALE), e.findings.filterIsInstance<Finding.Exempted>().map { it.rule }, case)
            assertEquals(setOf(Rule.STALE), e.dataStates.getValue(Dataset.CRLITE).rules, case)
            assertEquals(setOf(Rule.STALE), e.rules, case)
        }
        val shut = verdictOf(policy = policy, generation = generation(400 * DAY, fromSeed = true, gateOpen = false))
        assertIs<Verdict.Accepted>(shut)
        assertEquals(emptySet(), shut.rules)
        val strict =
            verdictOf(
                policy = RevoktPolicy.STRICT,
                generation = generation(400 * DAY, fromSeed = true, gateOpen = false),
            )
        assertIs<Verdict.Accepted>(strict, "STRICT with the seed gate shut")
        assertEquals(emptySet(), strict.rules)
    }

    @Test
    fun `a NO_SCTS chain under DEFAULT is Accepted`() {
        val v = verdictOf(crlite = CrliteQueryResult.NO_SCTS)
        assertIs<Verdict.Accepted>(v)
        assertEquals(setOf(Rule.NO_SCTS), v.rules)
        assertEquals(CrliteQueryResult.NO_SCTS, v.crlite?.result)
    }

    @Test
    fun `a SYSTEM generation fires UNSIGNED_DATA under a SIGNED floor, and STRICT rejects it`() {
        val system = generation(trustClass = TrustClass.SYSTEM)
        val floor =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .minTrustClass(Dataset.CRLITE, TrustClass.SIGNED)
                .build()
        val v = verdictOf(policy = floor, generation = system)
        assertIs<Verdict.Accepted>(v)
        assertTrue(Rule.UNSIGNED_DATA in v.rules)
        assertEquals(setOf(Rule.UNSIGNED_DATA), v.dataStates.getValue(Dataset.CRLITE).rules)
        val strict = verdictOf(policy = RevoktPolicy.STRICT, generation = system)
        assertEquals(Rule.UNSIGNED_DATA, assertIs<Verdict.Rejected>(strict).rule)
        assertEquals(setOf(Rule.UNSIGNED_DATA), strict.rules)
    }

    @Test
    fun `no generation, not pending, and a walker that throws is Rejected(NO_DATA) with ENGINE_ERROR`() {
        val run =
            Run(listOf(h.leaf.der, h.intermediate.der), snapshot = snapshot(noGeneration())) {
                throw IllegalStateException("walker")
            }
        val v = run.evaluate().verdict
        assertEquals(Rule.NO_DATA, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(setOf(Rule.NO_DATA, Rule.ENGINE_ERROR), v.rules)
        assertEquals(PathStatus.NOT_WALKED, v.path.status)
        assertEquals(listOf(EngineErrorProducer.BOUNDARY), engineErrors(v).map { it.producer })
        assertEquals(setOf(Rule.NO_DATA), v.dataStates.getValue(Dataset.CRLITE).rules)
        assertNull(v.crlite)
    }

    @Test
    fun `walker (ab) a PARSE_FAILED leaf with no CRLite generation fires PARSE_FAILED and NO_DATA, rule NO_DATA`() {
        val f =
            WalkerFixture(
                "ab",
                "",
                listOf(garbage(64), h.intermediate.der),
                honest.snapshot,
                honest.ok,
                ExpectedWalk.found(),
            )
        val v = verdictOf(f, generation = noGeneration())
        assertEquals(setOf(Rule.PARSE_FAILED, Rule.NO_DATA), v.rules)
        assertEquals(Rule.NO_DATA, assertIs<Verdict.Rejected>(v).rule)
    }

    // Step 7: the engine mapping.

    @Test
    fun `each engine answer maps to its rule, NO_DATA while published and ENGINE_ERROR being the engine's error`() {
        for (result in CrliteQueryResult.entries) {
            val engine = StubEngine.always(result)
            val v = Run(listOf(h.leaf.der), engine = engine) { decision(PathStatus.FOUND, key(1)) }.evaluate().verdict
            val want =
                when (result) {
                    CrliteQueryResult.NOT_REVOKED -> emptySet()
                    CrliteQueryResult.NO_DATA, CrliteQueryResult.ENGINE_ERROR -> setOf(Rule.ENGINE_ERROR)
                    else -> setOf(Rule.valueOf(result.name))
                }
            assertEquals(want, v.rules, "$result")
            assertEquals(1, engine.queries.size, "$result")
            assertContentEquals(key(1).toByteArray(), engine.queries[0].issuerSpkiHash, "$result")
            assertContentEquals(byteArrayOf(1), engine.queries[0].serial, "$result")
            val crlite = assertIs<Finding.Crlite>(v.crlite, "$result")
            assertEquals(result, crlite.result)
            assertContentEquals(key(1).toByteArray(), crlite.issuerSpkiSha256)
            assertEquals(StubEngine.COVERAGE_END, crlite.coverageEndMillis)
            val errors = engineErrors(v)
            if (Rule.ENGINE_ERROR in want) {
                assertEquals(listOf(EngineErrorProducer.ENGINE), errors.map { it.producer }, "$result")
                assertEquals(listOf("StubEngine"), errors.map { it.engineName }, "$result")
            } else {
                assertEquals(emptyList(), errors, "$result")
            }
        }
    }

    @Test
    fun `with no CRLite generation the engine is never asked and the synthesised NO_DATA fires nothing`() {
        for (gen in listOf(noGeneration(pending = true), noGeneration(), null)) {
            val engine = StubEngine.always(CrliteQueryResult.REVOKED)
            val v =
                Run(listOf(h.leaf.der), snapshot = snapshot(gen), engine = engine) {
                    decision(PathStatus.FOUND, key(1), key(2))
                }.evaluate().verdict
            assertEquals(emptyList(), engine.queries, "$gen")
            assertEquals(
                listOf(
                    CrliteQueryResult.NO_DATA,
                    CrliteQueryResult.NO_DATA,
                ),
                v.findings.filterIsInstance<Finding.Crlite>().map {
                    it.result
                },
            )
            assertNull(v.crlite?.coverageEndMillis)
            val dataRules = v.dataStates.getValue(Dataset.CRLITE).rules
            assertEquals(dataRules, v.rules, "only the data rules: $gen")
            assertEquals(emptyList(), engineErrors(v), "$gen")
        }
    }

    @Test
    fun `the Kotlin engine with no generation while one is published is ENGINE_ERROR named kotlin`() {
        KotlinRevocationEngine().use { engine ->
            val v = Run.of(honest, engine = engine).evaluate().verdict
            assertEquals(setOf(Rule.ENGINE_ERROR), v.rules)
            assertEquals(CrliteQueryResult.NO_DATA, v.crlite?.result)
            val error = engineErrors(v).single()
            assertEquals(EngineErrorProducer.ENGINE, error.producer)
            assertEquals("kotlin", error.engineName)
            assertIs<Verdict.Accepted>(v, "ENGINE_ERROR allows in DEFAULT")
            assertEquals(
                Rule.ENGINE_ERROR,
                assertIs<Verdict.Rejected>(
                    Run.of(honest, RevoktPolicy.STRICT, engine = engine).evaluate().verdict,
                ).rule,
            )
        }
    }

    @Test
    fun `the engine name is read once per engine instance, however many queries run`() {
        val engine = StubEngine(fixedName = "stub") { CrliteQueryResult.ENGINE_ERROR }
        val named = NamedEngine(engine)
        repeat(5) {
            val v =
                Run(listOf(h.leaf.der), engine = engine) {
                    decision(PathStatus.FOUND, key(1), key(2), key(3))
                }.evaluate(named).verdict
            assertEquals(listOf("stub", "stub", "stub"), engineErrors(v).map { it.engineName })
        }
        assertEquals(15, engine.queries.size)
        assertEquals(1, engine.nameReads)
    }

    @Test
    fun `the honest chain is queried under the intermediate's key with the leaf's serial`() {
        val engine =
            StubEngine {
                if (it ==
                    intermediateKey
                ) {
                    CrliteQueryResult.REVOKED
                } else {
                    CrliteQueryResult.NOT_REVOKED
                }
            }
        val v = Run.of(honest, engine = engine).evaluate().verdict
        assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(v).rule)
        assertContentEquals(intermediateKey.toByteArray(), engine.queries.single().issuerSpkiHash)
        assertContentEquals(
            dev.revokt.engine.walker.WalkerCerts
                .cert(h.leaf.der)
                .serial,
            engine.queries.single().serial,
        )
        assertContentEquals(intermediateKey.toByteArray(), v.crlite?.issuerSpkiSha256)
    }

    // Key aggregation.

    private fun twoKeys(
        a: CrliteQueryResult,
        b: CrliteQueryResult,
        status: PathStatus = PathStatus.FOUND,
    ): Verdict {
        val engine = StubEngine { if (it == key(1)) a else b }
        return Run(listOf(h.leaf.der), engine = engine) { decision(status, key(1), key(2)) }.evaluate().verdict
    }

    @Test
    fun `REVOKED on either key fires REVOKED alone, and crlite is the first REVOKED finding`() {
        val v = twoKeys(CrliteQueryResult.NOT_ENROLLED, CrliteQueryResult.REVOKED)
        assertEquals(setOf(Rule.REVOKED), v.rules)
        assertContentEquals(key(2).toByteArray(), v.crlite?.issuerSpkiSha256)
        assertEquals(2, v.findings.filterIsInstance<Finding.Crlite>().size)
        val first = twoKeys(CrliteQueryResult.REVOKED, CrliteQueryResult.NOT_ENROLLED)
        assertEquals(setOf(Rule.REVOKED), first.rules)
        assertContentEquals(key(1).toByteArray(), first.crlite?.issuerSpkiSha256)
        val revokedAndError = twoKeys(CrliteQueryResult.ENGINE_ERROR, CrliteQueryResult.REVOKED)
        assertEquals(setOf(Rule.REVOKED), revokedAndError.rules)
        assertEquals(emptyList(), engineErrors(revokedAndError), "the engine's error did not fire")
    }

    @Test
    fun `otherwise every key's non-answer fires, and crlite is the first key's`() {
        val v = twoKeys(CrliteQueryResult.NOT_ENROLLED, CrliteQueryResult.NO_SCTS)
        assertEquals(setOf(Rule.NOT_ENROLLED, Rule.NO_SCTS), v.rules)
        assertContentEquals(key(1).toByteArray(), v.crlite?.issuerSpkiSha256)
        val clean = twoKeys(CrliteQueryResult.NOT_REVOKED, CrliteQueryResult.NOT_COVERED)
        assertEquals(setOf(Rule.NOT_COVERED), clean.rules)
        val errors = twoKeys(CrliteQueryResult.ENGINE_ERROR, CrliteQueryResult.NO_DATA)
        assertEquals(setOf(Rule.ENGINE_ERROR), errors.rules)
        assertEquals(2, engineErrors(errors).size, "one EngineError per occurrence")
    }

    @Test
    fun `on Budget only REVOKED fires from CRLite and the other answers are findings only`() {
        val revoked =
            twoKeys(CrliteQueryResult.NOT_ENROLLED, CrliteQueryResult.REVOKED, PathStatus.PATH_BUDGET_EXCEEDED)
        assertEquals(setOf(Rule.REVOKED, Rule.PATH_BUDGET_EXCEEDED), revoked.rules)
        assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(revoked).rule)
        val other =
            twoKeys(CrliteQueryResult.NOT_ENROLLED, CrliteQueryResult.ENGINE_ERROR, PathStatus.PATH_BUDGET_EXCEEDED)
        assertEquals(setOf(Rule.PATH_BUDGET_EXCEEDED), other.rules)
        assertEquals(emptyList(), engineErrors(other))
        assertEquals(
            listOf(CrliteQueryResult.NOT_ENROLLED, CrliteQueryResult.ENGINE_ERROR),
            other.findings.filterIsInstance<Finding.Crlite>().map { it.result },
        )
    }

    @Test
    fun `walker (o) a second certified key is queried too, and its REVOKED fires`() {
        val sub = h.subCa()
        val f = h.fixture("o", presented = listOf(h.leaf, h.intermediate, sub), walk = ExpectedWalk.found())
        val engine = StubEngine { if (it == sub.keyHash) CrliteQueryResult.REVOKED else CrliteQueryResult.NOT_REVOKED }
        val v = Run.of(f, engine = engine).evaluate().verdict
        assertEquals(2, engine.queries.size)
        assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(v).rule)
        assertContentEquals(sub.keyHash.toByteArray(), v.crlite?.issuerSpkiSha256)
    }

    // No keys.

    @Test
    fun `with no issuer key nothing is queried, no CRLite rule fires and crlite is null, for every empty-key status`() {
        val leafU =
            h.w.cert(
                "LU",
                h.w.name("leaf.example"),
                h.intermediate.subject,
                sigOid = SymOids.UNSUPPORTED_SIGNATURE,
                key = h.w.leafKey(),
            )
        h.w.verifies(leafU, h.intermediate.key)
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
        val junk = h.junk(RevoktLimits.MAX_PRESENTED)
        val unrelated =
            List(RevoktLimits.FALLBACK_MAX_PRESENTED) { h.w.cert("U$it", h.w.name("U $it"), h.w.name("UI $it")) }

        fun f(
            id: String,
            presented: List<ByteArray>,
        ) = WalkerFixture(id, "", presented, honest.snapshot, h.w.ok, ExpectedWalk.found())
        val cases =
            listOf(
                Triple("PARSE_FAILED(STRUCTURE)", f("pf", listOf(garbage(64), h.intermediate.der)), Rule.PARSE_FAILED),
                Triple(
                    "PARSE_FAILED(OVERSIZE)",
                    f("pf", listOf(garbage(RevoktLimits.MAX_CERT_BYTES + 1), h.intermediate.der)),
                    Rule.PARSE_FAILED,
                ),
                Triple(
                    "PARSE_FAILED(PRODUCER_UNKEYABLE)",
                    f("k6", listOf(leaf6.der, h.intermediate.der)),
                    Rule.PARSE_FAILED,
                ),
                Triple(
                    "PATH_BUDGET_EXCEEDED, the step-3 cut",
                    f("ag", listOf(h.leaf.der) + junk.map { it.der }),
                    Rule.PATH_BUDGET_EXCEEDED,
                ),
                Triple(
                    "PATH_BUDGET_EXCEEDED, NotFound over FALLBACK_MAX_PRESENTED",
                    f("af", listOf(h.leaf.der) + unrelated.map { it.der }),
                    Rule.PATH_BUDGET_EXCEEDED,
                ),
                Triple("NO_ISSUER", f("g", listOf(h.leaf.der)), Rule.NO_ISSUER),
                Triple("ISSUER_UNVERIFIED", f("iu", listOf(leafU.der, h.intermediate.der)), Rule.ISSUER_UNVERIFIED),
            )
        for ((case, fixture, rule) in cases) {
            for (policy in listOf(RevoktPolicy.DEFAULT, RevoktPolicy.STRICT)) {
                val engine = StubEngine.always(CrliteQueryResult.REVOKED)
                val v = Run.of(fixture, policy, engine = engine).evaluate().verdict
                assertEquals(rule.name, v.path.status.name, case)
                assertEquals(emptyList(), v.path.issuerSpkiSha256s, case)
                assertEquals(emptyList(), engine.queries, "$case: never queried")
                assertEquals(emptyList(), v.findings.filterIsInstance<Finding.Crlite>(), case)
                assertNull(v.crlite, case)
                assertEquals(setOf(rule), v.rules, "$case: only the status rule")
                if (policy == RevoktPolicy.STRICT || rule == Rule.PATH_BUDGET_EXCEEDED) {
                    assertEquals(rule, assertIs<Verdict.Rejected>(v, case).rule, case)
                } else {
                    assertIs<Verdict.Accepted>(v, case)
                }
            }
        }
        assertEquals(NoIssuerReason.NO_CANDIDATE, verdictOf(cases[5].second).path.noIssuerReason)
    }

    @Test
    fun `a FOUND path with no issuer key is the boundary's error, never a clean answer`() {
        val engine = StubEngine.always(CrliteQueryResult.NOT_REVOKED)
        val v =
            Run(listOf(h.leaf.der), policy = RevoktPolicy.STRICT, engine = engine) {
                decision(PathStatus.FOUND)
            }.evaluate().verdict
        assertEquals(setOf(Rule.ENGINE_ERROR), v.rules)
        assertEquals(Rule.ENGINE_ERROR, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(listOf(EngineErrorProducer.BOUNDARY), engineErrors(v).map { it.producer })
        assertEquals(emptyList(), engine.queries)
    }

    // The verdict's other fields.

    @Test
    fun `the verdict lists every finding in order and carries the snapshot's epoch`() {
        val exempt =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_SCTS, anchorIn(h.root))
                .build()
        val run = Run.of(honest, exempt, engine = StubEngine.always(CrliteQueryResult.NO_SCTS))
        val evaluated = run.evaluate()
        val v = evaluated.verdict
        val decision = evaluated.decision!!
        val expected =
            listOf(v.path) + decision.findings + listOf(v.crlite!!) + v.dataStates.values +
                Finding.Exempted
                    .Builder()
                    .rule(Rule.NO_SCTS)
                    .build()
        assertEquals(expected, v.findings)
        assertEquals(EPOCH, assertIs<Verdict.Accepted>(v).generationEpoch)
        assertEquals(decision.path, v.path)
        assertTrue(v.elapsedNanos >= 0)
    }
}
