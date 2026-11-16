// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.CredentialType
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.EngineErrorProducer
import dev.revokt.Exemption
import dev.revokt.ExemptionContext
import dev.revokt.Finding
import dev.revokt.Outcome
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.TrustClass
import dev.revokt.Verdict
import dev.revokt.and
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.WalkerHarness
import dev.revokt.engine.walker.garbage
import dev.revokt.or
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Step 8's exemptions (spec §4 `Exemption`, `ExemptionContext`, `PresentedChain`; §5.1 decision step 8; §8
 * exemptions): they run for fired, exemptable `REJECT` rules only; the chain is built only when one runs, over every
 * presented certificate; the host is host' as given; a throw is not exempt plus `EngineError(EXEMPTION)`; `and` and
 * `or` follow CEL.
 */
class ExemptionStageTest {
    private val h = Honest()
    private val honest =
        h.fixture(
            "honest",
            presented = listOf(h.leaf, h.intermediate),
            walk = ExpectedWalk.found(h.path),
        )

    /** An exemption answering [answer] that records each context it is asked about. */
    private class Recording(
        private val answer: Boolean = true,
    ) : Exemption {
        val seen = ArrayList<ExemptionContext>()

        override fun isExempt(context: ExemptionContext): Boolean {
            seen += context
            return answer
        }
    }

    @Test
    fun `exemptions run only for fired, exemptable REJECT rules`() {
        val recorders = Rule.entries.filter { it.exemptable }.associateWith { Recording() }

        fun policy(base: RevoktPolicy) =
            base.newBuilder().apply { recorders.forEach { (r, e) -> exempt(r, e) } }.build()
        // DEFAULT: NO_SCTS fires and allows; nothing runs.
        val default =
            Run.of(
                honest,
                policy(RevoktPolicy.DEFAULT),
                engine = StubEngine.always(CrliteQueryResult.NO_SCTS),
            )
        val d = default.evaluate().verdict
        assertIs<Verdict.Accepted>(d)
        assertTrue(recorders.values.all { it.seen.isEmpty() })
        assertEquals(0, default.chainsBuilt)
        // STRICT: NO_SCTS and UNSIGNED_DATA fire and reject; exactly those two run, over one chain.
        val strict =
            Run.of(
                honest,
                policy(RevoktPolicy.STRICT),
                snapshot(generation(trustClass = TrustClass.MIRROR)),
                StubEngine.always(CrliteQueryResult.NO_SCTS),
            )
        val s = strict.evaluate().verdict
        assertEquals(setOf(Rule.NO_SCTS, Rule.UNSIGNED_DATA), recorders.filterValues { it.seen.isNotEmpty() }.keys)
        assertTrue(recorders.values.all { it.seen.size <= 1 })
        assertEquals(1, strict.chainsBuilt)
        assertIs<Verdict.Accepted>(s)
        assertEquals(
            listOf(Rule.NO_SCTS, Rule.UNSIGNED_DATA),
            s.findings.filterIsInstance<Finding.Exempted>().map { it.rule },
        )
    }

    @Test
    fun `an exemption on a non-exemptable rule never runs, even in a form built around the builder's check`() {
        val recording = Recording()
        val strict = RevoktPolicy.STRICT.form
        // NOT_COVERED allows in both presets; raised here so that its exemption would be asked if the check were missing.
        val form =
            PolicyForm(
                strict.preset,
                strict.outcomes + (Rule.NOT_COVERED to Outcome.REJECT),
                mapOf(Rule.REVOKED to recording, Rule.NOT_COVERED to recording),
                strict.requiredDatasets,
                strict.staleness,
                strict.minTrustClassEntries,
                strict.rollbackWindowMillis,
                strict.clockSkewMillis,
                strict.signedSourceFailingAfterMillis,
            )
        for (result in listOf(CrliteQueryResult.REVOKED, CrliteQueryResult.NOT_COVERED)) {
            val engine = StubEngine.always(result)
            val v =
                evaluate(
                    EvaluationInput(honest.presented, null, snapshot(), form, WalkerHarness.SNAPSHOT_ID),
                    NamedEngine(engine),
                    { NOW },
                    { now -> Run.decideFixture(honest, null, now) },
                ).verdict
            assertEquals(Rule.valueOf(result.name), assertIs<Verdict.Rejected>(v).rule, "$result")
        }
        assertEquals(emptyList(), recording.seen)
    }

    @Test
    fun `no chain is built when no exemption will run`() {
        val noExemption = Run.of(honest, RevoktPolicy.STRICT, engine = StubEngine.always(CrliteQueryResult.NO_SCTS))
        assertEquals(Rule.NO_SCTS, assertIs<Verdict.Rejected>(noExemption.evaluate().verdict).rule)
        assertEquals(0, noExemption.chainsBuilt)
        val onAllow =
            RevoktPolicy.STRICT
                .newBuilder()
                .rule(
                    Rule.NO_SCTS,
                    Outcome.ALLOW,
                ).exempt(
                    Rule.NO_SCTS,
                    Exemption {
                        true
                    },
                ).build()
        val allowed = Run.of(honest, onAllow, engine = StubEngine.always(CrliteQueryResult.NO_SCTS))
        assertIs<Verdict.Accepted>(allowed.evaluate().verdict)
        assertEquals(0, allowed.chainsBuilt)
        val notFired =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_SCTS, Exemption { true })
                .build()
        val clean = Run.of(honest, notFired)
        assertIs<Verdict.Accepted>(clean.evaluate().verdict)
        assertEquals(0, clean.chainsBuilt)
    }

    @Test
    fun `the context holds the rule, every presented certificate, the path, host', now and the data states`() {
        val recording = Recording(answer = false)
        val policy =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_SCTS, recording)
                .build()
        val presented = listOf(h.leaf.der, h.intermediate.der, garbage(40))
        // "x." is host' of "x..": normalising again would strip the second dot.
        val run =
            Run(presented, policy, engine = StubEngine.always(CrliteQueryResult.NO_SCTS), host = "x.") { now ->
                Run.decideFixture(
                    dev.revokt.engine.walker.WalkerFixture(
                        "ctx",
                        "",
                        presented,
                        honest.snapshot,
                        honest.ok,
                        honest.walk,
                    ),
                    null,
                    now,
                )
            }
        val v = run.evaluate().verdict
        val c = recording.seen.single()
        assertEquals(Rule.NO_SCTS, c.rule)
        assertEquals("x.", c.host)
        assertEquals(NOW, c.nowMillis)
        assertEquals(v.path, c.path)
        assertEquals(v.dataStates, c.dataStates)
        assertEquals(CredentialType.X509, c.credentialType)
        val chain = c.chain!!
        assertEquals(3, chain.size)
        presented.forEachIndexed { i, der -> assertContentEquals(der, chain.der(i), "certificate $i") }
        assertTrue(chain.parsed(0))
        assertTrue(chain.parsed(1))
        assertFalse(chain.parsed(2), "the parser rejected it")
        assertContentEquals(h.intermediate.keyHash.toByteArray(), chain.spkiSha256(1))
        assertEquals(Rule.NO_SCTS, assertIs<Verdict.Rejected>(v).rule)
    }

    @Test
    fun `certificates decide never read are kept unparsed`() {
        val recording = Recording()
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .exempt(Rule.NO_DATA, recording)
                .build()
        val presented = listOf(garbage(40), h.intermediate.der)
        val f =
            dev.revokt.engine.walker
                .WalkerFixture("pf", "", presented, honest.snapshot, honest.ok, honest.walk)
        val v = Run.of(f, policy, snapshot(noGeneration())).evaluate().verdict
        val chain = recording.seen.single().chain!!
        assertEquals(2, chain.size)
        assertFalse(chain.parsed(0))
        assertFalse(chain.parsed(1), "the evaluation stopped at the leaf")
        assertIs<Verdict.Accepted>(v)
        assertEquals(setOf(Rule.NO_DATA, Rule.PARSE_FAILED), v.rules)
    }

    @Test
    fun `a throwing exemption is not exempt and fires ENGINE_ERROR with an EXEMPTION error`() {
        for (t in listOf(IllegalStateException("bad"), StackOverflowError())) {
            val policy =
                RevoktPolicy.DEFAULT
                    .newBuilder()
                    .exempt(Rule.NO_DATA) { throw t }
                    .build()
            val v = Run.of(honest, policy, snapshot(noGeneration())).evaluate().verdict
            assertEquals(Rule.NO_DATA, assertIs<Verdict.Rejected>(v).rule, "$t")
            assertEquals(setOf(Rule.NO_DATA, Rule.ENGINE_ERROR), v.rules, "$t")
            val error = engineErrors(v).single()
            assertEquals(EngineErrorProducer.EXEMPTION, error.producer)
            assertEquals("the exemption for NO_DATA threw $t", error.message)
            assertEquals(emptyList(), v.findings.filterIsInstance<Finding.Exempted>())
        }
        val strict =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_SCTS) {
                    error("bad")
                }.exempt(Rule.NOT_ENROLLED, Exemption { true })
                .build()
        val engine = StubEngine { if (it == key(1)) CrliteQueryResult.NO_SCTS else CrliteQueryResult.NOT_ENROLLED }
        val v =
            Run(listOf(h.leaf.der), strict, engine = engine) {
                decision(dev.revokt.PathStatus.FOUND, key(1), key(2))
            }.evaluate().verdict
        assertEquals(setOf(Rule.ENGINE_ERROR, Rule.NOT_ENROLLED, Rule.NO_SCTS), v.rules)
        assertEquals(Rule.ENGINE_ERROR, assertIs<Verdict.Rejected>(v).rule, "ENGINE_ERROR rejects under STRICT")
        assertEquals(listOf(Rule.NOT_ENROLLED), v.findings.filterIsInstance<Finding.Exempted>().map { it.rule })
    }

    @Test
    fun `and and or follow CEL - an absorbed throw is not recorded, a rethrown one is not exempt plus the error`() {
        val throws = Exemption { error("operand") }
        val yes = Exemption { true }
        val no = Exemption { false }
        val cases =
            listOf(
                "throws or yes" to (throws or yes) to (true to 0),
                "yes or throws" to (yes or throws) to (true to 0),
                "throws and no" to (throws and no) to (false to 0),
                "throws and yes" to (throws and yes) to (false to 1),
                "throws or no" to (throws or no) to (false to 1),
            )
        for ((named, want) in cases) {
            val (case, exemption) = named
            val (exempt, errors) = want
            val policy =
                RevoktPolicy.DEFAULT
                    .newBuilder()
                    .exempt(Rule.NO_DATA, exemption)
                    .build()
            val v = Run.of(honest, policy, snapshot(noGeneration())).evaluate().verdict
            assertEquals(exempt, v is Verdict.Accepted, case)
            assertEquals(errors, engineErrors(v).count { it.producer == EngineErrorProducer.EXEMPTION }, case)
            assertEquals(errors == 1, Rule.ENGINE_ERROR in v.rules, case)
        }
    }

    @Test
    fun `the enterprise recipe exempts the data rules under STRICT for a chain under the private anchor`() {
        val policy =
            RevoktPolicy.STRICT
                .newBuilder()
                .exemptAnchors(listOf(h.root.bytesHash.toByteArray()))
                .build()
        val outage = Run.of(honest, policy, snapshot(noGeneration())).evaluate().verdict
        assertIs<Verdict.Accepted>(outage)
        assertEquals(setOf(Rule.NO_DATA), outage.rules)
        assertEquals(listOf(Rule.NO_DATA), outage.findings.filterIsInstance<Finding.Exempted>().map { it.rule })
        val mirror =
            Run.of(
                honest,
                policy,
                snapshot(generation(40 * DAY, TrustClass.MIRROR)),
                StubEngine.always(CrliteQueryResult.NOT_ENROLLED),
            )
        val m = mirror.evaluate().verdict
        assertIs<Verdict.Accepted>(m)
        assertEquals(setOf(Rule.NOT_ENROLLED, Rule.STALE, Rule.UNSIGNED_DATA), m.rules)
        val otherRoot = h.w.root("R2", "Other root")
        val otherIssuer = h.w.cert("I2", h.w.name("Other intermediate"), otherRoot.subject, signer = otherRoot.key)
        val otherLeaf =
            h.w.cert(
                "L2",
                h.w.name("other.example"),
                otherIssuer.subject,
                signer = otherIssuer.key,
                key = h.w.leafKey(),
            )
        val stranger =
            h.fixture(
                "other",
                presented = listOf(otherLeaf, otherIssuer),
                walk = ExpectedWalk.found(),
                snapshot = listOf(h.root, otherRoot),
            )
        val r = Run.of(stranger, policy, snapshot(noGeneration())).evaluate().verdict
        assertEquals(Rule.NO_DATA, assertIs<Verdict.Rejected>(r).rule, "another anchor is not exempt")
        assertEquals(dev.revokt.PathStatus.FOUND, r.path.status)
        assertEquals(setOf(Dataset.CRLITE), r.dataStates.keys)
    }
}
