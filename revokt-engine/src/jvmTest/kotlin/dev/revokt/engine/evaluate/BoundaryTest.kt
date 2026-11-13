// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.EngineErrorProducer
import dev.revokt.Exemption
import dev.revokt.Finding
import dev.revokt.PathStatus
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.TrustClass
import dev.revokt.Verdict
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.PathDecision
import dev.revokt.engine.walker.WalkerHarness
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Spec §5.5's one catch boundary around decide and evaluate: every `VirtualMachineError` but `StackOverflowError`
 * propagates; anything else is `ENGINE_ERROR(BOUNDARY)` added to the rules fired so far; the data rules and data
 * states are on the verdict regardless; the path is `NOT_WALKED` when the throw preceded the walk; and the one clock
 * read is guarded.
 */
class BoundaryTest {
    private val h = Honest()
    private val presented = listOf(h.leaf.der, h.intermediate.der)
    private val honest =
        h.fixture(
            "honest",
            presented = listOf(h.leaf, h.intermediate),
            walk = ExpectedWalk.found(h.path),
        )

    private fun throwing(t: Throwable): (Long) -> Nothing = { throw t }

    @Test
    fun `an OutOfMemoryError propagates from the clock, decide, the engine and an exemption`() {
        val oom = OutOfMemoryError("test")
        val raise = throwing(oom)
        val strict =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_SCTS) { raise(0) }
                .build()
        val runs =
            listOf(
                "clock" to Run(presented, clock = { raise(0) }) { error("never decided") },
                "decide" to Run(presented, decide = raise),
                "engine" to Run.of(honest, engine = StubEngine { raise(0) }),
                "exemption" to Run.of(honest, strict, engine = StubEngine.always(CrliteQueryResult.NO_SCTS)),
            )
        for ((case, run) in runs) {
            assertSame(oom, assertFailsWith<OutOfMemoryError>(case) { run.evaluate() }, case)
        }
    }

    @Test
    fun `a StackOverflowError and a LinkageError are ENGINE_ERROR, not a policy reject`() {
        for (t in listOf(
            StackOverflowError("deep"),
            LinkageError("r8"),
            IllegalStateException("bug"),
            NotImplementedError(),
        )) {
            val v = Run(presented, decide = throwing(t)).evaluate().verdict
            assertIs<Verdict.Accepted>(v, "$t under DEFAULT")
            assertEquals(setOf(Rule.ENGINE_ERROR), v.rules, "$t")
            assertEquals(PathStatus.NOT_WALKED, v.path.status, "$t")
            val error = engineErrors(v).single()
            assertEquals(EngineErrorProducer.BOUNDARY, error.producer, "$t")
            assertNull(error.engineName, "$t")
            assertEquals("caught $t", error.message)
            val strict = Run(presented, RevoktPolicy.STRICT, decide = throwing(t)).evaluate().verdict
            assertEquals(Rule.ENGINE_ERROR, assertIs<Verdict.Rejected>(strict).rule, "$t under STRICT")
        }
    }

    @Test
    fun `a throw after a REVOKED answer keeps REVOKED, and only the answered keys have findings`() {
        val engine =
            StubEngine {
                if (it == key(1)) CrliteQueryResult.REVOKED else error("engine bug")
            }
        val run = Run(presented, engine = engine) { decision(PathStatus.FOUND, key(1), key(2), key(3)) }
        val v = run.evaluate().verdict
        assertEquals(setOf(Rule.REVOKED, Rule.ENGINE_ERROR), v.rules)
        assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(PathStatus.FOUND, v.path.status, "the walk ran")
        assertEquals(listOf(CrliteQueryResult.REVOKED), v.findings.filterIsInstance<Finding.Crlite>().map { it.result })
        assertEquals(CrliteQueryResult.REVOKED, v.crlite?.result)
        assertEquals(2, engine.queries.size, "the third key is never asked")
        assertEquals(listOf(EngineErrorProducer.BOUNDARY), engineErrors(v).map { it.producer })
    }

    @Test
    fun `a throwing engine is the boundary's error, and the path the walk reached is kept`() {
        val v = Run.of(honest, engine = StubEngine { throw IllegalArgumentException("no") }).evaluate().verdict
        assertEquals(setOf(Rule.ENGINE_ERROR), v.rules)
        assertEquals(PathStatus.FOUND, v.path.status)
        assertNull(v.crlite)
        assertIs<Verdict.Accepted>(v)
    }

    @Test
    fun `data rules and data states are on every boundary verdict`() {
        val system = snapshot(generation(400 * DAY, TrustClass.SYSTEM))
        val v =
            Run(
                presented,
                RevoktPolicy.STRICT,
                system,
                decide = throwing(IllegalStateException()),
            ).evaluate().verdict
        assertEquals(setOf(Rule.ENGINE_ERROR, Rule.STALE, Rule.UNSIGNED_DATA), v.rules)
        assertEquals(setOf(Rule.STALE, Rule.UNSIGNED_DATA), v.dataStates.getValue(Dataset.CRLITE).rules)
        assertEquals(Rule.ENGINE_ERROR, assertIs<Verdict.Rejected>(v).rule)
    }

    @Test
    fun `a throwing clock is ENGINE_ERROR(BOUNDARY), never walks, and leaves the data rules that need no time`() {
        var decided = 0
        val v =
            Run(presented, snapshot = snapshot(noGeneration()), clock = { error("clock") }) {
                decided++
                error("unreachable")
            }.evaluate().verdict
        assertEquals(0, decided)
        assertEquals(PathStatus.NOT_WALKED, v.path.status)
        assertEquals(setOf(Rule.NO_DATA, Rule.ENGINE_ERROR), v.rules)
        assertEquals(Rule.NO_DATA, assertIs<Verdict.Rejected>(v).rule)
        val old =
            Run(
                presented,
                RevoktPolicy.STRICT,
                snapshot(generation(400 * DAY, TrustClass.SYSTEM)),
                clock = { error("clock") },
            ) {
                error("unreachable")
            }.evaluate().verdict
        assertNull(old.dataStates.getValue(Dataset.CRLITE).ageMillis)
        assertEquals(setOf(Rule.ENGINE_ERROR, Rule.UNSIGNED_DATA), old.rules, "no age, so no STALE")
    }

    @Test
    fun `no exemption runs after the boundary caught a throw`() {
        var calls = 0
        val exempting =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .exempt(Rule.NO_DATA) {
                    calls++
                    true
                }.build()
        val v =
            Run(
                presented,
                exempting,
                snapshot(noGeneration()),
                decide = throwing(IllegalStateException()),
            ).evaluate().verdict
        assertEquals(0, calls)
        assertEquals(Rule.NO_DATA, assertIs<Verdict.Rejected>(v).rule)
        val unsigned =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.UNSIGNED_DATA) {
                    calls++
                    true
                }.build()
        val system = snapshot(generation(trustClass = TrustClass.SYSTEM))
        val failingEngine = Run.of(honest, unsigned, system, StubEngine { error("x") }).evaluate().verdict
        assertEquals(0, calls)
        assertEquals(setOf(Rule.ENGINE_ERROR, Rule.UNSIGNED_DATA), failingEngine.rules)
        assertEquals(emptyList(), failingEngine.findings.filterIsInstance<Finding.Exempted>())
    }

    @Test
    fun `a throw building the exemptions' chain is the boundary's error and exempts nothing`() {
        val exempting =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NOT_ENROLLED, Exemption { true })
                .exempt(Rule.NO_SCTS, Exemption { true })
                .build()
        var built = 0
        val run = Run.of(honest, exempting, engine = StubEngine { CrliteQueryResult.NOT_ENROLLED })
        val v =
            evaluate(
                EvaluationInput(run.presented, null, run.snapshot, run.policy.form, WalkerHarness.SNAPSHOT_ID),
                NamedEngine(run.engine),
                run.clock,
                run.decide,
                chainOf = { _, _ ->
                    built++
                    error("chain bug")
                },
            ).verdict
        assertEquals(1, built)
        assertEquals(setOf(Rule.ENGINE_ERROR, Rule.NOT_ENROLLED), v.rules)
        assertEquals(Rule.ENGINE_ERROR, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(emptyList(), v.findings.filterIsInstance<Finding.Exempted>())
        assertTrue(engineErrors(v).single().message.startsWith("caught java.lang.IllegalStateException: chain bug"))
    }

    @Test
    fun `a throwable whose toString throws is named by its class`() {
        class Hostile : RuntimeException() {
            override fun toString(): String = error("hostile")
        }
        val v = Run(presented, decide = throwing(Hostile())).evaluate().verdict
        assertEquals("caught Hostile", engineErrors(v).single().message)
    }
}
