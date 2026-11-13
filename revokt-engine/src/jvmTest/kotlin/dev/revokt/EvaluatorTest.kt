// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.EPOCH
import dev.revokt.engine.evaluate.NOW
import dev.revokt.engine.evaluate.StubEngine
import dev.revokt.engine.evaluate.engineErrors
import dev.revokt.engine.evaluate.generation
import dev.revokt.engine.update.GenerationSnapshot
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.FakeFallback
import dev.revokt.engine.walker.FixtureCert
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.K6_VALIDITY
import dev.revokt.engine.walker.WalkerCerts
import dev.revokt.engine.walker.WalkerFixturesS1ToAj
import dev.revokt.engine.walker.WalkerHarness
import dev.revokt.engine.walker.garbage
import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `Evaluator.evaluate` over one candidate index (spec §4 `revokt.evaluator`, `EvaluationRequest`; §5.1 decision steps
 * 1 to 8 with no step 1 or 4; §5.5; §11's 0.2 row): the lifecycle and index checks before any boundary, the one read
 * of each input at entry, `presented` and `verifiedPaths`, `pkixFallback(false)`, the time and host', and hostile
 * input, which never throws.
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class EvaluatorTest {
    private val h = Honest()

    private val honest =
        h.fixture("honest", presented = listOf(h.leaf, h.intermediate), walk = ExpectedWalk.found(h.path))

    private val chain = listOf(h.leaf.der, h.intermediate.der)

    private fun request(
        presented: List<FixtureCert>? = null,
        verified: List<List<FixtureCert>>? = null,
        host: String? = null,
        nowMillis: Long? = null,
    ): EvaluationRequest =
        EvaluationRequest
            .Builder()
            .apply {
                presented?.let { presented(it.map(FixtureCert::der)) }
                verified?.let { paths -> verifiedPaths(paths.map { p -> p.map(FixtureCert::der) }) }
                host(host)
                nowMillis?.let { nowMillis(it) }
            }.build()

    private fun keys(v: Verdict): List<ByteString> = v.path.issuerSpkiSha256s.map { it.toByteString() }

    @Test
    fun `outside STARTED and with no index evaluate throws IllegalStateException before any boundary`() {
        val engine = StubEngine.always(CrliteQueryResult.REVOKED)
        var clockReads = 0
        val rig = EvaluatorRig(honest, engine = engine, clock = { NOW.also { clockReads++ } })
        val requests = listOf(request(presented = listOf(h.leaf, h.intermediate)), request(verified = listOf(h.path)))
        for (state in listOf(RevoktLifecycle.CREATED, RevoktLifecycle.CLOSED)) {
            rig.lifecycle = state
            requests.forEach { assertFailsWith<IllegalStateException>("$state") { rig.evaluate(it) } }
        }
        rig.lifecycle = RevoktLifecycle.STARTED
        rig.indexed = null
        requests.forEach { assertFailsWith<IllegalStateException>("no index") { rig.evaluate(it) } }
        assertEquals(0, clockReads, "no clock read")
        assertEquals(0, rig.generationReads, "no generation read")
        assertEquals(0, rig.policyReads, "no policy read")
        assertEquals(emptyList(), engine.queries, "nothing queried")
        assertEquals(0, rig.verifications, "nothing walked")
    }

    @Test
    fun `a presented chain is walked over the index read at entry and reported under its snapshot id`() {
        val engine = StubEngine.always(CrliteQueryResult.NOT_REVOKED)
        val rig = EvaluatorRig(honest, engine = engine)
        val v = rig.presented(chain)
        assertIs<Verdict.Accepted>(v)
        assertEquals(PathStatus.FOUND, v.path.status)
        assertEquals(ChainSource.RECONSTRUCTED, v.path.source)
        assertEquals(WalkerHarness.SNAPSHOT_ID, v.path.anchorSnapshotId)
        assertEquals(WalkEnd.COMPLETE, v.path.endReason)
        assertEquals(listOf(h.intermediate.keyHash), keys(v))
        assertEquals(h.path.map { it.bytesHash }, v.path.reportedPathSha256s.map { it.toByteString() })
        assertEquals(listOf(h.intermediate.keyHash), engine.queries.map { it.issuerSpkiHash.toByteString() })
        assertTrue(rig.verifications > 0, "the walk verified the links")
        assertEquals(EPOCH, v.generationEpoch)
    }

    @Test
    fun `the index, the generation snapshot and the policy are read once per evaluation, never a stale one`() {
        val rig = EvaluatorRig(honest, engine = StubEngine.always(CrliteQueryResult.REVOKED))
        val first = rig.presented(chain)
        assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(first).rule)
        assertEquals(1, rig.lifecycleReads)
        assertEquals(1, rig.anchorReads)
        assertEquals(1, rig.generationReads)
        assertEquals(1, rig.policyReads)
        // Every input replaced between two evaluations: the second sees each new one.
        rig.indexed = EvaluatorRig.indexed(listOf(h.root.der), WalkerHarness.SNAPSHOT_ID + 1)
        rig.generation = GenerationSnapshot(EPOCH + 1, mapOf(Dataset.CRLITE to generation()), StubEngine.COVERAGE_END)
        rig.policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.REVOKED, Outcome.ALLOW)
                .build()
        val second = rig.presented(chain)
        assertIs<Verdict.Accepted>(second, "the new policy allows REVOKED")
        assertEquals(WalkerHarness.SNAPSHOT_ID + 1, second.path.anchorSnapshotId)
        assertEquals(EPOCH + 1, second.generationEpoch)
        assertEquals(2, rig.anchorReads)
        assertEquals(2, rig.generationReads)
        assertEquals(2, rig.policyReads)
        // And an index that no longer holds the root: the walk runs against the new one.
        rig.indexed = EvaluatorRig.indexed(emptyList(), WalkerHarness.SNAPSHOT_ID + 2)
        val third = rig.presented(chain)
        assertEquals(PathStatus.NO_ISSUER, third.path.status)
        assertEquals(WalkerHarness.SNAPSHOT_ID + 2, third.path.anchorSnapshotId)
    }

    @Test
    fun `verifiedPaths only is PLATFORM with anchorSnapshotId 0, no walk and no verifier call`() {
        val other = h.w.cert("I2", h.w.name("Other intermediate"), h.root.subject, signer = h.root.key)
        val engine = StubEngine.always(CrliteQueryResult.NOT_REVOKED)
        val rig = EvaluatorRig(honest, engine = engine)
        val v = rig.evaluate(request(verified = listOf(h.path, listOf(h.leaf, other, h.root), listOf(h.leaf))))
        assertIs<Verdict.Accepted>(v)
        assertEquals(PathStatus.FOUND, v.path.status)
        assertEquals(ChainSource.PLATFORM, v.path.source)
        assertEquals(0, v.path.anchorSnapshotId)
        assertNull(v.path.endReason)
        assertNull(v.path.endDepth)
        assertNull(v.path.walkerReason)
        assertFalse(v.path.usedFallback)
        assertEquals(3, v.path.pathsFound)
        assertEquals(0, rig.verifications, "trusted without re-verification")
        val leafKey = h.leaf.keyHash
        // Each path's second certificate, the leaf's own key for the one-certificate path, in path order.
        assertEquals(listOf(h.intermediate.keyHash, other.keyHash, leafKey), keys(v))
        assertEquals(keys(v), engine.queries.map { it.issuerSpkiHash.toByteString() })
        engine.queries.forEach { assertContentEquals(WalkerCerts.cert(h.leaf.der).serial, it.serial) }
        assertEquals(h.path.map { it.bytesHash }, v.path.reportedPathSha256s.map { it.toByteString() })
        assertEquals(TerminalKind.ANCHOR, v.path.terminalKind)
        assertEquals(h.root.bytesHash, v.path.anchorSha256?.toByteString())
        assertEquals(listOf<Finding>(), v.findings.filterIsInstance<Finding.FallbackNotUsed>())
    }

    @Test
    fun `a verified leaf that does not parse or is outside the keyability profile is PARSE_FAILED, never queried`() {
        val leaf6 =
            h.w.withValidity(K6_VALIDITY) {
                h.w.cert("L6", h.w.name("leaf.example"), h.intermediate.subject, signer = h.intermediate.key)
            }
        val engine = StubEngine.always(CrliteQueryResult.REVOKED)
        val rig = EvaluatorRig(honest, engine = engine)
        val k6 = rig.evaluate(request(verified = listOf(listOf(leaf6, h.intermediate, h.root))))
        assertEquals(PathStatus.PARSE_FAILED, k6.path.status)
        assertEquals(ParseReason.PRODUCER_UNKEYABLE, k6.path.parseReason)
        assertEquals(KeyabilityClause.TIME, k6.path.keyabilityClause)
        assertEquals(ChainSource.PLATFORM, k6.path.source)
        assertEquals(0, k6.path.anchorSnapshotId)
        assertNull(k6.crlite)
        val broken =
            rig.evaluate(
                EvaluationRequest
                    .Builder()
                    .verifiedPaths(listOf(listOf(garbage(40), h.intermediate.der)))
                    .build(),
            )
        assertEquals(PathStatus.PARSE_FAILED, broken.path.status)
        assertEquals(ParseReason.STRUCTURE, broken.path.parseReason)
        assertEquals(emptyList(), engine.queries, "never queried")
        assertIs<Verdict.Accepted>(broken, "PARSE_FAILED allows under DEFAULT")
    }

    @Test
    fun `a verified path whose issuer does not parse gives no key, and with no key at all it is ENGINE_ERROR`() {
        val engine = StubEngine.always(CrliteQueryResult.NOT_REVOKED)
        val rig = EvaluatorRig(honest, engine = engine)
        val paths = listOf(listOf(h.leaf.der, garbage(40), h.root.der), h.path.map(FixtureCert::der))
        val v = rig.evaluate(EvaluationRequest.Builder().verifiedPaths(paths).build())
        assertEquals(listOf(h.intermediate.keyHash), keys(v), "only the readable key")
        assertEquals(h.path.map { it.bytesHash }, v.path.reportedPathSha256s.map { it.toByteString() })
        assertEquals(2, v.path.pathsFound)
        assertIs<Verdict.Accepted>(v)
        val none =
            rig.evaluate(
                EvaluationRequest
                    .Builder()
                    .verifiedPaths(listOf(listOf(h.leaf.der, garbage(40))))
                    .build(),
            )
        assertEquals(setOf(Rule.ENGINE_ERROR), none.rules, "no keys is never a clean answer")
        assertEquals(listOf(EngineErrorProducer.BOUNDARY), engineErrors(none).map { it.producer })
        assertEquals(ChainSource.PLATFORM, none.path.source)
    }

    @Test
    fun `with presented and verifiedPaths the verified paths win and the exemptions see the presented chain`() {
        val seen = ArrayList<ExemptionContext>()
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.NO_SCTS, Outcome.REJECT)
                .exempt(Rule.NO_SCTS) {
                    seen += it
                    true
                }.build()
        val rig = EvaluatorRig(honest, policy = policy, engine = StubEngine.always(CrliteQueryResult.NO_SCTS))
        val decoy = h.w.cert("X", h.w.name("Decoy"), h.w.name("Nobody"))
        val v = rig.evaluate(request(presented = listOf(h.leaf, decoy), verified = listOf(h.path)))
        assertEquals(ChainSource.PLATFORM, v.path.source)
        assertEquals(0, v.path.anchorSnapshotId)
        assertEquals(0, rig.verifications, "no walk")
        assertEquals(listOf(h.intermediate.keyHash), keys(v))
        val presented = assertNotNull(seen.single().chain)
        assertEquals(2, presented.size)
        assertContentEquals(decoy.der, presented.der(1))
        assertTrue(presented.parsed(0), "the leaf the decision parsed")
        assertFalse(presented.parsed(1), "a certificate the decision never read")
        assertIs<Verdict.Accepted>(v)
    }

    @Test
    fun `with only verifiedPaths the exemptions see the first verified path`() {
        val seen = ArrayList<ExemptionContext>()
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.NO_SCTS, Outcome.REJECT)
                .exempt(Rule.NO_SCTS) {
                    seen += it
                    false
                }.build()
        val rig = EvaluatorRig(honest, policy = policy, engine = StubEngine.always(CrliteQueryResult.NO_SCTS))
        val v = rig.evaluate(request(verified = listOf(h.path), host = "Leaf.Example."))
        assertEquals(Rule.NO_SCTS, assertIs<Verdict.Rejected>(v).rule)
        val chain = assertIs<PresentedChain>(seen.single().chain)
        assertEquals(3, chain.size)
        h.path.forEachIndexed { i, c -> assertContentEquals(c.der, chain.der(i)) }
        assertEquals(listOf(true, true, false), List(3) { chain.parsed(it) }, "the leaf and the issuer were read")
        assertEquals("leaf.example", seen.single().host)
    }

    @Test
    fun `pkixFallback(false) - a 9-certificate NotFound is PATH_BUDGET_EXCEEDED with FallbackNotUsed(DISABLED)`() {
        val f = WalkerFixturesS1ToAj.af().single()
        assertEquals(9, f.presented.size)
        val disabled = EvaluatorRig(f).presented(f.presented)
        assertEquals(PathStatus.PATH_BUDGET_EXCEEDED, disabled.path.status)
        assertEquals(WalkEnd.COMPLETE, disabled.path.endReason)
        assertFalse(disabled.path.usedFallback)
        assertEquals(
            listOf(FallbackReason.DISABLED),
            disabled.findings.filterIsInstance<Finding.FallbackNotUsed>().map { it.reason },
        )
        assertEquals(Rule.PATH_BUDGET_EXCEEDED, assertIs<Verdict.Rejected>(disabled).rule)
        // Enabled, the chain is over FALLBACK_MAX_PRESENTED: SKIPPED, and the fallback is never called.
        val fallback = FakeFallback.fails()
        val skipped = EvaluatorRig(f, fallback = fallback).presented(f.presented)
        assertEquals(PathStatus.PATH_BUDGET_EXCEEDED, skipped.path.status)
        assertEquals(
            listOf(FallbackReason.SKIPPED),
            skipped.findings.filterIsInstance<Finding.FallbackNotUsed>().map { it.reason },
        )
        assertEquals(0, fallback.calls)
    }

    @Test
    fun `a NotFound reports the walker's reason directly, never PLATFORM_ONLY`() {
        val f = WalkerFixturesS1ToAj.ae().single()
        for (fallback in listOf(null, FakeFallback.fails())) {
            val v = EvaluatorRig(f, fallback = fallback).presented(f.presented)
            assertEquals(PathStatus.NO_ISSUER, v.path.status, "fallback $fallback")
            assertEquals(NoIssuerReason.UNANCHORED, v.path.noIssuerReason)
            assertEquals(NoIssuerReason.UNANCHORED, v.path.walkerReason)
            assertEquals(setOf(Rule.NO_ISSUER), v.rules)
        }
    }

    @Test
    fun `a fallback path is evaluated, given the snapshot read at entry and the evaluation time`() {
        val f = WalkerFixturesS1ToAj.ae().single()
        val fallback = FakeFallback.finds(h.leaf, h.intermediate, h.root)
        val rig = EvaluatorRig(f, fallback = fallback)
        val v =
            rig.evaluate(
                EvaluationRequest
                    .Builder()
                    .presented(f.presented)
                    .nowMillis(NOW - 5)
                    .build(),
            )
        assertEquals(1, fallback.calls)
        val (_, snapshot, now) = assertNotNull(fallback.seen)
        assertEquals(WalkerHarness.SNAPSHOT_ID, snapshot.id)
        assertEquals(NOW - 5, now)
        assertTrue(v.path.usedFallback)
    }

    @Test
    fun `MAX_PRESENTED is cut at step 3, as on every trust-manager path`() {
        val presented = listOf(h.leaf.der) + List(RevoktLimits.MAX_PRESENTED) { h.intermediate.der }
        val rig = EvaluatorRig(honest)
        val v = rig.presented(presented)
        assertEquals(PathStatus.PATH_BUDGET_EXCEEDED, v.path.status)
        assertEquals(WalkEnd.EXPLORATION_BUDGET, v.path.endReason)
        assertEquals(0, v.path.endDepth)
        assertEquals(0, rig.verifications, "no walk")
    }

    @Test
    fun `the request's nowMillis is the evaluation time, and without it the evaluator reads its clock once`() {
        var clockReads = 0
        val rig =
            EvaluatorRig(
                honest,
                generation = GenerationSnapshot(EPOCH, mapOf(Dataset.CRLITE to generation(0)), null),
                clock = { (NOW + 2 * DAY_MILLIS).also { clockReads++ } },
            )
        val pinned = rig.evaluate(request(presented = listOf(h.leaf, h.intermediate), nowMillis = NOW))
        assertEquals(0, clockReads, "nowMillis set: the clock is not read")
        assertEquals(0, pinned.dataStates.getValue(Dataset.CRLITE).ageMillis)
        val read = rig.presented(chain)
        assertEquals(1, clockReads)
        assertEquals(2 * DAY_MILLIS, read.dataStates.getValue(Dataset.CRLITE).ageMillis)
        val broken = EvaluatorRig(honest, clock = { error("clock") })
        val throwing = broken.presented(chain)
        assertEquals(PathStatus.NOT_WALKED, throwing.path.status, "a throwing clock is the boundary's error")
        assertEquals(ChainSource.RECONSTRUCTED, throwing.path.source)
        assertEquals(WalkerHarness.SNAPSHOT_ID, throwing.path.anchorSnapshotId)
        assertEquals(listOf(EngineErrorProducer.BOUNDARY), engineErrors(throwing).map { it.producer })
        // A path never reached still reports what the request would have consulted: no snapshot for verified paths.
        val verified = broken.evaluate(request(verified = listOf(h.path)))
        assertEquals(PathStatus.NOT_WALKED, verified.path.status)
        assertEquals(ChainSource.PLATFORM, verified.path.source)
        assertEquals(0, verified.path.anchorSnapshotId)
    }

    @Test
    fun `the host is host', and a host of a dot is no host`() {
        val hosts = ArrayList<String?>()
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.NO_SCTS, Outcome.REJECT)
                .exempt(
                    Rule.NO_SCTS,
                    Exemption.hostIn(listOf("leaf.example")) or
                        Exemption {
                            hosts += it.host
                            false
                        },
                ).build()
        val rig = EvaluatorRig(honest, policy = policy, engine = StubEngine.always(CrliteQueryResult.NO_SCTS))
        assertIs<Verdict.Accepted>(rig.presented(chain, host = "LEAF.Example."))
        assertEquals(emptyList(), hosts, "hostIn decided")
        assertIs<Verdict.Rejected>(rig.presented(chain, host = "."))
        assertEquals(listOf<String?>(null), hosts)
    }

    @Test
    fun `hostile input never throws - garbage chains and paths, and a throwing verifier, engine or fallback`() {
        val random = Random(135)
        val inputs =
            buildList {
                add(listOf(ByteArray(0)))
                add(listOf(garbage(RevoktLimits.MAX_CERT_BYTES + 1)))
                add(listOf(h.leaf.der, ByteArray(0), garbage(3)))
                repeat(200) {
                    add(List(random.nextInt(1, 6)) { random.nextBytes(random.nextInt(0, 300)) })
                }
                repeat(50) {
                    val der = h.leaf.der.copyOf()
                    der[random.nextInt(der.size)] = random.nextInt().toByte()
                    add(listOf(der, h.intermediate.der))
                }
            }
        val rigs =
            listOf(
                EvaluatorRig(honest),
                EvaluatorRig(honest, engine = StubEngine { error("engine") }),
                EvaluatorRig(honest, fallback = FakeFallback.throws(IllegalStateException("fallback"))),
                EvaluatorRig(honest, decidePresented = { _, _, _, _ -> throw NotImplementedError("decide") }),
            )
        for (rig in rigs) {
            for (input in inputs) {
                rig.presented(input)
                rig.evaluate(EvaluationRequest.Builder().verifiedPaths(listOf(input, input.reversed())).build())
                rig.evaluate(
                    EvaluationRequest
                        .Builder()
                        .presented(input)
                        .verifiedPaths(listOf(input))
                        .build(),
                )
            }
        }
    }

    private companion object {
        const val DAY_MILLIS: Long = 24L * 60 * 60 * 1_000
    }
}
