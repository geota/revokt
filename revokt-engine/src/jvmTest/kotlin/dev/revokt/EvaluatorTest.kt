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
 * of each input at entry, `presented` and `verifiedPath`, `pkixFallback(false)`, the time and host', and hostile
 * input, which never throws and never misses a revoked key on a found path.
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class EvaluatorTest {
    private val h = Honest()

    private val honest =
        h.fixture("honest", presented = listOf(h.leaf, h.intermediate), walk = ExpectedWalk.found(h.path))

    private val chain = listOf(h.leaf.der, h.intermediate.der)

    private fun request(
        presented: List<FixtureCert>? = null,
        verified: List<FixtureCert>? = null,
        host: String? = null,
        nowMillis: Long? = null,
    ): EvaluationRequest =
        EvaluationRequest
            .Builder()
            .apply {
                presented?.let { presented(it.map(FixtureCert::der)) }
                verified?.let { path -> verifiedPath(path.map(FixtureCert::der)) }
                host(host)
                nowMillis?.let { nowMillis(it) }
            }.build()

    private fun keys(v: Verdict): List<ByteString> = v.path.issuerSpkiSha256s.map { it.toByteString() }

    @Test
    fun `outside STARTED and with no index evaluate throws IllegalStateException before any boundary`() {
        val engine = StubEngine.always(CrliteQueryResult.REVOKED)
        var clockReads = 0
        val rig = EvaluatorRig(honest, engine = engine, clock = { NOW.also { clockReads++ } })
        val requests = listOf(request(presented = listOf(h.leaf, h.intermediate)), request(verified = h.path))
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
    fun `verifiedPath only is PLATFORM with anchorSnapshotId 0, no walk and no verifier call`() {
        val engine = StubEngine.always(CrliteQueryResult.NOT_REVOKED)
        val rig = EvaluatorRig(honest, engine = engine)
        val v = rig.evaluate(request(verified = h.path))
        assertIs<Verdict.Accepted>(v)
        assertEquals(PathStatus.FOUND, v.path.status)
        assertEquals(ChainSource.PLATFORM, v.path.source)
        assertEquals(0, v.path.anchorSnapshotId)
        assertNull(v.path.endReason)
        assertNull(v.path.endDepth)
        assertNull(v.path.walkerReason)
        assertFalse(v.path.usedFallback)
        assertEquals(1, v.path.pathsFound)
        assertEquals(0, rig.verifications, "trusted without re-verification")
        assertEquals(listOf(h.intermediate.keyHash), keys(v), "the path's second certificate")
        assertEquals(keys(v), engine.queries.map { it.issuerSpkiHash.toByteString() })
        assertContentEquals(WalkerCerts.cert(h.leaf.der).serial, engine.queries.single().serial)
        assertEquals(h.path.map { it.bytesHash }, v.path.reportedPathSha256s.map { it.toByteString() })
        assertEquals(TerminalKind.ANCHOR, v.path.terminalKind)
        assertEquals(h.root.bytesHash, v.path.anchorSha256?.toByteString())
        assertEquals(listOf<Finding>(), v.findings.filterIsInstance<Finding.FallbackNotUsed>())
    }

    @Test
    fun `a one-certificate verified path skips the keyability check only when it is an anchor of the entry snapshot`() {
        // Step 2's rule (the maintainer's decision on #195): the caller's path does not make its leaf an anchor.
        assertEquals(KeyabilityClause.KEY, WalkerCerts.cert(h.root.der).keyabilityClause)
        assertEquals(KeyabilityClause.KEY, WalkerCerts.cert(h.intermediate.der).keyabilityClause)
        val engine = StubEngine.always(CrliteQueryResult.NOT_REVOKED)
        val rig = EvaluatorRig(honest, engine = engine)
        // An anchor by bytes: FOUND, keyed by its own SPKI, though outside the keyability profile.
        val anchor = rig.evaluate(request(verified = listOf(h.root)))
        assertEquals(PathStatus.FOUND, anchor.path.status)
        assertEquals(listOf(h.root.keyHash), keys(anchor))
        assertEquals(listOf(h.root.bytesHash), anchor.path.reportedPathSha256s.map { it.toByteString() })
        assertEquals(WalkerHarness.SNAPSHOT_ID, anchor.path.anchorSnapshotId, "the snapshot step 2 consulted")
        assertEquals(ChainSource.PLATFORM, anchor.path.source)
        // Not an anchor, outside the profile: gated like any leaf, never queried.
        val claimed = rig.evaluate(request(verified = listOf(h.intermediate)))
        assertEquals(PathStatus.PARSE_FAILED, claimed.path.status)
        assertEquals(ParseReason.PRODUCER_UNKEYABLE, claimed.path.parseReason)
        assertEquals(KeyabilityClause.KEY, claimed.path.keyabilityClause)
        assertEquals(WalkerHarness.SNAPSHOT_ID, claimed.path.anchorSnapshotId)
        assertEquals(listOf(h.root.keyHash), engine.queries.map { it.issuerSpkiHash.toByteString() }, "one query")
        // Not an anchor, inside the profile: keyed by its own SPKI, as the issue's one-certificate rule says.
        val keyable = rig.evaluate(request(verified = listOf(h.leaf)))
        assertEquals(PathStatus.FOUND, keyable.path.status)
        assertEquals(listOf(h.leaf.keyHash), keys(keyable))
        // An anchor leaf on a longer path is gated: step 2 decides a leaf alone.
        val longer = rig.evaluate(request(verified = listOf(h.root, h.root)))
        assertEquals(PathStatus.PARSE_FAILED, longer.path.status)
        assertEquals(0, longer.path.anchorSnapshotId, "a longer path consults no snapshot")
        // The snapshot read at entry decides: once the root is gone from it, the same path is gated.
        rig.indexed = EvaluatorRig.indexed(emptyList(), WalkerHarness.SNAPSHOT_ID + 1)
        val gone = rig.evaluate(request(verified = listOf(h.root)))
        assertEquals(PathStatus.PARSE_FAILED, gone.path.status)
        assertEquals(WalkerHarness.SNAPSHOT_ID + 1, gone.path.anchorSnapshotId)
        // A one-certificate path that never reached decide reports the snapshot id too.
        val noClock = EvaluatorRig(honest, clock = { error("clock") }).evaluate(request(verified = listOf(h.root)))
        assertEquals(PathStatus.NOT_WALKED, noClock.path.status)
        assertEquals(WalkerHarness.SNAPSHOT_ID, noClock.path.anchorSnapshotId)
    }

    @Test
    fun `a verified leaf that does not parse or is outside the keyability profile is PARSE_FAILED, never queried`() {
        val leaf6 =
            h.w.withValidity(K6_VALIDITY) {
                h.w.cert("L6", h.w.name("leaf.example"), h.intermediate.subject, signer = h.intermediate.key)
            }
        val engine = StubEngine.always(CrliteQueryResult.REVOKED)
        val rig = EvaluatorRig(honest, engine = engine)
        val k6 = rig.evaluate(request(verified = listOf(leaf6, h.intermediate, h.root)))
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
                    .verifiedPath(listOf(garbage(40), h.intermediate.der))
                    .build(),
            )
        assertEquals(PathStatus.PARSE_FAILED, broken.path.status)
        assertEquals(ParseReason.STRUCTURE, broken.path.parseReason)
        assertEquals(emptyList(), engine.queries, "never queried")
        assertIs<Verdict.Accepted>(broken, "PARSE_FAILED allows under DEFAULT")
    }

    @Test
    fun `a verified path whose issuer does not parse has no key, which is ENGINE_ERROR, never a clean answer`() {
        val engine = StubEngine.always(CrliteQueryResult.NOT_REVOKED)
        val request =
            EvaluationRequest
                .Builder()
                .verifiedPath(listOf(h.leaf.der, garbage(40), h.root.der))
                .build()
        val v = EvaluatorRig(honest, engine = engine).evaluate(request)
        assertEquals(setOf(Rule.ENGINE_ERROR), v.rules)
        assertEquals(emptyList(), keys(v))
        assertEquals(emptyList(), engine.queries)
        assertEquals(listOf(EngineErrorProducer.BOUNDARY), engineErrors(v).map { it.producer })
        assertEquals(ChainSource.PLATFORM, v.path.source)
        val strict = EvaluatorRig(honest, RevoktPolicy.STRICT, engine = engine).evaluate(request)
        assertEquals(Rule.ENGINE_ERROR, assertIs<Verdict.Rejected>(strict).rule)
    }

    @Test
    fun `a verified path for another leaf cannot be paired with a presented chain`() {
        // #195 review: the leaf's serial queried under another chain's issuer missed a revoked leaf under STRICT.
        val i9 = h.w.cert("I9", h.w.name("Intermediate 9"), h.root.subject, signer = h.root.key)
        val leaf1 = h.w.cert("L1", h.w.name("other.example"), i9.subject, signer = i9.key, key = h.w.leafKey())
        val e =
            assertFailsWith<IllegalArgumentException> {
                request(presented = listOf(h.leaf, h.intermediate), verified = listOf(leaf1, i9, h.root))
            }
        assertEquals("verifiedPath does not start with the presented leaf", e.message)
    }

    @Test
    fun `with presented and verifiedPath the verified path wins and is the exemptions' chain`() {
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
        val decoy = h.w.cert("X", h.w.name("Decoy"), h.w.name("Nobody"))
        val v = rig.evaluate(request(presented = listOf(h.leaf, decoy), verified = h.path, host = "Leaf.Example."))
        assertEquals(Rule.NO_SCTS, assertIs<Verdict.Rejected>(v).rule)
        assertEquals(ChainSource.PLATFORM, v.path.source)
        assertEquals(0, v.path.anchorSnapshotId)
        assertEquals(0, rig.verifications, "no walk")
        assertEquals(listOf(h.intermediate.keyHash), keys(v))
        val chain = assertIs<PresentedChain>(seen.single().chain)
        assertEquals(3, chain.size, "the reported path, not the presented chain")
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
        val verified = broken.evaluate(request(verified = h.path))
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
    fun `hostile input never throws, and a found path with a revoked key is always Rejected(REVOKED)`() {
        val random = Random(135)
        val inputs =
            buildList {
                add(listOf(ByteArray(0)))
                add(listOf(garbage(RevoktLimits.MAX_CERT_BYTES + 1)))
                add(listOf(h.leaf.der, ByteArray(0), garbage(3)))
                add(chain)
                add(h.path.map(FixtureCert::der))
                add(chain + garbage(40))
                repeat(200) {
                    add(List(random.nextInt(1, 6)) { random.nextBytes(random.nextInt(0, 300)) })
                }
                repeat(50) {
                    val der = h.leaf.der.copyOf()
                    der[random.nextInt(der.size)] = random.nextInt().toByte()
                    add(listOf(der, h.intermediate.der))
                }
                repeat(50) {
                    val path = h.path.map { it.der.copyOf() }
                    val c = path[random.nextInt(path.size)]
                    c[random.nextInt(c.size)] = random.nextInt().toByte()
                    add(path)
                }
            }
        val throwingVerifier: (SignatureVerifier) -> SignatureVerifier = { sym ->
            object : SignatureVerifier by sym {
                override fun verify(
                    sigAlg: ByteArray,
                    spki: ByteArray,
                    message: ByteArray,
                    signature: ByteArray,
                ): VerifyResult = error("verifier")
            }
        }
        val revoking = { StubEngine.always(CrliteQueryResult.REVOKED) }
        val oracles =
            listOf(
                EvaluatorRig(honest, engine = revoking()),
                EvaluatorRig(honest, engine = revoking(), verifier = throwingVerifier),
                EvaluatorRig(honest, engine = revoking(), fallback = FakeFallback.throws(IllegalStateException("x"))),
                EvaluatorRig(honest, RevoktPolicy.STRICT, engine = revoking()),
            )
        val others =
            listOf(
                EvaluatorRig(honest, engine = StubEngine { error("engine") }),
                EvaluatorRig(honest, decidePresented = { _, _, _, _ -> throw NotImplementedError("decide") }),
            )
        var found = 0
        for (rig in oracles + others) {
            for (input in inputs) {
                val verdicts =
                    listOf(
                        rig.presented(input),
                        rig.evaluate(EvaluationRequest.Builder().verifiedPath(input).build()),
                        rig.evaluate(
                            EvaluationRequest
                                .Builder()
                                .presented(listOf(input[0]) + input.reversed())
                                .verifiedPath(input)
                                .build(),
                        ),
                    )
                if (rig in oracles) found += verdicts.count { revokedOracle(it, "$input") }
            }
        }
        assertTrue(found > 0, "the oracle saw found paths with a key")
    }

    /**
     * The oracle under an engine that revokes every key: a found path with a key is `Rejected(REVOKED)`, and one with
     * no key (an issuer revokt cannot parse) is never a clean answer. True when [v] is a found path with a key.
     */
    private fun revokedOracle(
        v: Verdict,
        case: String,
    ): Boolean {
        if (v.path.status != PathStatus.FOUND) return false
        if (v.path.issuerSpkiSha256s.isEmpty()) {
            assertTrue(Rule.ENGINE_ERROR in v.rules, case)
            return false
        }
        assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(v, case).rule, case)
        return true
    }

    private companion object {
        const val DAY_MILLIS: Long = 24L * 60 * 60 * 1_000
    }
}
