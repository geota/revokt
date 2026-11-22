// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt

import dev.revokt.engine.evaluate.snapshot
import dev.revokt.engine.walker.DecideContext
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.WalkerFixture
import dev.revokt.engine.walker.WalkerHarness
import dev.revokt.engine.walker.decide
import dev.revokt.engine.walker.fixture
import dev.revokt.testing.SymOids
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A server can turn a walker reason into `UNSUPPORTED_ALGORITHM` (#196 F1, #225, spec §5.1 decision step 6): a related
 * non-anchor counts its own unsupported signature OID before its link is verified, as mozilla::pkix runs
 * CheckIssuerIndependentProperties before VerifySignedData, and the leaf's own OID is deferred until it has an issuer
 * candidate. `[L]` is `NO_ISSUER(NO_CANDIDATE)`; `[L, D]`, where D verifies the leaf under a recovered key and signs
 * itself with an unsupported OID under an issuer no candidate matches, and `[L, J]`, where J does not verify the leaf,
 * are `NO_ISSUER(UNSUPPORTED_ALGORITHM)`. Both are the one rule `NO_ISSUER` (#225), so the label changes only the
 * diagnostic: the verdict is the same under every preset and every exemption. On a trust-manager binding
 * (`platformOnly`) every one of them is `NO_ISSUER(PLATFORM_ONLY)`, so `platformOnly()` matches whatever the label
 * would have been.
 */
@OptIn(RevoktTestingApi::class)
class UnsupportedAlgorithmLabelTest {
    private val h = Honest()

    private val d =
        h.w
            .cert("D", h.intermediate.subject, h.w.name("Nowhere"), sigOid = SymOids.UNSUPPORTED_SIGNATURE)
            .also { h.w.verifies(h.leaf, it.key) }

    private val leafOnly =
        h.fixture("relabel", "[L]", listOf(h.leaf), ExpectedWalk.notFound(NoIssuerReason.NO_CANDIDATE))

    private val withD =
        h.fixture(
            "relabel",
            "[L, D]",
            listOf(h.leaf, d),
            ExpectedWalk
                .notFound(
                    NoIssuerReason.UNANCHORED,
                ).copy(unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE)),
        )

    /** J is named like the leaf's issuer and signs itself with an unsupported OID, but no link verifies the leaf. */
    private val withJ =
        h.w.cert("J", h.intermediate.subject, h.w.name("Nowhere"), sigOid = SymOids.UNSUPPORTED_SIGNATURE).let { j ->
            h.fixture(
                "relabel",
                "[L, J]",
                listOf(h.leaf, j),
                ExpectedWalk
                    .notFound(NoIssuerReason.ALL_CANDIDATES_INVALID)
                    .copy(unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE), verifications = 1),
            )
        }

    /** A leaf whose own signature OID is unsupported: its OID is deferred until it has an issuer candidate. */
    private val leaf2 =
        h.w.cert(
            "L2",
            h.w.name("leaf.example"),
            h.intermediate.subject,
            sigOid = SymOids.UNSUPPORTED_SIGNATURE,
            key = h.w.leafKey(),
        )

    private val leaf2Only =
        h.fixture("deferral", "[L2]", listOf(leaf2), ExpectedWalk.notFound(NoIssuerReason.NO_CANDIDATE))

    private val leaf2WithIssuer =
        h.fixture(
            "deferral",
            "[L2, I]",
            listOf(leaf2, h.intermediate),
            ExpectedWalk
                .notFound(NoIssuerReason.ALL_CANDIDATES_INVALID)
                .copy(unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE), verifications = 1),
        )

    @Test
    fun `walker a related non-verifying candidate counts its own unsupported OID, as pkix checks it first`() {
        WalkerHarness.check(withJ)
        val decision = WalkerHarness.decide(withJ, fallback = null)
        assertUnsupportedLabel(decision.path)
        assertEquals(NoIssuerReason.ALL_CANDIDATES_INVALID, decision.detail.walkerReason)
    }

    @Test
    fun `decide the leaf's own unsupported OID counts only once an issuer candidate was found`() {
        WalkerHarness.check(leaf2Only)
        WalkerHarness.check(leaf2WithIssuer)
        val decided = WalkerHarness.decide(leaf2Only, fallback = null)
        assertEquals(PathStatus.NO_ISSUER, decided.path.status)
        assertEquals(PathReason.NO_CANDIDATE, decided.path.reason)
        assertEquals(emptyList(), decided.findings.filterIsInstance<Finding.UnsupportedAlgorithm>())
        assertUnsupportedLabel(WalkerHarness.decide(leaf2WithIssuer, fallback = null).path)
    }

    @Test
    fun `walker a related store anchor's own unsupported OID never counts`() {
        // A is named like the leaf's issuer and signs itself with an unsupported OID; no link verifies the leaf.
        val anchor =
            h.w.cert(
                "A",
                h.intermediate.subject,
                h.intermediate.subject,
                sigOid = SymOids.UNSUPPORTED_SIGNATURE,
            )
        val f =
            h.w.fixture(
                "relabel",
                "[L], anchor A",
                listOf(h.leaf),
                listOf(h.root, anchor),
                ExpectedWalk.notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 1),
            )
        WalkerHarness.check(f)
        val decision = WalkerHarness.decide(f, fallback = null)
        assertEquals(PathStatus.NO_ISSUER, decision.path.status)
        assertEquals(PathReason.ALL_CANDIDATES_INVALID, decision.path.reason)
    }

    @Test
    fun `walker an unrelated certificate is no candidate, so its own unsupported OID is never recorded`() {
        // U is not related to the leaf but verifies it, and signs itself with an unsupported OID.
        val u =
            h.w
                .cert("U", h.w.name("Other"), h.w.name("Nowhere"), sigOid = SymOids.UNSUPPORTED_SIGNATURE)
                .also { h.w.verifies(h.leaf, it.key) }
        val f =
            h.fixture(
                "relabel",
                "[L, U]",
                listOf(h.leaf, u),
                ExpectedWalk.notFound(NoIssuerReason.NO_CANDIDATE).copy(verifications = 0, candidatesExplored = 0),
            )
        WalkerHarness.check(f)
        val path = WalkerHarness.decide(f, fallback = null).path
        assertEquals(PathStatus.NO_ISSUER, path.status)
        assertEquals(PathReason.NO_CANDIDATE, path.reason)
    }

    @Test
    fun `walker the leaf alone records nothing and D's own unsupported OID is recorded without a candidate for D`() {
        WalkerHarness.check(leafOnly)
        WalkerHarness.check(withD)
    }

    @Test
    fun `decide the leaf alone is NO_CANDIDATE and the leaf with D is UNSUPPORTED_ALGORITHM`() {
        val alone = WalkerHarness.decide(leafOnly, fallback = null).path
        assertEquals(PathStatus.NO_ISSUER, alone.status)
        assertEquals(PathReason.NO_CANDIDATE, alone.reason)
        val decision = WalkerHarness.decide(withD, fallback = null)
        assertUnsupportedLabel(decision.path)
        assertEquals(NoIssuerReason.UNANCHORED, decision.detail.walkerReason)
        val unsupported = decision.findings.filterIsInstance<Finding.UnsupportedAlgorithm>().single()
        assertEquals(SymOids.UNSUPPORTED_SIGNATURE, unsupported.oid)
        assertEquals(true, unsupported.outcomeDepended)
    }

    @Test
    fun `the verdict is the same for every label under every preset and a NO_ISSUER exemption`() {
        val corp = Exemption.hostSuffixIn(listOf("example"))
        val policies =
            listOf(
                "DEFAULT" to RevoktPolicy.DEFAULT,
                "STRICT" to RevoktPolicy.STRICT,
                "STRICT, NO_ISSUER exempt" to
                    RevoktPolicy.STRICT
                        .newBuilder()
                        .exempt(Rule.NO_ISSUER, corp)
                        .build(),
                "DEFAULT, NO_ISSUER raised" to
                    RevoktPolicy.DEFAULT
                        .newBuilder()
                        .rule(Rule.NO_ISSUER, Outcome.REJECT)
                        .build(),
            )
        for ((name, policy) in policies) {
            val alone = verdict(leafOnly, policy)
            assertEquals(setOf(Rule.NO_ISSUER), alone.rules, name)
            for (relabelled in listOf(verdict(withD, policy), verdict(withJ, policy))) {
                assertEquals(setOf(Rule.NO_ISSUER), relabelled.rules, name)
                assertEquals(alone::class, relabelled::class, "$name: one verdict for every label")
                if (alone is Verdict.Rejected) {
                    assertEquals(Rule.NO_ISSUER, alone.rule, name)
                    assertEquals(Rule.NO_ISSUER, assertIs<Verdict.Rejected>(relabelled).rule, name)
                }
            }
        }
        val exempted =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_ISSUER, corp)
                .build()
        assertEquals(listOf(Rule.NO_ISSUER), exemptedRules(verdict(withD, exempted)))
        assertEquals(listOf(Rule.NO_ISSUER), exemptedRules(verdict(leafOnly, exempted)))
    }

    @Test
    fun `decide under platformOnly a fallback-failed NotFound is NO_ISSUER(PLATFORM_ONLY) whatever the label`() {
        for (f in listOf(leafOnly, withD, withJ, leaf2Only, leaf2WithIssuer)) {
            val d = WalkerHarness.decide(f, fallback = null, platformOnly = true)
            assertEquals(PathStatus.NO_ISSUER, d.path.status, "$f")
            assertEquals(PathReason.PLATFORM_ONLY, d.path.reason, "$f")
            assertEquals(f.walk.reason, d.detail.walkerReason, "$f: the walker's reason is kept")
            val findings = d.findings.filterIsInstance<Finding.UnsupportedAlgorithm>()
            assertEquals(f.walk.unsupportedOids, findings.map { it.oid }.toSet(), "$f: the OIDs are kept")
            assertTrue(findings.none { it.outcomeDepended }, "$f: outcomeDepended follows the reason")
        }
    }

    @Test
    fun `on a trust-manager binding hostSuffixIn and platformOnly exempts every label under STRICT`() {
        val corp = Exemption.hostSuffixIn(listOf("example")) and Exemption.platformOnly()
        val policy =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_ISSUER, corp)
                .build()
        for (f in listOf(leafOnly, withD, withJ, leaf2Only, leaf2WithIssuer)) {
            val v = verdict(f, policy, platformOnly = true)
            assertIs<Verdict.Accepted>(v, "$f")
            assertEquals(setOf(Rule.NO_ISSUER), v.rules, "$f")
            assertEquals(listOf(Rule.NO_ISSUER), exemptedRules(v), "$f")
            assertIs<Verdict.Rejected>(verdict(f, RevoktPolicy.STRICT, platformOnly = true), "$f: not exempt")
        }
    }

    private fun verdict(
        f: WalkerFixture,
        policy: RevoktPolicy,
        platformOnly: Boolean = false,
    ): Verdict =
        EvaluatorRig(
            f,
            policy,
            snapshot(),
            decidePresented = { chain, index, anchors, c ->
                val context = DecideContext(c.verifier, c.probe, c.crossCallMemo, c.fallback, c.nowMillis, platformOnly)
                decide(chain, index, anchors, context)
            },
        ).presented(f.presented, host = "www.example")

    /** [path] is `NO_ISSUER(UNSUPPORTED_ALGORITHM)`: the one rule, with the label a server can steer. */
    private fun assertUnsupportedLabel(path: Finding.Path) {
        assertEquals(PathStatus.NO_ISSUER, path.status)
        assertEquals(PathReason.UNSUPPORTED_ALGORITHM, path.reason)
    }

    private fun exemptedRules(v: Verdict): List<Rule> = v.findings.filterIsInstance<Finding.Exempted>().map { it.rule }
}
