// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.snapshot
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.WalkerFixture
import dev.revokt.engine.walker.WalkerHarness
import dev.revokt.testing.SymOids
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * A server can relabel `NO_ISSUER` as `ISSUER_UNVERIFIED` (#196 F1, spec §5.1 decision step 6): every certificate the
 * walk visits counts its own unsupported signature OID, as mozilla::pkix checks a non-anchor's signature algorithm
 * before it looks for an issuer. `[L]` is `NO_ISSUER`; `[L, D]`, where D verifies the leaf under a recovered key and
 * signs itself with an unsupported OID under an issuer no candidate matches, is `ISSUER_UNVERIFIED`. The two rules
 * share one outcome and one exemption, so the relabel changes only the diagnostic: the verdict is the same under every
 * preset and every exemption, whichever rule it was registered on.
 */
@OptIn(RevoktTestingApi::class)
class IssuerUnverifiedRelabelTest {
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

    @Test
    fun `walker the leaf alone records nothing and D's own unsupported OID is recorded without a candidate for D`() {
        WalkerHarness.check(leafOnly)
        WalkerHarness.check(withD)
    }

    @Test
    fun `decide the leaf alone is NO_ISSUER and the leaf with D is ISSUER_UNVERIFIED`() {
        val alone = WalkerHarness.decide(leafOnly, fallback = null).path
        assertEquals(PathStatus.NO_ISSUER, alone.status)
        assertEquals(NoIssuerReason.NO_CANDIDATE, alone.noIssuerReason)
        val decision = WalkerHarness.decide(withD, fallback = null)
        assertEquals(PathStatus.ISSUER_UNVERIFIED, decision.path.status)
        assertEquals(NoIssuerReason.UNANCHORED, decision.path.walkerReason)
        val unsupported = decision.findings.filterIsInstance<Finding.UnsupportedAlgorithm>().single()
        assertEquals(SymOids.UNSUPPORTED_SIGNATURE, unsupported.oid)
        assertEquals(true, unsupported.outcomeDepended)
    }

    @Test
    fun `the verdict is the same for both labels under every preset and an exemption on either rule`() {
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
                "STRICT, ISSUER_UNVERIFIED exempt" to
                    RevoktPolicy.STRICT
                        .newBuilder()
                        .exempt(Rule.ISSUER_UNVERIFIED, corp)
                        .build(),
                "DEFAULT, both raised by one rule()" to
                    RevoktPolicy.DEFAULT
                        .newBuilder()
                        .rule(Rule.ISSUER_UNVERIFIED, Outcome.REJECT)
                        .build(),
            )
        for ((name, policy) in policies) {
            val alone = verdict(leafOnly, policy)
            val relabelled = verdict(withD, policy)
            assertEquals(setOf(Rule.NO_ISSUER), alone.rules, name)
            assertEquals(setOf(Rule.ISSUER_UNVERIFIED), relabelled.rules, name)
            assertEquals(alone::class, relabelled::class, "$name: one verdict for both labels")
            if (alone is Verdict.Rejected) {
                assertEquals(Rule.NO_ISSUER, alone.rule, name)
                assertEquals(Rule.ISSUER_UNVERIFIED, assertIs<Verdict.Rejected>(relabelled).rule, name)
            }
        }
        val exempted =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_ISSUER, corp)
                .build()
        assertEquals(listOf(Rule.ISSUER_UNVERIFIED), exemptedRules(verdict(withD, exempted)))
        assertEquals(listOf(Rule.NO_ISSUER), exemptedRules(verdict(leafOnly, exempted)))
    }

    private fun verdict(
        f: WalkerFixture,
        policy: RevoktPolicy,
    ): Verdict = EvaluatorRig(f, policy, snapshot()).presented(f.presented, host = "www.example")

    private fun exemptedRules(v: Verdict): List<Rule> = v.findings.filterIsInstance<Finding.Exempted>().map { it.rule }
}
