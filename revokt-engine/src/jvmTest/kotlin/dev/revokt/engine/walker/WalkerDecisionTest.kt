// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import kotlin.test.Test

/**
 * The decision columns of the §9 walker fixtures (expected `PathStatus` / `PathReason`, the `Finding.Path` fields and
 * the decision's detail, the verdict's relation to the honest chain) on the JVM walker and the JVM walker with the
 * fallback disabled, both in the walker-only harness (spec §9, §5.1 decision steps 2 to 8; #136, #140). Each test runs
 * every case of one row on both paths through [WalkerDecisionRunner]; the rows are [WalkerDecisionRows] and
 * [WalkerFixturesJ], the Walk column [WalkerFixtureTest].
 */
class WalkerDecisionTest {
    private fun run(rows: List<DecisionRow>) {
        WalkerDecisionRunner.check(rows)
    }

    @Test
    fun `walker (a) random-key fake issuer decides as the honest chain on both paths`() = run(WalkerDecisionRows.a())

    @Test
    fun `walker (b) ECDSA-recovered second key decides as the honest chain on both paths`() =
        run(WalkerDecisionRows.b())

    @Test
    fun `walker (c) RSA duplicate-signature key decides as the honest chain on both paths`() =
        run(WalkerDecisionRows.c())

    @Test
    fun `walker (d) recovered-key fake with an unsupported own signature is Found with outcomeDepended false`() =
        run(WalkerDecisionRows.d())

    @Test
    fun `walker (e) 8, 16 and 63 related junk ahead give the honest verdict`() = run(WalkerDecisionRows.e())

    @Test
    fun `walker (f) cross-signed chain with both roots in the snapshot reports the first path`() =
        run(WalkerDecisionRows.f())

    @Test
    fun `walker (g) chain omitting the intermediate is NO_ISSUER(NO_CANDIDATE) on both paths`() =
        run(WalkerDecisionRows.g())

    @Test
    fun `walker (h) self-signed non-anchor and an A-B loop decide as the honest chain`() = run(WalkerDecisionRows.h())

    @Test
    fun `walker (i) one past MAX_EXPLORED is PATH_BUDGET_EXCEEDED(EXPLORATION_BUDGET) with the fallback skipped`() =
        run(WalkerDecisionRows.i())

    @Test
    fun `walker (k) same-key decoy with garbage signature decides as the honest chain`() = run(WalkerDecisionRows.k())

    @Test
    fun `walker (k2) EC-key decoy under an RSA-signed leaf decides as the honest chain`() = run(WalkerDecisionRows.k2())

    @Test
    fun `walker (l) retired non-anchor cross-certificate first decides as the honest chain`() =
        run(WalkerDecisionRows.l())

    @Test
    fun `walker (m) sound path then 62 related junk decides as the honest chain`() = run(WalkerDecisionRows.m())

    @Test
    fun `walker (n) unsupported candidate on a dead branch is Found with outcomeDepended false`() =
        run(WalkerDecisionRows.n())

    @Test
    fun `walker (o) the presented order picks the one key, REVOKED only through the honest intermediate`() =
        run(WalkerDecisionRows.o())

    @Test
    fun `walker (p) name-encoding mismatch decides as the honest chain`() = run(WalkerDecisionRows.p())

    @Test
    fun `walker (q) depth-9 bridge decides as the honest chain`() = run(WalkerDecisionRows.q())

    @Test
    fun `walker (r) TBS and outer OID mismatch carries AlgorithmIdMismatch, NULL vs absent none`() =
        run(WalkerDecisionRows.r())

    @Test
    fun `walker (s1) 62 related junk and the attacker CA last is Found through the honest intermediate, REVOKED`() =
        run(WalkerDecisionRows.s1())

    @Test
    fun `walker (s2) 255 related junk is PATH_BUDGET_EXCEEDED with no key evaluated`() = run(WalkerDecisionRows.s2())

    @Test
    fun `walker (t) 300 related junk is PATH_BUDGET_EXCEEDED with no key evaluated`() = run(WalkerDecisionRows.t())

    @Test
    fun `walker (v) honest chain against a 200-anchor snapshot gives the honest verdict`() = run(WalkerDecisionRows.v())

    @Test
    fun `walker (v2) honest chain with a retired-root cross-certificate gives the honest verdict`() =
        run(WalkerDecisionRows.v2())

    @Test
    fun `walker (w) dense cross-certified mesh reports leaf to I to anchor`() = run(WalkerDecisionRows.w())

    @Test
    fun `walker (x) self-signed anchor as server certificate is Found with its own key on both paths`() =
        run(WalkerDecisionRows.x())

    @Test
    fun `walker (y) junk below the leaf one past the budget is PATH_BUDGET_EXCEEDED with the fallback skipped`() =
        run(WalkerDecisionRows.y())

    @Test
    fun `walker (y2) store root first below the leaf decides as the honest chain`() = run(WalkerDecisionRows.y2())

    @Test
    fun `walker (z) unrelated unsupported key OID is NO_ISSUER(UNANCHORED) with no UnsupportedAlgorithm`() =
        run(WalkerDecisionRows.z())

    @Test
    fun `walker (aa) root-issued leaf with the root presented has pathsFound 1`() = run(WalkerDecisionRows.aa())

    @Test
    fun `walker (ab) PARSE_FAILED leaf with no CRLite generation is rule NO_DATA on both paths`() =
        run(WalkerDecisionRows.ab())

    @Test
    fun `walker (ac) an issuer unrelated by encoding is reached by the fallback only`() = run(WalkerDecisionRows.ac())

    @Test
    fun `walker (ad) Budget keys the fallback's honest key, and none with the fallback disabled`() =
        run(WalkerDecisionRows.ad())

    @Test
    fun `walker (ae) walker UNANCHORED and the fallback failed reports the walker reason in the harness`() =
        run(WalkerDecisionRows.ae())

    @Test
    fun `walker (af) 9 presented and a link the walker cannot reproduce is PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)`() =
        run(WalkerDecisionRows.af())

    @Test
    fun `walker (ag) 70 presented is cut at step 3 with no FallbackNotUsed on both paths`() =
        run(WalkerDecisionRows.ag())

    @Test
    fun `walker (ah) duplicate-signature subtrees are PATH_BUDGET_EXCEEDED(EXPLORATION_BUDGET)`() =
        run(WalkerDecisionRows.ah())

    @Test
    fun `walker (ai) 17 certificates is Found and 18 is PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT)`() =
        run(WalkerDecisionRows.ai())

    @Test
    fun `walker (aj) two unrelated anchored issuers give the fallback's outcome in every order`() =
        run(WalkerDecisionRows.aj())

    @Test
    fun `walker (j) ML-DSA anchor on a provider without ML-DSA is NO_ISSUER(UNSUPPORTED_ALGORITHM)`() =
        run(WalkerFixturesJ.j())

    @Test
    fun `walker (j2) brainpool anchor on SunEC is NO_ISSUER(ALL_CANDIDATES_INVALID) with no UnsupportedAlgorithm`() =
        run(WalkerFixturesJ.j2())
}
