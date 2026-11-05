// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The expected Walk column of the §9 walker fixtures, in the walker-only harness (spec §9, §5.1): one test per row id,
 * every case of the row, the cross-call memo cleared. The rows themselves are [WalkerFixtures].
 */
class WalkerFixtureTest {
    private fun run(rows: List<WalkerFixture>): List<Walk> {
        assertTrue(rows.isNotEmpty())
        return rows.map { WalkerHarness.check(it) }
    }

    @Test
    fun `walker (a) random-key fake issuer`() {
        run(WalkerFixtures.a())
    }

    @Test
    fun `walker (b) ECDSA-recovered second key`() {
        run(WalkerFixtures.b())
    }

    @Test
    fun `walker (c) RSA duplicate-signature key`() {
        run(WalkerFixtures.c())
    }

    @Test
    fun `walker (d) recovered-key fake with an unsupported own signature under a real anchor`() {
        run(WalkerFixtures.d())
    }

    @Test
    fun `walker (e) 8, 16 and 63 related junk ahead of the real intermediate`() {
        assertEquals(3, run(WalkerFixtures.e()).size)
    }

    @Test
    fun `walker (f) cross-signed chain with both roots in the snapshot gives the first path`() {
        run(WalkerFixtures.f())
    }

    @Test
    fun `walker (g) chain omitting the intermediate is NO_CANDIDATE`() {
        run(WalkerFixtures.g())
    }

    @Test
    fun `walker (h) self-signed non-anchor and an A-B loop`() {
        run(WalkerFixtures.h())
    }

    @Test
    fun `walker (i) 65 related junk at the leaf is RELATED_BUDGET after 64 explorations`() {
        run(WalkerFixtures.i())
    }

    @Test
    fun `walker (k) same-key decoy with garbage signature`() {
        run(WalkerFixtures.k())
    }

    @Test
    fun `walker (k2) EC-key decoy under an RSA-signed leaf`() {
        run(WalkerFixtures.k2())
    }

    @Test
    fun `walker (l) public cross-certificate to a retired non-anchor root first`() {
        run(WalkerFixtures.l())
    }

    @Test
    fun `walker (m) sound path then 62 related junk`() {
        run(WalkerFixtures.m())
    }

    @Test
    fun `walker (n) unsupported candidate on a dead branch with a supported path found`() {
        run(WalkerFixtures.n())
    }

    @Test
    fun `walker (o) second certified key verifying the leaf gives both keys`() {
        run(WalkerFixtures.o())
    }

    @Test
    fun `walker (p) PrintableString and UTF8String issuer names chain by canonical form`() {
        run(WalkerFixtures.p())
    }

    @Test
    fun `walker (q) depth-9 bridge`() {
        run(WalkerFixtures.q())
    }

    @Test
    fun `walker (r) TBS and outer signature algorithm mismatches walk to Found`() {
        val rows = WalkerFixtures.r()
        run(rows)
        // The finding is decide's (#124), from the parser's flag: set for the OID mismatch, clear for NULL vs absent.
        assertEquals(
            listOf(true, false),
            rows.map { WalkerCerts.cert(it.presented[0]).algorithmIdMismatch },
        )
    }

    @Test
    fun `walker (s1) second key plus 62 related junk is Found with both paths`() {
        run(WalkerFixtures.s1())
    }

    @Test
    fun `walker (s2) second key plus 63 related junk is RELATED_BUDGET with the first key partial`() {
        run(WalkerFixtures.s2())
    }

    @Test
    fun `walker (t) second key plus 80 related junk is RELATED_BUDGET`() {
        run(WalkerFixtures.t())
    }

    @Test
    fun `walker (v) honest chain against a 200-anchor snapshot`() {
        run(WalkerFixtures.v())
    }

    @Test
    fun `walker (v2) honest chain with a retired-root cross-certificate presented`() {
        run(WalkerFixtures.v2())
    }

    @Test
    fun `walker (w) dense cross-certified mesh reports leaf to I to anchor`() {
        run(WalkerFixtures.w())
    }

    @Test
    fun `walker (y) related cap below the leaf aborts the walk at endDepth 2`() {
        run(WalkerFixtures.y())
    }

    @Test
    fun `walker (y2) store root sorts first below the leaf`() {
        run(WalkerFixtures.y2())
    }

    @Test
    fun `walker (z) unrelated unsupported key OID records nothing`() {
        run(WalkerFixtures.z())
    }

    @Test
    fun `walker (aa) root-issued leaf with the root presented has one path`() {
        run(WalkerFixtures.aa())
    }

    @Test
    fun `walker (ac) custom canonicaliser reaches the honest issuer through the unrelated loop`() {
        run(WalkerFixtures.ac())
    }

    @Test
    fun `walker (ad) mutually cross-signing same-name junk exhausts MAX_EXPLORED`() {
        run(WalkerFixtures.ad())
    }

    @Test
    fun `walker (ae) related candidate verifies but is unanchored`() {
        run(WalkerFixtures.ae())
    }

    @Test
    fun `walker (af) a link the walker cannot reproduce is UNANCHORED`() {
        run(WalkerFixtures.af())
    }

    @Test
    fun `walker (ah) duplicate-signature subtrees exhaust MAX_VERIFICATIONS`() {
        run(WalkerFixtures.ah())
    }

    @Test
    fun `walker (ai) a 17-certificate path is Found and an 18-certificate one is a dead end`() {
        run(WalkerFixtures.ai())
    }

    @Test
    fun `walker (aj) two unrelated anchored leaf issuers are both collected in every order`() {
        assertEquals(4, run(WalkerFixtures.aj()).size)
    }
}
