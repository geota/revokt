// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.TestCert
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** `Exemption.hostIn`, `hostSuffixIn`, `platformOnly` and the `and`/`or` combinators as spec §4 declares them (#122). */
@OptIn(RevoktTestingApi::class)
class ExemptionHelpersTest {
    private val chain =
        PresentedChain
            .Builder()
            .certificates(listOf(TestCert().der))
            .build()

    private fun path(reason: NoIssuerReason?) =
        Finding.Path
            .Builder()
            .status(if (reason == null) PathStatus.FOUND else PathStatus.NO_ISSUER)
            .source(ChainSource.RECONSTRUCTED)
            .noIssuerReason(reason)
            .build()

    /** A context as #120's testing builder makes it: [host] is passed through as given, not normalised. */
    private fun context(
        host: String?,
        reason: NoIssuerReason? = null,
    ) = ExemptionContext
        .Builder()
        .rule(Rule.NO_ISSUER)
        .chain(chain)
        .path(path(reason))
        .host(host)
        .nowMillis(1_700_000_000_000)
        .build()

    private class Boom : RuntimeException("exemption threw")

    private val yes = Exemption { true }
    private val no = Exemption { false }
    private val throws = Exemption { throw Boom() }

    @Test
    fun `hostIn compares lowercased hosts with one trailing dot stripped, on both sides`() {
        val exemption = Exemption.hostIn(listOf("Corp.Example.", "intranet"))
        for (host in listOf(
            "corp.example",
            "CORP.EXAMPLE",
            "corp.example.",
            "Corp.Example.",
            "intranet",
            "INTRANET.",
        )) {
            assertTrue(exemption.isExempt(context(host)), host)
        }
        for (host in listOf("a.corp.example", "example", "corp.example..", "intranet.corp", "")) {
            assertFalse(exemption.isExempt(context(host)), host)
        }
    }

    @Test
    fun `hostSuffixIn matches the suffix itself and its subdomains, never a longer label`() {
        val exemption = Exemption.hostSuffixIn(listOf("corp"))
        for (host in listOf("corp", "a.corp", "b.a.corp", "A.CORP", "a.corp.", "CORP.")) {
            assertTrue(exemption.isExempt(context(host)), host)
        }
        for (host in listOf("acorp", "a.acorp", "corp.example", "cor", "", "a.corp..")) {
            assertFalse(exemption.isExempt(context(host)), host)
        }
        val mixed = Exemption.hostSuffixIn(listOf("Corp.Example.", "lab"))
        assertTrue(mixed.isExempt(context("db.corp.example")))
        assertTrue(mixed.isExempt(context("x.LAB")))
        assertFalse(mixed.isExempt(context("example")))
        assertFalse(Exemption.hostSuffixIn(emptyList()).isExempt(context("corp")))
    }

    @Test
    fun `a null host never matches hostIn or hostSuffixIn`() {
        assertFalse(Exemption.hostIn(listOf("corp")).isExempt(context(null)))
        assertFalse(Exemption.hostSuffixIn(listOf("corp")).isExempt(context(null)))
        assertFalse(Exemption.hostIn(listOf("", ".")).isExempt(context(null)))
        assertFalse(Exemption.hostSuffixIn(listOf("", ".")).isExempt(context(null)))
    }

    @Test
    fun `the host helpers copy their input, so a later change does not change the match`() {
        val hosts = mutableListOf("corp")
        val byHost = Exemption.hostIn(hosts)
        val bySuffix = Exemption.hostSuffixIn(hosts)
        hosts[0] = "other"
        assertTrue(byHost.isExempt(context("corp")))
        assertTrue(bySuffix.isExempt(context("a.corp")))
        assertFalse(byHost.isExempt(context("other")))
        assertFalse(bySuffix.isExempt(context("a.other")))
    }

    @Test
    fun `platformOnly matches exactly the PLATFORM_ONLY reason`() {
        val exemption = Exemption.platformOnly()
        for (reason in NoIssuerReason.entries) {
            assertEquals(reason == NoIssuerReason.PLATFORM_ONLY, exemption.isExempt(context("corp", reason)), "$reason")
        }
        assertFalse(exemption.isExempt(context("corp", null)), "a FOUND path has no reason")
        assertSame(exemption, Exemption.platformOnly(), "stateless, so one instance")
    }

    @Test
    fun `and and or follow their truth tables`() {
        val c = context("corp")
        for ((a, b) in listOf(yes to yes, yes to no, no to yes, no to no)) {
            val (x, y) = a.isExempt(c) to b.isExempt(c)
            assertEquals(x && y, (a and b).isExempt(c), "$x and $y")
            assertEquals(x || y, (a or b).isExempt(c), "$x or $y")
        }
    }

    @Test
    fun `a throwing operand propagates from and and or, whichever side it is on and whatever the other answers`() {
        val c = context("corp")
        for (other in listOf(yes, no)) {
            for (combined in listOf(throws and other, other and throws, throws or other, other or throws)) {
                assertFailsWith<Boom> { combined.isExempt(c) }
            }
        }
    }

    @Test
    fun `the enterprise recipe combines hostSuffixIn and platformOnly`() {
        // §8: NO_ISSUER and ISSUER_UNVERIFIED under STRICT, exempted only for the corporate domains.
        val recipe = Exemption.hostSuffixIn(listOf("corp.example")) and Exemption.platformOnly()
        assertTrue(recipe.isExempt(context("git.corp.example", NoIssuerReason.PLATFORM_ONLY)))
        assertFalse(recipe.isExempt(context("public.example", NoIssuerReason.PLATFORM_ONLY)))
        assertFalse(recipe.isExempt(context("git.corp.example", NoIssuerReason.NO_CANDIDATE)))
        assertFalse(recipe.isExempt(context(null, NoIssuerReason.PLATFORM_ONLY)))
        val either = Exemption.hostIn(listOf("a.example")) or Exemption.hostSuffixIn(listOf("corp.example"))
        assertTrue(either.isExempt(context("a.example")))
        assertTrue(either.isExempt(context("x.corp.example")))
        assertFalse(either.isExempt(context("b.example")))
    }
}
