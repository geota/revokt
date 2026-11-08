// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.TestCert
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
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

    /** A context as the testing builder makes it: [host] is given raw, and the builder stores host'. */
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

    private fun rejects(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!

    @Test
    fun `hostIn compares host', ASCII lowercased with one trailing dot stripped`() {
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
        for (host in listOf("a.corp.example", "example", "corp.example..", "intranet.corp", "", ".")) {
            assertFalse(exemption.isExempt(context(host)), host)
        }
    }

    @Test
    fun `hostSuffixIn matches the suffix itself and its subdomains, never a longer label`() {
        val exemption = Exemption.hostSuffixIn(listOf("corp"))
        for (host in listOf("corp", "a.corp", "b.a.corp", "A.CORP", "a.corp.", "CORP.")) {
            assertTrue(exemption.isExempt(context(host)), host)
        }
        for (host in listOf("acorp", "a.acorp", "corp.example", "cor", "", ".", "a.corp..")) {
            assertFalse(exemption.isExempt(context(host)), host)
        }
        val mixed = Exemption.hostSuffixIn(listOf("Corp.Example.", "lab"))
        assertTrue(mixed.isExempt(context("db.corp.example")))
        assertTrue(mixed.isExempt(context("x.LAB")))
        assertFalse(mixed.isExempt(context("example")))
        assertFalse(Exemption.hostSuffixIn(emptyList()).isExempt(context("corp")))
    }

    @Test
    fun `the host is normalised once, so a second trailing dot never matches`() {
        val c = context("A.Corp..")
        assertEquals("a.corp.", c.host, "one dot stripped, once")
        assertEquals("a.corp.", c.newBuilder().build().host, "newBuilder keeps host' rather than normalising again")
        assertEquals(c, c.newBuilder().build())
        assertFalse(Exemption.hostSuffixIn(listOf("corp")).isExempt(c))
        assertFalse(Exemption.hostIn(listOf("a.corp")).isExempt(c))
        assertEquals("a.corp", hostPrime("A.CORP."))
        assertEquals("a.corp.", hostPrime("a.corp.."))
    }

    @Test
    fun `case folding is ASCII only, and a non-ASCII entry is rejected at construction`() {
        val kelvin = "\u212A.corp" // KELVIN SIGN, which Unicode lowercasing turns into an ASCII k
        assertEquals(kelvin, hostPrime(kelvin))
        assertEquals(kelvin, context(kelvin).host)
        assertFalse(Exemption.hostIn(listOf("k.corp")).isExempt(context(kelvin)))
        assertFalse(Exemption.hostSuffixIn(listOf("k.corp")).isExempt(context("a.$kelvin")))
        for (entry in listOf(kelvin, "b\u00FCcher.example", "xn--bcher-kva.\u00E9xample")) {
            assertEquals(
                "hostIn: \"$entry\" is not ASCII; pass the A-label",
                rejects { Exemption.hostIn(listOf(entry)) },
            )
            assertEquals(
                "hostSuffixIn: \"$entry\" is not ASCII; pass the A-label",
                rejects { Exemption.hostSuffixIn(listOf("corp", entry)) },
            )
        }
        assertTrue(Exemption.hostIn(listOf("xn--bcher-kva.example")).isExempt(context("XN--BCHER-KVA.example")))
    }

    @Test
    fun `an entry that is empty once normalised, or starts with a dot, is rejected at construction`() {
        for (entry in listOf("", ".", ".corp", "..", "..corp.")) {
            assertEquals(
                "hostIn: \"$entry\" is empty or starts with a dot",
                rejects { Exemption.hostIn(listOf(entry)) },
            )
            assertEquals(
                "hostSuffixIn: \"$entry\" is empty or starts with a dot",
                rejects { Exemption.hostSuffixIn(listOf("corp", entry)) },
            )
        }
        Exemption.hostIn(listOf("corp."))
        Exemption.hostSuffixIn(listOf("corp."))
    }

    @Test
    fun `an empty host is no host, and no host never matches`() {
        assertNull(context("").host)
        assertNull(context(".").host)
        assertNull(context(null).host)
        for (host in listOf("", ".", null)) {
            assertFalse(Exemption.hostIn(listOf("corp")).isExempt(context(host)), "$host")
            assertFalse(Exemption.hostSuffixIn(listOf("corp")).isExempt(context(host)), "$host")
        }
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

    /** What an exemption answered, a throw included, so outcomes can be compared. */
    private fun outcome(
        exemption: Exemption,
        c: ExemptionContext,
    ): String =
        try {
            exemption.isExempt(c).toString()
        } catch (e: Boom) {
            "throws"
        }

    private val operands = mapOf("true" to yes, "false" to no, "throws" to throws)

    @Test
    fun `and and or follow CEL's truth tables, errors absorbed when the other side decides`() {
        val c = context("corp")
        // Rows: left operand, right operand, then the CEL result of && and of ||.
        val table =
            listOf(
                listOf("true", "true", "true", "true"),
                listOf("true", "false", "false", "true"),
                listOf("true", "throws", "throws", "true"),
                listOf("false", "true", "false", "true"),
                listOf("false", "false", "false", "false"),
                listOf("false", "throws", "false", "throws"),
                listOf("throws", "true", "throws", "true"),
                listOf("throws", "false", "false", "throws"),
                listOf("throws", "throws", "throws", "throws"),
            )
        for ((left, right, both, either) in table) {
            val a = operands.getValue(left)
            val b = operands.getValue(right)
            assertEquals(both, outcome(a and b, c), "$left and $right")
            assertEquals(either, outcome(a or b, c), "$left or $right")
        }
    }

    @Test
    fun `and and or are commutative`() {
        val c = context("corp")
        for ((x, a) in operands) {
            for ((y, b) in operands) {
                assertEquals(outcome(a and b, c), outcome(b and a, c), "$x and $y")
                assertEquals(outcome(a or b, c), outcome(b or a, c), "$x or $y")
            }
        }
    }

    @Test
    fun `the right operand does not run when the left one decides`() {
        val c = context("corp")
        var runs = 0
        val counted =
            Exemption {
                runs++
                true
            }
        assertFalse((no and counted).isExempt(c))
        assertTrue((yes or counted).isExempt(c))
        assertEquals(0, runs)
        assertTrue((yes and counted).isExempt(c))
        assertTrue((no or counted).isExempt(c))
        assertTrue((throws or counted).isExempt(c), "a throw on the left does not decide")
        assertEquals(3, runs)
    }

    @Test
    fun `with no decisive answer the first throw propagates`() {
        val c = context("corp")
        val second = Exemption { throw IllegalStateException("second") }
        assertFailsWith<Boom> { (throws and second).isExempt(c) }
        assertFailsWith<Boom> { (throws or second).isExempt(c) }
        assertFailsWith<IllegalStateException> { (yes and second).isExempt(c) }
        assertFailsWith<IllegalStateException> { (no or second).isExempt(c) }
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
