// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.policy.PolicyTable
import dev.revokt.engine.policy.Preset
import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds

/**
 * `RevoktPolicy`, its `Builder` and `Staleness` as spec §4 declares them and §8 fills the presets (#123). The builder
 * cases are §4's builder comments (`exemptAnchors`, `rejectStaleAfter`) and the §8 enterprise-CA recipe.
 */
@OptIn(RevoktTestingApi::class)
class RevoktPolicyTest {
    private val day = 24L * 60 * 60 * 1_000
    private val privateCa = ByteArray(32) { 7 }

    private fun exempted(policy: RevoktPolicy): List<Rule> = Rule.entries.filter { policy.exemption(it) != null }

    private fun context(anchor: ByteArray?) =
        ExemptionContext
            .Builder()
            .rule(Rule.NO_DATA)
            .chain(PresentedChain.Builder().certificates(listOf(TestCert().der)).build())
            .path(
                Finding.Path
                    .Builder()
                    .status(PathStatus.FOUND)
                    .source(ChainSource.RECONSTRUCTED)
                    .anchorSha256(anchor)
                    .build(),
            ).nowMillis(1_700_000_000_000)
            .build()

    private fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!

    @Test
    fun `the presets read the section 8 table`() {
        for ((policy, preset) in listOf(RevoktPolicy.DEFAULT to Preset.DEFAULT, RevoktPolicy.STRICT to Preset.STRICT)) {
            val table = PolicyTable.preset(preset)
            for (rule in Rule.entries) assertEquals(table.outcome(rule), policy.outcome(rule), "$preset $rule")
            assertEquals(emptyList(), exempted(policy))
            assertEquals(setOf(Dataset.CRLITE), policy.requiredDatasets)
            for (dataset in Dataset.entries) {
                val s = table.staleness[dataset]
                assertEquals(
                    s?.let { Staleness.ofMillis(it.staleAfterMillis, it.rejectStaleAfterMillis) },
                    policy.staleness(dataset),
                )
                assertEquals(table.minTrustClass.getValue(dataset), policy.minTrustClass(dataset))
            }
            assertEquals(day, policy.rollbackWindowMillis)
            assertEquals(day, policy.clockSkewMillis)
            assertEquals(day, policy.signedSourceFailingAfterMillis)
            assertEquals(Duration.ofDays(1), policy.rollbackWindow())
            assertEquals(Duration.ofDays(1), policy.clockSkew())
            assertEquals(Duration.ofDays(1), policy.signedSourceFailingAfter())
        }
        assertEquals(Staleness.ofMillis(3 * day, null), RevoktPolicy.DEFAULT.staleness(Dataset.CRLITE))
        assertEquals(Staleness.ofMillis(3 * day, 30 * day), RevoktPolicy.STRICT.staleness(Dataset.CRLITE))
        assertEquals(TrustClass.BUNDLED, RevoktPolicy.DEFAULT.minTrustClass(Dataset.CRLITE))
        assertEquals(TrustClass.SIGNED, RevoktPolicy.STRICT.minTrustClass(Dataset.CRLITE))
    }

    @Test
    fun `rule STALE REJECT on DEFAULT leaves the reject threshold null`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.STALE, Outcome.REJECT)
                .build()
        assertEquals(Outcome.REJECT, policy.outcome(Rule.STALE))
        assertNull(policy.staleness(Dataset.CRLITE)!!.rejectStaleAfterMillis)
        assertEquals(3 * day, policy.staleness(Dataset.CRLITE)!!.staleAfterMillis)
    }

    @Test
    fun `exemptAnchors on DEFAULT covers the rejecting rules at its call, never evidence or the empty path`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.NO_SCTS, Outcome.REJECT)
                .exemptAnchors(listOf(privateCa))
                .build()
        // STALE and UNSIGNED_DATA still allow at the call; REVOKED is evidence; NO_ISSUER, ISSUER_UNVERIFIED empty-path.
        assertEquals(listOf(Rule.NO_DATA, Rule.NO_SCTS), exempted(policy))
        for (rule in exempted(policy)) {
            assertTrue(policy.exemption(rule)!!.isExempt(context(privateCa)), "$rule under the private CA")
            assertFalse(policy.exemption(rule)!!.isExempt(context(ByteArray(32))), "$rule under another anchor")
            assertFalse(policy.exemption(rule)!!.isExempt(context(null)), "$rule on an empty path")
        }
    }

    @Test
    fun `exemptAnchors on STRICT is the enterprise-CA recipe`() {
        val policy =
            RevoktPolicy.STRICT
                .newBuilder()
                .exemptAnchors(listOf(privateCa))
                .build()
        assertEquals(
            listOf(Rule.NO_DATA, Rule.NOT_ENROLLED, Rule.NO_SCTS, Rule.STALE, Rule.UNSIGNED_DATA),
            exempted(policy),
        )
    }

    @Test
    fun `exemptAnchors applies at its call position`() {
        val narrower = Exemption { false }
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .exemptAnchors(listOf(privateCa))
                .exempt(Rule.NO_DATA, narrower)
                .rule(Rule.NO_SCTS, Outcome.REJECT)
                .build()
        assertSame(narrower, policy.exemption(Rule.NO_DATA), "a later exempt() wins")
        assertNull(policy.exemption(Rule.NO_SCTS), "a rule raised to REJECT after the call is not covered")

        val earlier =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .exempt(Rule.NO_DATA, narrower)
                .exemptAnchors(listOf(privateCa))
                .build()
        assertNotEquals(narrower, earlier.exemption(Rule.NO_DATA), "a later exemptAnchors replaces an earlier exempt()")
    }

    @Test
    fun `exemptAnchors copies the anchors when it is called`() {
        val anchor = privateCa.copyOf()
        val anchors = mutableListOf(anchor)
        val builder = RevoktPolicy.DEFAULT.newBuilder().exemptAnchors(anchors)
        anchor.fill(0)
        anchors.clear()
        assertTrue(builder.build().exemption(Rule.NO_DATA)!!.isExempt(context(privateCa)))
    }

    @Test
    fun `exempt replaces, clearExemption removes`() {
        val first = Exemption { true }
        val second = Exemption { false }
        val builder =
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(Rule.NO_ISSUER, first)
                .exempt(Rule.NO_ISSUER, second)
        assertSame(second, builder.build().exemption(Rule.NO_ISSUER))
        assertNull(builder.clearExemption(Rule.NO_ISSUER).build().exemption(Rule.NO_ISSUER))
        assertNull(
            RevoktPolicy.STRICT
                .newBuilder()
                .clearExemption(Rule.NO_ISSUER)
                .build()
                .exemption(Rule.NO_ISSUER),
        )
    }

    @Test
    fun `rule, exempt and clearExemption on NO_ISSUER or ISSUER_UNVERIFIED apply to both`() {
        val pair = listOf(Rule.NO_ISSUER, Rule.ISSUER_UNVERIFIED)
        for ((set, other) in listOf(pair, pair.reversed())) {
            val raised = RevoktPolicy.DEFAULT.newBuilder().rule(set, Outcome.REJECT)
            assertEquals(Outcome.REJECT, raised.build().outcome(other), "rule($set)")
            val exemption = Exemption { true }
            val exempting = raised.exempt(set, exemption)
            assertSame(exemption, exempting.build().exemption(other), "exempt($set)")
            assertNull(exempting.clearExemption(other).build().exemption(set), "clearExemption($other)")
            assertEquals(Outcome.ALLOW, raised.rule(other, Outcome.ALLOW).build().outcome(set), "rule($other)")
        }
        // exemptAnchors still leaves both alone: they fire only on an empty reported path.
        val anchors =
            RevoktPolicy.STRICT
                .newBuilder()
                .exemptAnchors(listOf(privateCa))
                .build()
        for (rule in pair) assertNull(anchors.exemption(rule), "$rule")
    }

    @Test
    fun `rejectStaleAfter sets or clears only the reject threshold, and creates a missing entry`() {
        val strict = RevoktPolicy.STRICT.newBuilder()
        assertEquals(
            Staleness.ofMillis(3 * day, null),
            strict.rejectStaleAfter(Dataset.CRLITE, null).build().staleness(Dataset.CRLITE),
        )
        assertEquals(
            Staleness.ofMillis(3 * day, 10 * day),
            strict.rejectStaleAfter(Dataset.CRLITE, Duration.ofDays(10)).build().staleness(Dataset.CRLITE),
        )
        val cleared = RevoktPolicy.DEFAULT.newBuilder().clearStaleness(Dataset.CRLITE)
        assertNull(cleared.build().staleness(Dataset.CRLITE))
        assertNull(
            cleared.rejectStaleAfterMillis(Dataset.CRLITE, null).build().staleness(Dataset.CRLITE),
            "null on no entry",
        )
        assertEquals(
            Staleness.ofMillis(5 * day, 5 * day),
            cleared.rejectStaleAfterMillis(Dataset.CRLITE, 5 * day).build().staleness(Dataset.CRLITE),
        )
        assertEquals(
            Staleness.ofMillis(3 * day, 4 * day),
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rejectStaleAfter(
                    Dataset.CRLITE,
                    4.days,
                ).build()
                .staleness(Dataset.CRLITE),
        )
    }

    @Test
    fun `build throws when a reject threshold is below its loud threshold`() {
        assertTrue(
            "rejectStaleAfter" in
                message {
                    RevoktPolicy.DEFAULT
                        .newBuilder()
                        .rejectStaleAfterMillis(Dataset.CRLITE, day)
                        .build()
                },
        )
        message {
            RevoktPolicy.DEFAULT
                .newBuilder()
                .staleness(
                    Dataset.CRLITE,
                    Staleness.ofMillis(2 * day, day),
                ).build()
        }
        // Equal thresholds build, and a bad entry replaced before build() is not checked.
        RevoktPolicy.DEFAULT
            .newBuilder()
            .rejectStaleAfterMillis(Dataset.CRLITE, 3 * day)
            .build()
        RevoktPolicy.DEFAULT
            .newBuilder()
            .staleness(Dataset.CRLITE, Staleness.ofMillis(2 * day, day))
            .staleness(Dataset.CRLITE, Staleness.ofMillis(day, null))
            .build()
    }

    @Test
    fun `build throws for an exemption on a rule that is not exemptable`() {
        for (rule in Rule.entries.filter { !it.exemptable }) {
            assertTrue(
                "$rule" in
                    message {
                        RevoktPolicy.STRICT
                            .newBuilder()
                            .exempt(rule, Exemption { true })
                            .build()
                    },
            )
        }
        for (rule in Rule.entries.filter { it.exemptable }) {
            RevoktPolicy.STRICT
                .newBuilder()
                .exempt(rule, Exemption { true })
                .build()
        }
    }

    @Test
    fun `the time fields in millis, java time and kotlin time`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rollbackWindowMillis(1_000)
                .clockSkew(Duration.ofMinutes(5))
                .signedSourceFailingAfter(6.hours)
                .build()
        assertEquals(1_000, policy.rollbackWindowMillis)
        assertEquals(Duration.ofMinutes(5), policy.clockSkew())
        assertEquals(6 * 60 * 60 * 1_000L, policy.signedSourceFailingAfterMillis)
        val other =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rollbackWindow(Duration.ofSeconds(2))
                .clockSkew(3.hours)
                .clockSkewMillis(7)
                .signedSourceFailingAfterMillis(8)
                .rollbackWindow(1500.milliseconds)
                .build()
        assertEquals(
            listOf(1_500L, 7L, 8L),
            listOf(other.rollbackWindowMillis, other.clockSkewMillis, other.signedSourceFailingAfterMillis),
        )
        for (bad in listOf<RevoktPolicy.Builder.() -> Any>(
            { rollbackWindowMillis(-1) },
            { clockSkew(Duration.ofMillis(-1)) },
            { signedSourceFailingAfter((-1).milliseconds) },
            { rejectStaleAfterMillis(Dataset.CRLITE, -1) },
        )) {
            message { RevoktPolicy.DEFAULT.newBuilder().bad() }
        }
        // A java.time.Duration beyond Long milliseconds is an argument error too, not an ArithmeticException.
        val huge = Duration.ofSeconds(Long.MAX_VALUE)
        for ((name, overflow) in listOf<Pair<String, RevoktPolicy.Builder.() -> Any>>(
            "rollbackWindow" to { rollbackWindow(huge) },
            "clockSkew" to { clockSkew(huge) },
            "signedSourceFailingAfter" to { signedSourceFailingAfter(huge) },
            "rejectStaleAfter" to { rejectStaleAfter(Dataset.CRLITE, huge) },
        )) {
            val e = assertFailsWith<IllegalArgumentException> { RevoktPolicy.DEFAULT.newBuilder().overflow() }
            assertTrue(name in e.message!! && e.cause is ArithmeticException, "$name: $e")
        }
    }

    @Test
    fun `requiredDatasets and minTrustClass`() {
        val given = mutableSetOf(Dataset.CRLITE)
        val builder = RevoktPolicy.DEFAULT.newBuilder().requiredDatasets(given)
        given.clear()
        val policy = builder.build()
        assertEquals(setOf(Dataset.CRLITE), policy.requiredDatasets)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST") // a Java caller can cast the read-only view; it must not mutate the policy
            (policy.requiredDatasets as MutableSet<Dataset>).clear()
        }
        assertEquals(
            emptySet(),
            RevoktPolicy.STRICT
                .newBuilder()
                .requiredDatasets(emptySet())
                .build()
                .requiredDatasets,
        )
        val raised =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .minTrustClass(Dataset.CRLITE, TrustClass.SIGNED)
                .build()
        assertEquals(TrustClass.SIGNED, raised.minTrustClass(Dataset.CRLITE))
        assertEquals(TrustClass.BUNDLED, RevoktPolicy.DEFAULT.minTrustClass(Dataset.CRLITE), "the preset is unchanged")
    }

    @Test
    fun `a derived policy's builder keeps its values and preset, and a built policy is independent of its builder`() {
        val builder =
            RevoktPolicy.STRICT
                .newBuilder()
                .rule(
                    Rule.NO_SCTS,
                    Outcome.ALLOW,
                ).exempt(
                    Rule.NO_DATA,
                    Exemption {
                        true
                    },
                )
        val first = builder.build()
        builder.rule(Rule.NO_SCTS, Outcome.REJECT).clearExemption(Rule.NO_DATA).clockSkewMillis(1)
        assertEquals(Outcome.ALLOW, first.outcome(Rule.NO_SCTS))
        assertTrue(first.exemption(Rule.NO_DATA) != null)
        assertEquals(day, first.clockSkewMillis)

        val again = first.newBuilder().build()
        assertEquals(Preset.STRICT, again.form.preset)
        for (rule in Rule.entries) assertEquals(first.outcome(rule), again.outcome(rule))
        assertSame(first.exemption(Rule.NO_DATA), again.exemption(Rule.NO_DATA))
        assertEquals(first.staleness(Dataset.CRLITE), again.staleness(Dataset.CRLITE))
        assertEquals(
            Preset.DEFAULT,
            RevoktPolicy.DEFAULT
                .newBuilder()
                .build()
                .form.preset,
        )
    }

    @Test
    fun `Staleness from millis, java time and kotlin time`() {
        val millis = Staleness.ofMillis(3 * day, 30 * day)
        val java = Staleness.of(Duration.ofDays(3), Duration.ofDays(30))
        val kotlin = Staleness.of(3.days, 30.days)
        for (same in listOf(java, kotlin)) {
            assertEquals(millis, same)
            assertEquals(millis.hashCode(), same.hashCode())
            assertEquals(millis.toString(), same.toString())
        }
        assertEquals(Duration.ofDays(3), millis.staleAfter())
        assertEquals(Duration.ofDays(30), millis.rejectStaleAfter())
        assertNull(Staleness.of(Duration.ofDays(3), null).rejectStaleAfter())
        assertEquals(Staleness.ofMillis(3 * day, null), Staleness.of(3.days, null))
        assertNotEquals(millis, Staleness.ofMillis(3 * day, null))
        assertNotEquals(millis, Staleness.ofMillis(2 * day, 30 * day))
        assertNotEquals<Any>(millis, "staleness")
        assertTrue("staleAfterMillis=" in millis.toString() && "rejectStaleAfterMillis=" in millis.toString())
        // Accepted here; the builder's build() refuses it.
        Staleness.ofMillis(2 * day, day)
        message { Staleness.ofMillis(-1, null) }
        message { Staleness.ofMillis(0, -1) }
        assertTrue("staleAfter" in message { Staleness.of(Duration.ofSeconds(Long.MAX_VALUE), null) })
        assertTrue("rejectStaleAfter" in message { Staleness.of(Duration.ZERO, Duration.ofSeconds(Long.MAX_VALUE)) })
    }

    @Test
    fun `the current minor is the build's`() {
        val version = checkNotNull(System.getProperty("revokt.version")) { "the build passes revokt.version" }
        assertEquals(
            version
                .substringBefore("-")
                .split(".")
                .take(2)
                .joinToString("."),
            PolicyTable.CURRENT_MINOR,
        )
    }
}
