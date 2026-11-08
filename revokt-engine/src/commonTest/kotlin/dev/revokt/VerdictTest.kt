// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `Verdict.Accepted` and `Verdict.Rejected` as spec §4 declares them (#122). */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class VerdictTest {
    private fun path(status: PathStatus = PathStatus.FOUND) =
        Finding.Path
            .Builder()
            .status(status)
            .source(ChainSource.RECONSTRUCTED)
            .apply { if (status == PathStatus.NO_ISSUER) noIssuerReason(NoIssuerReason.NO_CANDIDATE) }
            .build()

    private val crlite =
        Finding.Crlite
            .Builder()
            .result(CrliteQueryResult.NOT_ENROLLED)
            .issuerSpkiSha256(ByteArray(32) { 7 })
            .build()

    private val dataState =
        Finding.DataState
            .Builder()
            .dataset(Dataset.CRLITE)
            .rules(setOf(Rule.NO_DATA))
            .build()

    private val exempted =
        Finding.Exempted
            .Builder()
            .rule(Rule.NOT_ENROLLED)
            .build()

    private fun accepted() =
        Verdict.Accepted
            .Builder()
            .rules(setOf(Rule.NOT_ENROLLED))
            .findings(listOf(path(), crlite, exempted))
            .elapsedNanos(1_000)
            .path(path())
            .crlite(crlite)
            .dataStates(mapOf(Dataset.CRLITE to dataState))
            .generationEpoch(3)
            .build()

    private fun rejected() =
        Verdict.Rejected
            .Builder()
            .rules(setOf(Rule.NO_DATA, Rule.NOT_ENROLLED))
            .rule(Rule.NO_DATA)
            .findings(listOf(path(), crlite))
            .elapsedNanos(1_000)
            .path(path())
            .crlite(crlite)
            .dataStates(mapOf(Dataset.CRLITE to dataState))
            .generationEpoch(3)
            .build()

    private fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!

    @Test
    fun `rules iterate in precedence order whatever the insertion order`() {
        val given = linkedSetOf(Rule.UNSIGNED_DATA, Rule.NOT_ENROLLED, Rule.REVOKED, Rule.NO_DATA, Rule.STALE)
        val expected = listOf(Rule.REVOKED, Rule.NO_DATA, Rule.NOT_ENROLLED, Rule.STALE, Rule.UNSIGNED_DATA)
        val accepted = accepted().newBuilder().rules(given).build()
        val rejected =
            rejected()
                .newBuilder()
                .rules(given)
                .rule(Rule.REVOKED)
                .build()
        for (verdict in listOf(accepted, rejected, accepted.newBuilder().build(), rejected.newBuilder().build())) {
            assertEquals(expected, verdict.rules.toList())
        }
        assertEquals(
            Rule.PRECEDENCE,
            accepted
                .newBuilder()
                .rules(Rule.entries.reversed().toSet())
                .build()
                .rules
                .toList(),
        )
    }

    @Test
    fun `rules, findings and data states are read-only copies`() {
        val rules = mutableSetOf(Rule.NOT_ENROLLED)
        val findings = mutableListOf<Finding>(crlite)
        val dataStates = mutableMapOf(Dataset.CRLITE to dataState)
        val verdict =
            accepted()
                .newBuilder()
                .rules(rules)
                .findings(findings)
                .dataStates(dataStates)
                .build()
        rules.clear()
        findings.clear()
        dataStates.clear()
        assertEquals(setOf(Rule.NOT_ENROLLED), verdict.rules)
        assertEquals(listOf<Finding>(crlite), verdict.findings)
        assertEquals(mapOf(Dataset.CRLITE to dataState), verdict.dataStates)
        @Suppress("UNCHECKED_CAST") // The check is that each read-only view cannot be cast back and changed.
        run {
            assertFailsWith<UnsupportedOperationException> { (verdict.rules as MutableSet<Rule>).add(Rule.REVOKED) }
            assertFailsWith<UnsupportedOperationException> { (verdict.findings as MutableList<Finding>).clear() }
            assertFailsWith<UnsupportedOperationException> {
                (verdict.dataStates as MutableMap<Dataset, Finding.DataState>).clear()
            }
        }
    }

    @Test
    fun `a verdict built from equal inputs is equal, and newBuilder round-trips`() {
        val built =
            listOf<Pair<Verdict, Verdict>>(
                accepted() to accepted().newBuilder().build(),
                rejected() to rejected().newBuilder().build(),
            )
        for ((original, roundTripped) in built) {
            val again = if (original is Verdict.Accepted) accepted() else rejected()
            for (same in listOf(again, roundTripped)) {
                assertEquals(original, same)
                assertEquals(original.hashCode(), same.hashCode())
                assertEquals(original.toString(), same.toString())
                assertEquals(original.elapsedNanos, same.elapsedNanos)
            }
            val text = original.toString()
            for (field in listOf("rules", "rule", "findings", "path", "crlite", "dataStates")) {
                assertTrue("$field=" in text, "$field missing from $text")
            }
        }
        assertEquals(3, accepted().newBuilder().build().generationEpoch, "newBuilder keeps the cache key")
        assertEquals(3, rejected().newBuilder().build().generationEpoch, "newBuilder keeps the cache key")
        assertTrue(accepted().toString().startsWith("Accepted("), accepted().toString())
        assertTrue(rejected().toString().startsWith("Rejected("), rejected().toString())
        assertNotEquals<Any>(accepted(), "verdict")
        assertNotEquals<Any>(rejected(), "verdict")
    }

    @Test
    fun `elapsedNanos and generationEpoch are outside equality, hashing and toString`() {
        for (verdict in listOf<Verdict>(accepted(), rejected())) {
            val other =
                when (verdict) {
                    is Verdict.Accepted -> {
                        verdict
                            .newBuilder()
                            .elapsedNanos(9_999_999)
                            .generationEpoch(8)
                            .build()
                    }

                    is Verdict.Rejected -> {
                        verdict
                            .newBuilder()
                            .elapsedNanos(9_999_999)
                            .generationEpoch(8)
                            .build()
                    }
                }
            assertEquals(9_999_999, other.elapsedNanos)
            assertEquals(
                8,
                when (other) {
                    is Verdict.Accepted -> other.generationEpoch
                    is Verdict.Rejected -> other.generationEpoch
                },
            )
            assertEquals(verdict, other)
            assertEquals(verdict.hashCode(), other.hashCode())
            assertEquals(verdict.toString(), other.toString())
            assertFalse("elapsedNanos" in other.toString(), other.toString())
            assertFalse("generationEpoch" in other.toString(), other.toString())
        }
    }

    @Test
    fun `every other field takes part in equality`() {
        val accepted = accepted()
        val acceptedChanges =
            mapOf<String, Verdict.Accepted.Builder.() -> Verdict.Accepted.Builder>(
                "rules" to { rules(setOf(Rule.NO_SCTS)) },
                "findings" to { findings(emptyList()) },
                "path" to { path(path(PathStatus.NO_ISSUER)) },
                "crlite" to { crlite(null) },
                "dataStates" to { dataStates(emptyMap()) },
            )
        for ((field, change) in acceptedChanges) {
            assertNotEquals(accepted, accepted.newBuilder().change().build(), field)
        }
        val rejected = rejected()
        val rejectedChanges =
            mapOf<String, Verdict.Rejected.Builder.() -> Verdict.Rejected.Builder>(
                "rules" to { rules(setOf(Rule.NO_DATA)) },
                "rule" to { rule(Rule.NOT_ENROLLED) },
                "findings" to { findings(emptyList()) },
                "path" to { path(path(PathStatus.NO_ISSUER)) },
                "crlite" to { crlite(null) },
                "dataStates" to { dataStates(emptyMap()) },
            )
        for ((field, change) in rejectedChanges) {
            assertNotEquals(rejected, rejected.newBuilder().change().build(), field)
        }
    }

    @Test
    fun `an Accepted and a Rejected verdict are never equal`() {
        val both = setOf(Rule.NO_DATA)
        val accepted = accepted().newBuilder().rules(both).build()
        val rejected = rejected().newBuilder().rules(both).build()
        assertNotEquals<Verdict>(accepted, rejected)
        assertNotEquals<Verdict>(rejected, accepted)
    }

    @Test
    fun `Accepted has no rule, Rejected names one of its fired rules`() {
        assertNull(accepted().rule)
        assertEquals(Rule.NO_DATA, rejected().rule)
        val rule: Rule = rejected().rule // Non-null on Rejected, so this compiles without a cast.
        assertTrue(rule in rejected().rules)
        val notFired = message { rejected().newBuilder().rule(Rule.REVOKED).build() }
        assertEquals(
            "rule is one of the fired rules (spec §4): got rule=REVOKED, rules=[NO_DATA, NOT_ENROLLED]",
            notFired,
        )
    }

    @Test
    fun `Rejected never names an exempted rule`() {
        val exemptedNoData =
            Finding.Exempted
                .Builder()
                .rule(Rule.NO_DATA)
                .build()
        val broken = message { rejected().newBuilder().findings(listOf(path(), exemptedNoData)).build() }
        assertEquals("rule is not an exempted rule (spec §4): got rule=NO_DATA, which a Finding.Exempted names", broken)
        // NOT_ENROLLED was exempted, NO_DATA was not: the verdict names NO_DATA.
        val fine = rejected().newBuilder().findings(listOf(path(), exempted)).build()
        assertEquals(Rule.NO_DATA, fine.rule)
    }

    @Test
    fun `the builders' defaults and required fields`() {
        val accepted =
            Verdict.Accepted
                .Builder()
                .path(path())
                .build()
        assertEquals(emptySet(), accepted.rules)
        assertEquals(emptyList(), accepted.findings)
        assertEquals(0, accepted.elapsedNanos)
        assertNull(accepted.crlite)
        assertEquals(emptyMap(), accepted.dataStates)
        assertEquals(0, accepted.generationEpoch)
        assertEquals("path is not set", message { Verdict.Accepted.Builder().build() })
        val fired = Verdict.Rejected.Builder().rules(setOf(Rule.STALE))
        assertEquals("rule is not set", message { fired.path(path()).build() })
        assertEquals(
            "path is not set",
            message {
                Verdict.Rejected
                    .Builder()
                    .rules(setOf(Rule.STALE))
                    .rule(Rule.STALE)
                    .build()
            },
        )
        val rejected = fired.rule(Rule.STALE).path(path(PathStatus.NOT_WALKED)).build()
        assertEquals(PathStatus.NOT_WALKED, rejected.path.status)
        assertEquals(emptyList(), rejected.findings)
        assertEquals(0, rejected.generationEpoch)
    }
}
