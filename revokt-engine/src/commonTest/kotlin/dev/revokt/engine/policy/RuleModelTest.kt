// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.Layer
import dev.revokt.Outcome
import dev.revokt.ParseReason
import dev.revokt.PathStatus
import dev.revokt.Rule
import dev.revokt.TrustClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The [0.1] items of spec §9 "`Rule` model tests", except two held elsewhere: the `BasicReason` map and the model's
 * equality with the golden fixture are jvmTest's (`RuleGoldenTest`), and "the golden growability fixture diff is
 * additive" is the build's `verifyRuleGrowability` check (#73).
 */
class RuleModelTest {
    private val day = 24L * 60 * 60 * 1_000

    @Test
    fun `declaration order is precedence, grouped by class`() {
        assertEquals(Rule.entries.sortedBy { it.ruleClass }, Rule.entries)
        assertEquals(Rule.entries, Rule.PRECEDENCE)
    }

    @Test
    fun `both preset tables are total over Rule entries and Dataset entries`() {
        for (preset in Preset.entries) {
            val table = PolicyTable.preset(preset)
            assertEquals(Rule.entries.size, Rule.entries.map(table::outcome).size, "$preset outcomes")
            assertEquals(Dataset.entries.toSet(), table.minTrustClass.keys, "$preset minTrustClass")
        }
    }

    @Test
    fun `the DEFAULT preset is the spec 8 table`() {
        val rejected = setOf(Rule.REVOKED, Rule.PATH_BUDGET_EXCEEDED, Rule.NO_DATA)
        for (rule in Rule.entries) {
            val expected = if (rule in rejected) Outcome.REJECT else Outcome.ALLOW
            assertEquals(expected, PolicyTable.DEFAULT.outcome(rule), "$rule")
        }
        assertEquals(mapOf(Dataset.CRLITE to StalenessTable(3 * day, null)), PolicyTable.DEFAULT.staleness)
        assertEquals(Dataset.entries.associateWith { TrustClass.BUNDLED }, PolicyTable.DEFAULT.minTrustClass)
    }

    @Test
    fun `the STRICT preset is the spec 8 table`() {
        for (rule in Rule.entries) {
            val expected = if (rule == Rule.NOT_COVERED) Outcome.ALLOW else Outcome.REJECT
            assertEquals(expected, PolicyTable.STRICT.outcome(rule), "$rule")
        }
        assertEquals(mapOf(Dataset.CRLITE to StalenessTable(3 * day, 30 * day)), PolicyTable.STRICT.staleness)
        assertEquals(Dataset.entries.associateWith { TrustClass.SIGNED }, PolicyTable.STRICT.minTrustClass)
    }

    @Test
    fun `both presets require CRLite and share the three time fields`() {
        for (table in listOf(PolicyTable.DEFAULT, PolicyTable.STRICT)) {
            assertEquals(setOf(Dataset.CRLITE), table.requiredDatasets)
            assertEquals(day, table.rollbackWindowMillis)
            assertEquals(day, table.clockSkewMillis)
            assertEquals(day, table.signedSourceFailingAfterMillis)
        }
    }

    @Test
    fun `the empty-path rules are exemptable path rules`() {
        assertEquals(setOf(Rule.ISSUER_UNVERIFIED, Rule.NO_ISSUER), PolicyTable.EMPTY_PATH)
        assertTrue(PolicyTable.EMPTY_PATH.all { it.exemptable && it.layer == Layer.PATH })
    }

    @Test
    fun `the PathStatus to Rule table`() {
        val expected =
            mapOf(
                PathStatus.FOUND to null,
                PathStatus.NOT_WALKED to null,
                PathStatus.NO_ISSUER to Rule.NO_ISSUER,
                PathStatus.ISSUER_UNVERIFIED to Rule.ISSUER_UNVERIFIED,
                PathStatus.PATH_BUDGET_EXCEEDED to Rule.PATH_BUDGET_EXCEEDED,
                PathStatus.PARSE_FAILED to Rule.PARSE_FAILED,
            )
        assertEquals(PathStatus.entries.toSet(), expected.keys)
        for ((status, rule) in expected) assertEquals(rule, status.firedRule(), "$status")
    }

    @Test
    fun `the CrliteQueryResult to Rule table`() {
        val sameNamed =
            listOf(
                CrliteQueryResult.REVOKED,
                CrliteQueryResult.NOT_COVERED,
                CrliteQueryResult.NOT_ENROLLED,
                CrliteQueryResult.NO_SCTS,
            )
        for (published in listOf(false, true)) {
            for (result in sameNamed) assertEquals(Rule.valueOf(result.name), result.firedRule(published), "$result")
            assertNull(CrliteQueryResult.NOT_REVOKED.firedRule(published))
            assertEquals(Rule.ENGINE_ERROR, CrliteQueryResult.ENGINE_ERROR.firedRule(published))
        }
        // Rule.NO_DATA is driven by requiredDatasets: an engine's NO_DATA with a generation published is its error.
        assertNull(CrliteQueryResult.NO_DATA.firedRule(generationPublished = false))
        assertEquals(Rule.ENGINE_ERROR, CrliteQueryResult.NO_DATA.firedRule(generationPublished = true))
    }

    @Test
    fun `the status maps reach every rule but the data rules`() {
        val reached =
            PathStatus.entries.mapNotNull { it.firedRule() }.toSet() +
                CrliteQueryResult.entries.flatMap { r -> listOf(false, true).mapNotNull { r.firedRule(it) } }
        assertEquals(Rule.entries.toSet() - setOf(Rule.NO_DATA, Rule.STALE, Rule.UNSIGNED_DATA), reached)
    }

    @Test
    fun `the counters are zero-filled`() {
        val counts = zeroRuleCounts()
        assertEquals(Rule.entries, counts.keys.toList())
        assertTrue(counts.values.all { it == 0L })
        val parseFailed = zeroParseFailedCounts()
        assertEquals(ParseReason.entries, parseFailed.keys.toList())
        assertTrue(parseFailed.values.all { it == 0L })
    }
}
