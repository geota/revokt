// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.Finding
import dev.revokt.Outcome
import dev.revokt.PathStatus
import dev.revokt.RevoktTestingApi
import dev.revokt.Rule
import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.Preset
import dev.revokt.engine.policy.firedRule
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The rule table of decision step 8 (spec §4 "Status-to-rule mappings", "Key aggregation (L3, M1)", "Data rules"; §5.1
 * step 8; §5.5's three `ENGINE_ERROR` producers; §8): one row per rule in precedence, each row against the 0.1 mapping
 * tables, key aggregation and `Verdict.rule`'s precedence over every set of fired rules.
 */
@OptIn(RevoktTestingApi::class)
class RuleTableTest {
    private fun facts(
        status: PathStatus = PathStatus.FOUND,
        results: List<CrliteQueryResult> = listOf(CrliteQueryResult.NOT_REVOKED),
        published: Boolean = true,
        dataRules: Set<Rule> = emptySet(),
        boundaryError: Boolean = false,
        exemptionError: Boolean = false,
    ): RuleFacts =
        RuleFacts(
            status,
            results,
            published,
            mapOf(
                Dataset.CRLITE to
                    Finding.DataState
                        .Builder()
                        .dataset(Dataset.CRLITE)
                        .rules(dataRules)
                        .build(),
            ),
            boundaryError,
            exemptionError,
        )

    private fun fired(facts: RuleFacts): Set<Rule> = RULE_TABLE.filter { it.fires(facts) }.mapTo(HashSet()) { it.rule }

    @Test
    fun `the table has one row per rule, in precedence order, with the rule's own columns`() {
        assertEquals(Rule.PRECEDENCE, RULE_TABLE.map { it.rule })
        RULE_TABLE.forEach {
            assertEquals(it.rule.ruleClass, it.ruleClass, "${it.rule}")
            assertEquals(it.rule.layer, it.layer, "${it.rule}")
            assertEquals(it.rule.exemptable, it.exemptable, "${it.rule}")
        }
    }

    @Test
    fun `nothing fires on a clean found path with clean data`() {
        assertEquals(emptySet(), fired(facts()))
    }

    @Test
    fun `each path status fires exactly its mapped rule`() {
        for (status in PathStatus.entries) {
            val results = if (status == PathStatus.FOUND) listOf(CrliteQueryResult.NOT_REVOKED) else emptyList()
            assertEquals(setOfNotNull(status.firedRule()), fired(facts(status, results)), "$status")
        }
        assertEquals(setOf(Rule.NO_ISSUER), fired(facts(PathStatus.NO_ISSUER, emptyList())))
        assertEquals(emptySet(), fired(facts(PathStatus.NOT_WALKED, emptyList())))
    }

    @Test
    fun `each engine answer fires exactly its mapped rule on a found path`() {
        for (published in listOf(true, false)) {
            for (result in CrliteQueryResult.entries) {
                val want = setOfNotNull(result.firedRule(published))
                assertEquals(want, fired(facts(results = listOf(result), published = published)), "$result $published")
            }
        }
        assertEquals(setOf(Rule.ENGINE_ERROR), fired(facts(results = listOf(CrliteQueryResult.NO_DATA))))
        assertEquals(emptySet(), fired(facts(results = listOf(CrliteQueryResult.NO_DATA), published = false)))
    }

    @Test
    fun `key aggregation - REVOKED wins, otherwise every key's non-answer fires`() {
        val r = CrliteQueryResult.entries
        for (a in r) {
            for (b in r) {
                val got = fired(facts(results = listOf(a, b)))
                val want =
                    if (CrliteQueryResult.REVOKED in listOf(a, b)) {
                        setOf(Rule.REVOKED)
                    } else {
                        setOfNotNull(a.firedRule(true), b.firedRule(true))
                    }
                assertEquals(want, got, "$a + $b")
            }
        }
        assertEquals(
            setOf(Rule.REVOKED),
            fired(facts(results = listOf(CrliteQueryResult.REVOKED, CrliteQueryResult.NOT_ENROLLED))),
        )
        assertEquals(
            setOf(Rule.NOT_ENROLLED, Rule.NO_SCTS),
            fired(facts(results = listOf(CrliteQueryResult.NOT_ENROLLED, CrliteQueryResult.NO_SCTS))),
        )
    }

    @Test
    fun `on Budget only REVOKED fires from CRLite`() {
        val budget = PathStatus.PATH_BUDGET_EXCEEDED
        for (result in CrliteQueryResult.entries) {
            val want =
                setOfNotNull(Rule.PATH_BUDGET_EXCEEDED, Rule.REVOKED.takeIf { result == CrliteQueryResult.REVOKED })
            assertEquals(want, fired(facts(budget, listOf(CrliteQueryResult.NOT_REVOKED, result))), "$result")
        }
    }

    @Test
    fun `no evaluated key fires no CRLite rule, published or not`() {
        for (published in listOf(true, false)) {
            assertEquals(emptySet(), facts(results = emptyList(), published = published).crliteRules)
        }
    }

    @Test
    fun `ENGINE_ERROR has the engine, the boundary and a throwing exemption as producers`() {
        assertEquals(setOf(Rule.ENGINE_ERROR), fired(facts(results = listOf(CrliteQueryResult.ENGINE_ERROR))))
        assertEquals(setOf(Rule.ENGINE_ERROR), fired(facts(boundaryError = true)))
        assertEquals(setOf(Rule.ENGINE_ERROR), fired(facts(exemptionError = true)))
        assertEquals(
            setOf(Rule.REVOKED, Rule.ENGINE_ERROR),
            fired(facts(results = listOf(CrliteQueryResult.REVOKED), boundaryError = true)),
        )
    }

    @Test
    fun `the data rule rows fire on any dataset's rules`() {
        for (rule in listOf(Rule.NO_DATA, Rule.STALE, Rule.UNSIGNED_DATA)) {
            assertEquals(setOf(rule), fired(facts(dataRules = setOf(rule))), "$rule")
        }
        assertEquals(
            setOf(Rule.NO_DATA, Rule.STALE, Rule.UNSIGNED_DATA),
            fired(facts(dataRules = setOf(Rule.NO_DATA, Rule.STALE, Rule.UNSIGNED_DATA))),
        )
    }

    @Test
    fun `fire maps each fired rule to the policy's outcome, in precedence order`() {
        val f = facts(PathStatus.PARSE_FAILED, emptyList(), dataRules = setOf(Rule.NO_DATA, Rule.UNSIGNED_DATA))
        val default = PolicyForm.of(Preset.DEFAULT)
        assertEquals(
            listOf(
                FiredRule(Rule.NO_DATA, Outcome.REJECT),
                FiredRule(Rule.PARSE_FAILED, Outcome.ALLOW),
                FiredRule(Rule.UNSIGNED_DATA, Outcome.ALLOW),
            ),
            fire(f, default),
        )
        assertEquals(
            listOf(Outcome.REJECT, Outcome.REJECT, Outcome.REJECT),
            fire(f, PolicyForm.of(Preset.STRICT)).map { it.outcome },
        )
    }

    @Test
    fun `the verdict rule is the first fired, non-exempted REJECT rule in precedence, over every set of fired rules`() {
        val random = Random(133)
        val rules = Rule.PRECEDENCE
        for (mask in 0 until (1 shl rules.size)) {
            val fired = rules.filterIndexed { i, _ -> mask and (1 shl i) != 0 }
            repeat(4) {
                val outcomes = fired.associateWith { if (random.nextBoolean()) Outcome.REJECT else Outcome.ALLOW }
                val exempted = fired.filterTo(HashSet()) { random.nextInt(3) == 0 }
                val list = fired.map { FiredRule(it, outcomes.getValue(it)) }
                val want = rules.firstOrNull { it in fired && outcomes[it] == Outcome.REJECT && it !in exempted }
                assertEquals(want, verdictRule(list, exempted), "$list exempted $exempted")
                assertEquals(want, verdictRule(list.reversed(), exempted), "reversed $list exempted $exempted")
            }
        }
    }

    @Test
    fun `every pair of REJECT rules is decided by precedence, and exempting the first leaves the second`() {
        for ((i, first) in Rule.PRECEDENCE.withIndex()) {
            for (second in Rule.PRECEDENCE.drop(i + 1)) {
                val both = listOf(FiredRule(second, Outcome.REJECT), FiredRule(first, Outcome.REJECT))
                assertEquals(first, verdictRule(both, emptySet()), "$first before $second")
                assertEquals(second, verdictRule(both, setOf(first)), "$first exempted")
                assertNull(verdictRule(both, setOf(first, second)), "both exempted")
                assertEquals(second, verdictRule(listOf(FiredRule(first, Outcome.ALLOW)) + both.take(1), emptySet()))
            }
        }
    }
}
