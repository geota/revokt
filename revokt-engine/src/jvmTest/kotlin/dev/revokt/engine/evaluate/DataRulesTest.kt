// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.evaluate

import dev.revokt.Dataset
import dev.revokt.Finding
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.Staleness
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.policy.PolicyForm
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The data rules and data states (spec §4 `Finding.DataState`, `Verdict.dataStates`, "Data rules"; §5.1 decision step
 * 7; §8 data rules per dataset, the `STALE` seed gate): computed from the snapshot, the policy and the one clock read.
 */
class DataRulesTest {
    private fun state(
        crlite: DatasetGeneration?,
        policy: RevoktPolicy = RevoktPolicy.DEFAULT,
        now: Long? = NOW,
    ): Finding.DataState? = dataStates(snapshot(crlite), policy.form, now)[Dataset.CRLITE]

    private val rejectAt3Days: RevoktPolicy =
        RevoktPolicy.DEFAULT
            .newBuilder()
            .rejectStaleAfterMillis(
                Dataset.CRLITE,
                3 * DAY,
            ).build()

    @Test
    fun `a fresh signed generation fires nothing and is reported whole`() {
        val gen = generation(ageMillis = 5_000)
        val s = state(gen)!!
        assertEquals(Dataset.CRLITE, s.dataset)
        assertEquals(gen.generationId, s.generationId)
        assertEquals(gen.freshness, s.freshness)
        assertEquals(NOW - 5_000, s.sourceTimestampMillis)
        assertEquals(5_000L, s.ageMillis)
        assertFalse(s.fromSeed)
        assertFalse(s.pending)
        assertNull(s.seedFormat)
        assertFalse(s.stale)
        assertEquals(emptySet(), s.rules)
        val seed = state(generation(fromSeed = true))!!
        assertTrue(seed.fromSeed)
        assertEquals(1, seed.seedFormat)
    }

    @Test
    fun `NO_DATA fires for a required dataset with no generation that is not pending, and only then`() {
        assertEquals(setOf(Rule.NO_DATA), state(noGeneration())!!.rules)
        assertEquals(emptySet(), state(noGeneration(pending = true))!!.rules)
        assertTrue(state(noGeneration(pending = true))!!.pending)
        assertEquals(emptySet(), state(generation())!!.rules)
        assertEquals(emptySet(), state(generation(fromSeed = true))!!.rules, "a seed generation is a generation")
        val notRequired =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .requiredDatasets(emptySet())
                .build()
        assertEquals(emptySet(), state(noGeneration(), notRequired)!!.rules)
    }

    @Test
    fun `a required dataset the snapshot does not hold has no generation, is not pending and fires NO_DATA`() {
        val s = state(crlite = null)!!
        assertNull(s.generationId)
        assertNull(s.ageMillis)
        assertFalse(s.pending)
        assertEquals(setOf(Rule.NO_DATA), s.rules)
    }

    @Test
    fun `dataStates holds every required dataset and every dataset the snapshot holds`() {
        val notRequired =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .requiredDatasets(emptySet())
                .build()
        assertEquals(setOf(Dataset.CRLITE), dataStates(snapshot(generation()), notRequired.form, NOW).keys)
        assertEquals(emptySet(), dataStates(snapshot(null), notRequired.form, NOW).keys)
        assertEquals(setOf(Dataset.CRLITE), dataStates(snapshot(null), RevoktPolicy.DEFAULT.form, NOW).keys)
    }

    @Test
    fun `STALE fires strictly past rejectStaleAfter, and the loud flag strictly past staleAfter`() {
        val at = 3 * DAY
        assertEquals(emptySet(), state(generation(ageMillis = at), rejectAt3Days)!!.rules)
        assertEquals(setOf(Rule.STALE), state(generation(ageMillis = at + 1), rejectAt3Days)!!.rules)
        val loud =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .staleness(Dataset.CRLITE, Staleness.ofMillis(DAY, null))
                .build()
        assertFalse(state(generation(ageMillis = DAY), loud)!!.stale)
        assertTrue(state(generation(ageMillis = DAY + 1), loud)!!.stale)
        assertEquals(emptySet(), state(generation(ageMillis = 400 * DAY), loud)!!.rules, "rejectStaleAfter null")
    }

    @Test
    fun `DEFAULT never fires STALE, however old, and flags it past three days`() {
        val s = state(generation(ageMillis = 365 * DAY))!!
        assertTrue(s.stale)
        assertEquals(emptySet(), s.rules)
        assertFalse(state(generation(ageMillis = 3 * DAY))!!.stale)
    }

    @Test
    fun `no staleness entry is neither stale nor STALE`() {
        val none =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .clearStaleness(Dataset.CRLITE)
                .build()
        val s = state(generation(ageMillis = 400 * DAY), none)!!
        assertFalse(s.stale)
        assertEquals(emptySet(), s.rules)
    }

    @Test
    fun `a seed generation fires STALE only with the persisted gate open`() {
        val old = 31 * DAY
        assertEquals(emptySet(), state(generation(old, fromSeed = true, gateOpen = false), rejectAt3Days)!!.rules)
        assertEquals(emptySet(), state(generation(old, fromSeed = true, gateOpen = false), RevoktPolicy.STRICT)!!.rules)
        assertTrue(state(generation(old, fromSeed = true, gateOpen = false), RevoktPolicy.STRICT)!!.stale)
        assertEquals(setOf(Rule.STALE), state(generation(old, fromSeed = true, gateOpen = true), rejectAt3Days)!!.rules)
        assertEquals(setOf(Rule.STALE), state(generation(old, gateOpen = false), rejectAt3Days)!!.rules, "not a seed")
    }

    @Test
    fun `STRICT fires STALE past 30 days`() {
        assertEquals(emptySet(), state(generation(30 * DAY), RevoktPolicy.STRICT)!!.rules)
        assertEquals(setOf(Rule.STALE), state(generation(30 * DAY + 1), RevoktPolicy.STRICT)!!.rules)
    }

    @Test
    fun `the age is clamped at 0 for a generation from the future`() {
        val s = state(generation(ageMillis = -DAY), rejectAt3Days)!!
        assertEquals(0L, s.ageMillis)
        assertFalse(s.stale)
        assertEquals(emptySet(), s.rules)
    }

    @Test
    fun `with no clock read there is no age, so no STALE, while NO_DATA still fires`() {
        val s = state(generation(400 * DAY), RevoktPolicy.STRICT, now = null)!!
        assertNull(s.ageMillis)
        assertFalse(s.stale)
        assertEquals(emptySet(), s.rules)
        assertEquals(setOf(Rule.NO_DATA), state(noGeneration(), now = null)!!.rules)
    }

    @Test
    fun `the data rules are NO_DATA then STALE`() {
        val all =
            dataStates(
                snapshot(generation(400 * DAY)),
                PolicyForm.of(dev.revokt.engine.policy.Preset.STRICT),
                NOW,
            )
        assertEquals(listOf(Rule.STALE), all.getValue(Dataset.CRLITE).rules.toList())
        assertEquals(listOf(Rule.NO_DATA, Rule.STALE), DATA_RULES.map { it.rule })
    }
}
