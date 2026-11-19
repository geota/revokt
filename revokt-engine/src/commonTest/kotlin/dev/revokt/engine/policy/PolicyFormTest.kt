// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.Enforcement
import dev.revokt.Exemption
import dev.revokt.Outcome
import dev.revokt.Rule
import dev.revokt.TrustClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The commonMain policy form `RevoktPolicy` compiles to (#123): the presets as §8 tabulates them, read-only copies. */
class PolicyFormTest {
    @Test
    fun `a preset's form is its table`() {
        for (preset in Preset.entries) {
            val table = PolicyTable.preset(preset)
            val form = PolicyForm.of(preset)
            assertEquals(preset, form.preset)
            for (rule in Rule.entries) assertEquals(table.outcome(rule), form.outcome(rule), "$preset $rule")
            assertTrue(form.exemptions.isEmpty())
            assertEquals(table.requiredDatasets, form.requiredDatasets)
            assertEquals(table.staleness, form.staleness)
            for (dataset in Dataset.entries) {
                assertEquals(table.minTrustClass.getValue(dataset), form.minTrustClass(dataset), "$preset $dataset")
            }
            assertTrue(form.minTrustClassEntries.isEmpty())
            assertEquals(table.rollbackWindowMillis, form.rollbackWindowMillis)
            assertEquals(table.clockSkewMillis, form.clockSkewMillis)
            assertEquals(table.signedSourceFailingAfterMillis, form.signedSourceFailingAfterMillis)
        }
    }

    @Test
    fun `a dataset with no minTrustClass entry takes the preset floor, an entry wins`() {
        val strict = PolicyForm.of(Preset.STRICT)
        val form = copy(strict, minTrustClass = mapOf(Dataset.CRLITE to TrustClass.MIRROR))
        assertEquals(TrustClass.SIGNED, strict.minTrustClass(Dataset.CRLITE))
        assertEquals(TrustClass.MIRROR, form.minTrustClass(Dataset.CRLITE))
    }

    @Test
    fun `the form copies its inputs and needs an outcome for every rule`() {
        val outcomes = Rule.entries.associateWithTo(mutableMapOf()) { Outcome.ALLOW }
        val required = mutableSetOf(Dataset.CRLITE)
        val form = copy(PolicyForm.of(Preset.DEFAULT), outcomes = outcomes, requiredDatasets = required)
        outcomes[Rule.REVOKED] = Outcome.REJECT
        required.clear()
        assertEquals(Outcome.ALLOW, form.outcome(Rule.REVOKED))
        assertEquals(setOf(Dataset.CRLITE), form.requiredDatasets)

        outcomes.remove(Rule.STALE)
        assertFailsWith<IllegalArgumentException> { copy(form, outcomes = outcomes) }
    }

    @Test
    fun `exemptAnchors covers the exemptable non-evidence rules off the empty path`() {
        assertEquals(
            listOf(Rule.NO_DATA, Rule.NOT_ENROLLED, Rule.NO_SCTS, Rule.STALE, Rule.UNSIGNED_DATA),
            Rule.entries.filter { it.anchorExemptable() },
        )
    }

    @Test
    fun `neither preset's form has a diagnostic`() {
        for (preset in Preset.entries) {
            for (enforcement in Enforcement.entries) {
                assertEquals(emptyList(), validatePolicy(PolicyForm.of(preset), enforcement), "$preset $enforcement")
            }
        }
    }

    @Test
    fun `an exemption is held as given`() {
        val exemption = Exemption { true }
        val form = copy(PolicyForm.of(Preset.STRICT), exemptions = mapOf(Rule.NO_SCTS to exemption))
        assertEquals(exemption, form.exemption(Rule.NO_SCTS))
        assertEquals(null, form.exemption(Rule.NO_DATA))
    }

    private fun copy(
        form: PolicyForm,
        outcomes: Map<Rule, Outcome> = form.outcomes,
        exemptions: Map<Rule, Exemption> = form.exemptions,
        requiredDatasets: Set<Dataset> = form.requiredDatasets,
        minTrustClass: Map<Dataset, TrustClass> = form.minTrustClassEntries,
    ) = PolicyForm(
        preset = form.preset,
        outcomes = outcomes,
        exemptions = exemptions,
        requiredDatasets = requiredDatasets,
        staleness = form.staleness,
        minTrustClass = minTrustClass,
        rollbackWindowMillis = form.rollbackWindowMillis,
        clockSkewMillis = form.clockSkewMillis,
        signedSourceFailingAfterMillis = form.signedSourceFailingAfterMillis,
    )
}
