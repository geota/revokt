// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.Rule
import dev.revokt.RuleClass
import java.security.cert.CertPathValidatorException.BasicReason
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The growability golden fixture of spec §4, in three sections:
 * - `[rules]`, one row per rule in precedence order with §4's tuple: rule, class, layer, exemptable, emptyPath,
 *   basicReason, introducedIn, flippedIn per preset, then the `DEFAULT` and `STRICT` outcomes;
 * - `[presets]`, one row per preset with its `requiredDatasets` and the three time fields;
 * - `[datasets]`, one row per preset and dataset with its staleness thresholds and `minTrustClass`, so a new
 *   dataset adds rows and changes none.
 *
 * The fixture is edited by hand, under the growability contract, whenever the model changes. This test asserts the
 * model equals it, and `verifyRuleGrowability` (#73) checks that its diff is one the contract permits.
 */
class RuleGoldenTest {
    @Test
    fun `the model equals the golden fixture`() {
        val committed =
            checkNotNull(javaClass.getResourceAsStream(FIXTURE)) { "missing $FIXTURE" }.bufferedReader().use { r ->
                r.readLines().filter { it.isNotBlank() && !it.startsWith("#") }
            }
        assertEquals(render(), committed, "the Rule model changed: update $FIXTURE under the growability contract")
    }

    @Test
    fun `the BasicReason map is total`() {
        for (rule in Rule.entries) {
            val revocation = rule.ruleClass == RuleClass.EVIDENCE
            val expected = if (revocation) BasicReason.REVOKED else BasicReason.UNDETERMINED_REVOCATION_STATUS
            assertEquals(expected, rule.basicReason(), "$rule")
        }
    }

    private fun render(): List<String> {
        val out = mutableListOf("[rules]", RULE_COLUMNS.joinToString(TAB))
        for (rule in Rule.PRECEDENCE) {
            out +=
                listOf(
                    rule.name,
                    rule.ruleClass.name,
                    rule.layer?.name ?: NONE,
                    rule.exemptable.toString(),
                    (rule in PolicyTable.EMPTY_PATH).toString(),
                    rule.basicReason().name,
                    PolicyTable.introducedIn(rule),
                    PolicyTable.flippedIn(Preset.DEFAULT, rule) ?: NONE,
                    PolicyTable.flippedIn(Preset.STRICT, rule) ?: NONE,
                    PolicyTable.DEFAULT.outcome(rule).name,
                    PolicyTable.STRICT.outcome(rule).name,
                ).joinToString(TAB)
        }
        out += listOf("[presets]", PRESET_COLUMNS.joinToString(TAB))
        for (preset in Preset.entries) {
            val t = PolicyTable.preset(preset)
            out +=
                listOf(
                    preset.name,
                    t.requiredDatasets
                        .map { it.name }
                        .sorted()
                        .joinToString(","),
                    t.rollbackWindowMillis.toString(),
                    t.clockSkewMillis.toString(),
                    t.signedSourceFailingAfterMillis.toString(),
                ).joinToString(TAB)
        }
        out += listOf("[datasets]", DATASET_COLUMNS.joinToString(TAB))
        for (preset in Preset.entries) {
            val t = PolicyTable.preset(preset)
            for (dataset in Dataset.entries) {
                val staleness = t.staleness[dataset]
                out +=
                    listOf(
                        preset.name,
                        dataset.name,
                        staleness?.staleAfterMillis?.toString() ?: NONE,
                        staleness?.rejectStaleAfterMillis?.toString() ?: NONE,
                        t.minTrustClass.getValue(dataset).name,
                    ).joinToString(TAB)
            }
        }
        return out
    }

    private companion object {
        const val FIXTURE = "/dev/revokt/engine/policy/rule-growability.tsv"
        const val NONE = "-"
        const val TAB = "\t"
        val RULE_COLUMNS =
            listOf(
                "rule",
                "class",
                "layer",
                "exemptable",
                "emptyPath",
                "basicReason",
                "introducedIn",
                "flippedIn.DEFAULT",
                "flippedIn.STRICT",
                "DEFAULT",
                "STRICT",
            )
        val PRESET_COLUMNS =
            listOf(
                "preset",
                "requiredDatasets",
                "rollbackWindowMillis",
                "clockSkewMillis",
                "signedSourceFailingAfterMillis",
            )
        val DATASET_COLUMNS = listOf("preset", "dataset", "staleAfterMillis", "rejectStaleAfterMillis", "minTrustClass")
    }
}
