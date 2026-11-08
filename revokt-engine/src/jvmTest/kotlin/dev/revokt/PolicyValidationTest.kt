// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.Preset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import dev.revokt.engine.policy.validatePolicy as validateForm

/**
 * The V diagnostics of spec §4 that are functions of the policy alone (#123): each fires in exactly its case, with its
 * severity under `OBSERVE` and `ENFORCE` (and `OFF`, which never enforces), and neither preset has any.
 */
class PolicyValidationTest {
    private data class Seen(
        val code: DiagnosticCode,
        val severity: Severity,
        val rule: Rule? = null,
        val dataset: Dataset? = null,
    )

    private fun seen(diagnostics: List<PolicyDiagnostic>) =
        diagnostics.map {
            Seen(it.code, it.severity, it.rule, it.dataset)
        }

    private fun validate(
        policy: RevoktPolicy,
        enforcement: Enforcement,
    ) = seen(validatePolicy(policy, enforcement))

    /** The same diagnostics under every enforcement. */
    private fun assertAlways(
        expected: List<Seen>,
        policy: RevoktPolicy,
    ) {
        for (enforcement in Enforcement.entries) assertEquals(expected, validate(policy, enforcement), "$enforcement")
    }

    private fun default() = RevoktPolicy.DEFAULT.newBuilder()

    private fun strict() = RevoktPolicy.STRICT.newBuilder()

    @Test
    fun `neither preset has a diagnostic under any enforcement`() {
        for (policy in listOf(RevoktPolicy.DEFAULT, RevoktPolicy.STRICT)) assertAlways(emptyList(), policy)
        assertAlways(emptyList(), strict().exemptAnchors(listOf(ByteArray(32))).build())
    }

    @Test
    fun `STALE_REJECTS_WITHOUT_THRESHOLD when STALE rejects and no dataset has a reject threshold`() {
        val warning = listOf(Seen(DiagnosticCode.STALE_REJECTS_WITHOUT_THRESHOLD, Severity.WARNING, Rule.STALE))
        assertAlways(warning, default().rule(Rule.STALE, Outcome.REJECT).build())
        assertAlways(warning, strict().rejectStaleAfterMillis(Dataset.CRLITE, null).build())
        assertAlways(
            emptyList(),
            default()
                .rule(Rule.STALE, Outcome.REJECT)
                .rejectStaleAfterMillis(
                    Dataset.CRLITE,
                    1L shl 40,
                ).build(),
        )
        assertAlways(emptyList(), default().rejectStaleAfterMillis(Dataset.CRLITE, 1L shl 40).build())
    }

    @Test
    fun `EXEMPT_ON_ALLOW for each exempted rule that allows`() {
        assertAlways(
            listOf(
                Seen(DiagnosticCode.EXEMPT_ON_ALLOW, Severity.WARNING, Rule.NO_ISSUER),
                Seen(DiagnosticCode.EXEMPT_ON_ALLOW, Severity.WARNING, Rule.NO_SCTS),
            ),
            default().exempt(Rule.NO_SCTS, Exemption { true }).exempt(Rule.NO_ISSUER, Exemption { true }).build(),
        )
        assertAlways(
            emptyList(),
            default().rule(Rule.NO_SCTS, Outcome.REJECT).exempt(Rule.NO_SCTS, Exemption { true }).build(),
        )
        // exemptAnchors made while the rule rejected, then the rule lowered.
        assertAlways(
            listOf(Seen(DiagnosticCode.EXEMPT_ON_ALLOW, Severity.WARNING, Rule.NO_SCTS)),
            strict().exemptAnchors(listOf(ByteArray(32))).rule(Rule.NO_SCTS, Outcome.ALLOW).build(),
        )
    }

    @Test
    fun `EVIDENCE_LOWERED_BELOW_PRESET is an ERROR under ENFORCE for a row rejecting since the major's x_0`() {
        for (preset in listOf(RevoktPolicy.DEFAULT, RevoktPolicy.STRICT)) {
            val lowered = preset.newBuilder().rule(Rule.REVOKED, Outcome.ALLOW).build()
            val diagnostic = Seen(DiagnosticCode.EVIDENCE_LOWERED_BELOW_PRESET, Severity.WARNING, Rule.REVOKED)
            assertEquals(listOf(diagnostic), validate(lowered, Enforcement.OBSERVE))
            assertEquals(listOf(diagnostic), validate(lowered, Enforcement.OFF))
            assertEquals(listOf(diagnostic.copy(severity = Severity.ERROR)), validate(lowered, Enforcement.ENFORCE))
            val message = validatePolicy(lowered, Enforcement.ENFORCE).single().message
            assertTrue("derive from DEFAULT" in message && "exempt per anchor" in message, message)
        }
        // Lowering a rule that is not evidence is not this diagnostic.
        assertAlways(emptyList(), default().rule(Rule.NO_DATA, Outcome.ALLOW).build())
        assertAlways(emptyList(), strict().rule(Rule.ENGINE_ERROR, Outcome.ALLOW).build())
    }

    @Test
    fun `EVIDENCE_LOWERED_BELOW_PRESET is a WARNING in the minor the preset row flipped and an ERROR after`() {
        val lowered =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.REVOKED, Outcome.ALLOW)
                .build()

        fun severity(
            enforcement: Enforcement,
            currentMinor: String,
        ) = validateForm(lowered.form, enforcement, currentMinor) { preset, rule ->
            "0.5".takeIf { preset == Preset.DEFAULT && rule == Rule.REVOKED }
        }.single().severity

        assertEquals(Severity.WARNING, severity(Enforcement.ENFORCE, "0.5"))
        assertEquals(Severity.ERROR, severity(Enforcement.ENFORCE, "0.6"))
        assertEquals(Severity.WARNING, severity(Enforcement.OBSERVE, "0.5"))
        assertEquals(Severity.WARNING, severity(Enforcement.OBSERVE, "0.6"))
    }

    @Test
    fun `EXEMPTION_ON_EVIDENCE_RULE for an exemption on an evidence rule`() {
        // M1's one evidence rule is not exemptable, so the builder refuses this; the form is what validate reads.
        val default = PolicyForm.of(Preset.DEFAULT)
        val form =
            PolicyForm(
                preset = default.preset,
                outcomes = default.outcomes,
                exemptions = mapOf(Rule.REVOKED to Exemption { true }),
                requiredDatasets = default.requiredDatasets,
                staleness = default.staleness,
                minTrustClass = default.minTrustClassEntries,
                rollbackWindowMillis = default.rollbackWindowMillis,
                clockSkewMillis = default.clockSkewMillis,
                signedSourceFailingAfterMillis = default.signedSourceFailingAfterMillis,
            )
        for (enforcement in Enforcement.entries) {
            assertEquals(
                listOf(Seen(DiagnosticCode.EXEMPTION_ON_EVIDENCE_RULE, Severity.WARNING, Rule.REVOKED)),
                seen(validateForm(form, enforcement)),
            )
        }
    }

    @Test
    fun `BUDGET_ALLOWS when the path budget allows`() {
        val warning = listOf(Seen(DiagnosticCode.BUDGET_ALLOWS, Severity.WARNING, Rule.PATH_BUDGET_EXCEEDED))
        assertAlways(warning, default().rule(Rule.PATH_BUDGET_EXCEEDED, Outcome.ALLOW).build())
        assertAlways(warning, strict().rule(Rule.PATH_BUDGET_EXCEEDED, Outcome.ALLOW).build())
    }

    @Test
    fun `STALENESS_CLEARED_FOR_REQUIRED_DATASET when a required dataset's entry is cleared`() {
        val cleared =
            Seen(DiagnosticCode.STALENESS_CLEARED_FOR_REQUIRED_DATASET, Severity.WARNING, dataset = Dataset.CRLITE)
        assertAlways(listOf(cleared), default().clearStaleness(Dataset.CRLITE).build())
        assertAlways(
            listOf(Seen(DiagnosticCode.STALE_REJECTS_WITHOUT_THRESHOLD, Severity.WARNING, Rule.STALE), cleared),
            strict().clearStaleness(Dataset.CRLITE).build(),
        )
        assertAlways(emptyList(), default().clearStaleness(Dataset.CRLITE).requiredDatasets(emptySet()).build())
        assertAlways(
            emptyList(),
            default().clearStaleness(Dataset.CRLITE).staleness(Dataset.CRLITE, Staleness.ofMillis(1, null)).build(),
        )
    }

    @Test
    fun `several diagnostics come in the section 4 order`() {
        val policy =
            strict()
                .rule(Rule.REVOKED, Outcome.ALLOW)
                .rule(Rule.PATH_BUDGET_EXCEEDED, Outcome.ALLOW)
                .rule(Rule.NO_SCTS, Outcome.ALLOW)
                .exempt(Rule.NO_SCTS, Exemption { true })
                .clearStaleness(Dataset.CRLITE)
                .build()
        assertEquals(
            listOf(
                Seen(DiagnosticCode.STALE_REJECTS_WITHOUT_THRESHOLD, Severity.WARNING, Rule.STALE),
                Seen(DiagnosticCode.EXEMPT_ON_ALLOW, Severity.WARNING, Rule.NO_SCTS),
                Seen(DiagnosticCode.EVIDENCE_LOWERED_BELOW_PRESET, Severity.ERROR, Rule.REVOKED),
                Seen(DiagnosticCode.BUDGET_ALLOWS, Severity.WARNING, Rule.PATH_BUDGET_EXCEEDED),
                Seen(DiagnosticCode.STALENESS_CLEARED_FOR_REQUIRED_DATASET, Severity.WARNING, dataset = Dataset.CRLITE),
            ),
            validate(policy, Enforcement.ENFORCE),
        )
    }
}
