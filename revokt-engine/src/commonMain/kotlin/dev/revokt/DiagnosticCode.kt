// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What a [PolicyDiagnostic] is about (spec §4): one code per configuration check that `validate(enforcement)` runs.
 * Runtime conditions are [WarningCode]s, and why a sync stopped is its [SyncFailure]. Growable: a code may be added in
 * a minor, so a `when` over codes needs an `else` branch. Persist `name`, never `ordinal`. Match on the code, never on
 * the message.
 */
public enum class DiagnosticCode {
    /** An exemption registered on an `EVIDENCE` rule. */
    EXEMPTION_ON_EVIDENCE_RULE,

    /** `STALE` rejects and no dataset has a `rejectStaleAfter`, so the rule can never fire. */
    STALE_REJECTS_WITHOUT_THRESHOLD,

    /** An exemption on a rule whose outcome is `ALLOW`. */
    EXEMPT_ON_ALLOW,

    /** `PATH_BUDGET_EXCEEDED` allows. */
    BUDGET_ALLOWS,

    /** An `EVIDENCE` rule allowed where the preset the policy derives from rejects. */
    EVIDENCE_LOWERED_BELOW_PRESET,

    /** A required dataset's staleness entry cleared. */
    STALENESS_CLEARED_FOR_REQUIRED_DATASET,
}
