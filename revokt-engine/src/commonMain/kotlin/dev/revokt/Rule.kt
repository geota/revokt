// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.jvm.JvmField

/**
 * One rule of the spec §8 table, one-to-one with the policy, the status counters and the events (spec §4). Growable.
 * Declaration order is precedence: rules are grouped by class, and a new rule is appended at the end of its class
 * group. `ordinal` is not stable across minors, so persist `name`. [ruleClass], [layer] and [exemptable] are frozen
 * within a major, except that [exemptable] may change from false to true.
 */
public enum class Rule(
    public val ruleClass: RuleClass,
    public val layer: Layer?,
    public val exemptable: Boolean,
) {
    REVOKED(RuleClass.EVIDENCE, Layer.CRLITE, false),
    PATH_BUDGET_EXCEEDED(RuleClass.UNEVALUABLE, Layer.PATH, false),

    /** Driven by `requiredDatasets`, never by [CrliteQueryResult.NO_DATA]. */
    NO_DATA(RuleClass.UNEVALUABLE, null, true),
    ENGINE_ERROR(RuleClass.UNEVALUABLE, null, false),
    PARSE_FAILED(RuleClass.UNEVALUABLE, Layer.PATH, false),
    ISSUER_UNVERIFIED(RuleClass.UNEVALUABLE, Layer.PATH, true),
    NO_ISSUER(RuleClass.UNEVALUABLE, Layer.PATH, true),
    NOT_ENROLLED(RuleClass.NON_ANSWER, Layer.CRLITE, true),
    NO_SCTS(RuleClass.NON_ANSWER, Layer.CRLITE, true),
    NOT_COVERED(RuleClass.NON_ANSWER, Layer.CRLITE, false),
    STALE(RuleClass.DATA_QUALITY, null, true),
    UNSIGNED_DATA(RuleClass.DATA_QUALITY, null, true),
    ;

    public companion object {
        /** The precedence: declaration order. */
        @JvmField public val PRECEDENCE: List<Rule> = entries
    }
}
