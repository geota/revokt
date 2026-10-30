// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** What kind of finding a [Rule] reports (spec §4). Closed. */
public enum class RuleClass {
    /** A verified positive finding against the chain: revoked, listed, distrusted, CT policy verified and not met. */
    EVIDENCE,

    /** revokt could not evaluate this chain. */
    UNEVALUABLE,

    /** A layer ran and had nothing to say. */
    NON_ANSWER,

    /** About the data, not the chain. */
    DATA_QUALITY,
}
