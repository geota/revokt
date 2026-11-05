// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** How a walk ended (spec §4, §5.1): complete, or the budget it exhausted. Growable. */
public enum class WalkEnd {
    COMPLETE,

    /** `RevoktLimits.MAX_RELATED_PER_LEVEL` related candidates at one node. */
    RELATED_BUDGET,

    /** `RevoktLimits.MAX_VERIFICATIONS` verifier calls. */
    VERIFICATION_BUDGET,

    /** `RevoktLimits.MAX_EXPLORED` candidates explored, or a presented chain over its caps (no walk). */
    EXPLORATION_BUDGET,
}
