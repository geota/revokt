// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What a [RevoktWarning] is about (spec §4): a condition found at run time, by a sync or the seed load, not by reading
 * the configuration ([DiagnosticCode] is that). Growable: a code may be added in a minor, so a `when` over codes needs
 * an `else` branch. Persist `name`, never `ordinal`. Match on the code, never on the message.
 */
public enum class WarningCode {
    /** A sync's body or record count above half its `RevoktLimits` constant, the signed size notwithstanding (§5.1). */
    CAP_NEAR_LIMIT,

    /** The seed could not be read, and is ignored (§6.5). */
    SEED_UNREADABLE,

    /** The seed's channel is not the configured one (§6.5); `start()` throws on it. */
    SEED_CHANNEL_MISMATCH,
}
