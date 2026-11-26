// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What a [RevoktWarning] is about (spec §4): a condition found at run time, by a sync or the seed load, not by reading
 * the configuration ([DiagnosticCode] is that). Growable: a code may be added in a minor, so a `when` over codes needs
 * an `else` branch. Persist `name`, never `ordinal`. Match on the code, never on the message.
 */
internal enum class WarningCode {
    /** A sync's body or record count above half its `RevoktLimits` constant, the signed size notwithstanding (§5.1). */
    CAP_NEAR_LIMIT,

    /** The seed could not be read, and is ignored (§6.5). */
    SEED_UNREADABLE,

    /** The seed's channel is not the configured one (§6.5); `start()` throws on it. */
    SEED_CHANNEL_MISMATCH,

    /**
     * `start()` could not open the store (§3, §6.5): ownership, an I/O failure in `lock()`, or a `store.version` that is
     * absent beside other entries, malformed or unreadable. The instance runs in memory and the store is left untouched.
     */
    STORE_UNREADABLE,

    /** `store.version` was lower than this engine's: the store was rebuilt, `store.version` first (§6.5). */
    STORE_MIGRATED,

    /** `store.version` was higher than this engine's: run in memory, or rebuilt, per the storage's `NewerLayout` (§6.5). */
    STORE_NEWER_LAYOUT,

    /** Another process holds the store's lock (§3): the instance runs in memory for the life of the process. */
    STORE_LOCKED,
}
