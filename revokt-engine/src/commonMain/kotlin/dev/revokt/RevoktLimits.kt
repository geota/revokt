// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.jvm.JvmField

/**
 * The documented limits of spec §5.1 ("Limits" table), named exactly as the table names them; every duration is in
 * milliseconds (the spec's convention: time fields are stored as millis). Walker budgets are constants; download and
 * record caps are builder-overridable upward; cache sizes are builder-configurable. `@JvmField val`, never
 * `const val`, so a value is read at runtime rather than inlined into consumers (spec §4). A change to any value is a
 * `spec` PR. The per-channel readiness deadlines (`AWAIT_DATA_COMPAT`, `AWAIT_DATA_DEFAULT`) are measured in 0.3.
 */
public object RevoktLimits {
    /** A path holds at most `MAX_DEPTH + 1` certificates including the terminal. */
    @JvmField public val MAX_DEPTH: Int = 16

    /** Presented certificates beyond which the chain is `Budget(EXPLORATION_BUDGET)` without a walk. */
    @JvmField public val MAX_PRESENTED: Int = 64

    /** Summed presented DER beyond which the chain is `Budget(EXPLORATION_BUDGET)` without a walk. */
    @JvmField public val MAX_PRESENTED_BYTES: Long = 1L shl 20

    /** Related candidates explored at one node; the next one triggers `RELATED_BUDGET`. */
    @JvmField public val MAX_RELATED_PER_LEVEL: Int = 64

    /** Verifier calls per walk (memo hits excluded). */
    @JvmField public val MAX_VERIFICATIONS: Int = 256

    /** Candidates for which verification was requested per walk, memo hits included. */
    @JvmField public val MAX_EXPLORED: Int = 1_024

    /** The PKIX fallback is skipped for longer presented chains. */
    @JvmField public val FALLBACK_MAX_PRESENTED: Int = 8

    @JvmField public val PATH_CACHE_ENTRIES: Int = 256

    @JvmField public val PATH_CACHE_TTL: Long = 10L * 60 * 1_000

    @JvmField public val CROSS_CALL_MEMO_ENTRIES: Int = 1_024

    @JvmField public val ACCEPTANCE_MEMO_ENTRIES: Int = 1_024

    @JvmField public val ACCEPTANCE_MEMO_TTL: Long = 24L * 60 * 60 * 1_000

    /** The signed source's `BLOCKED_BY_SELF` hold, millis (spec §8). */
    @JvmField public val FEED_HOST_HOLD: Long = 24L * 60 * 60 * 1_000

    @JvmField public val ENGINE_CLOSE_DRAIN: Long = 5_000

    @JvmField public val FETCH_TIMEOUT: Long = 30_000

    @JvmField public val VERDICT_CACHE_ENTRIES: Int = 1_024

    @JvmField public val VERDICT_CACHE_TTL: Long = 60_000

    @JvmField public val ANCHOR_REFRESH_MIN_INTERVAL: Long = 60_000

    @JvmField public val EVENT_RING_CAPACITY: Int = 64

    @JvmField public val REJECTED_QUEUE_CAPACITY: Int = 4_096

    /** Live trust managers per `Revokt`; builder-overridable in both directions, at least 1. */
    @JvmField public val MAX_TRUST_MANAGERS: Int = 16

    /** Per-certificate DER size; a larger certificate is a dropped candidate, or `PARSE_FAILED(OVERSIZE)` for the leaf. */
    @JvmField public val MAX_CERT_BYTES: Int = 262_144

    @JvmField public val MAX_FILTER_BYTES: Long = 16L shl 20

    @JvmField public val MAX_JSON_BYTES: Long = 4L shl 20

    @JvmField public val MAX_X5U_BYTES: Long = 64L shl 10

    @JvmField public val MAX_MANIFEST_ENTRIES: Int = 32

    @JvmField public val MAX_CHANGESET_RECORDS: Int = 256

    @JvmField public val MAX_SYNC_BYTES: Long = 128L shl 20

    @JvmField public val READONLY_POLL_INTERVAL: Long = 60_000

    @JvmField public val MAX_BACKOFF: Long = 24L * 60 * 60 * 1_000

    /** `MiB`, for the builder's `limits { }` block. */
    @JvmField public val MiB: Long = 1L shl 20
}
