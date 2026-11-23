// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.jvm.JvmField

/**
 * The documented limits of spec §5.1 ("Limits" table), named exactly as the table names them; every duration is in
 * milliseconds (the spec's convention: time fields are stored as millis). Public are only the four download and
 * record caps the builder raises (spec §4 `limits { }`): `@JvmField val`, never `const val`, so a value is read at
 * runtime rather than inlined into consumers. The walker budgets and the other limits are internal (#221), and a
 * limit joins this object when the feature that reads it is built. A change to any value is a `spec` PR.
 */
public object RevoktLimits {
    /** A path holds at most `MAX_DEPTH + 1` certificates including the terminal. */
    internal val MAX_DEPTH: Int = 16

    /** Presented certificates beyond which the chain is `Budget(EXPLORATION_BUDGET)` without a walk. */
    internal val MAX_PRESENTED: Int = 64

    /** Summed presented DER beyond which the chain is `Budget(EXPLORATION_BUDGET)` without a walk. */
    internal val MAX_PRESENTED_BYTES: Long = 1L shl 20

    /**
     * The walk's one work budget: candidates explored per walk, memo hits and candidates the issuer rules refuse
     * included, a loop not; the next one ends the walk `Budget(EXPLORATION_BUDGET)`. Each exploration makes at most
     * one verifier call, so it bounds those too.
     */
    internal val MAX_EXPLORED: Int = 256

    /** The PKIX fallback is skipped for longer presented chains. */
    internal val FALLBACK_MAX_PRESENTED: Int = 8

    internal val CROSS_CALL_MEMO_ENTRIES: Int = 1_024

    internal val ENGINE_CLOSE_DRAIN: Long = 5_000

    internal val FETCH_TIMEOUT: Long = 30_000

    /** Per-certificate DER size; a larger certificate is a dropped candidate, or `PARSE_FAILED(OVERSIZE)` for the leaf. */
    internal val MAX_CERT_BYTES: Int = 262_144

    @JvmField public val MAX_FILTER_BYTES: Long = 16L shl 20

    @JvmField public val MAX_JSON_BYTES: Long = 4L shl 20

    @JvmField public val MAX_X5U_BYTES: Long = 64L shl 10

    /**
     * Records a changeset may keep after channel filtering; more is rejected before any body fetch. 1,024: at about four
     * deltas a day, some 256 days, so the cap does not freeze a shipped client; the per-file caps still bound the bodies.
     */
    @JvmField public val MAX_CHANGESET_RECORDS: Int = 1_024

    internal val MAX_BACKOFF: Long = 24L * 60 * 60 * 1_000
}
