// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.SyncFailure

/**
 * What one [RemoteSettingsClient] call produced: never a throw (spec §3). Every result carries the server's honoured
 * `Backoff` or `Retry-After` ([backoffMillis], for #131) and the response status when a response arrived.
 */
internal sealed class ClientResult<out T> {
    /** The last response's status; null when no response arrived (refused before the fetch, a throw, a timeout). */
    abstract val httpStatus: Int?

    /** The longest `Backoff` or `Retry-After` wait in milliseconds, at most `MAX_BACKOFF`; null when none ([Backoff]). */
    abstract val backoffMillis: Long?

    /**
     * [value] passed every check; [httpStatus] is null for the record check, which fetches nothing. [bodyBytes] is the
     * size of the body read, for the sync's half-cap warning (spec §4 `WarningCode.CAP_NEAR_LIMIT`); null when nothing
     * was fetched.
     */
    class Ok<out T>(
        val value: T,
        override val httpStatus: Int?,
        override val backoffMillis: Long?,
        val bodyBytes: Long? = null,
    ) : ClientResult<T>()

    /** A 304 to the changeset's `If-None-Match`: the collection is at the verified cursor (spec §3 `UNCHANGED`). */
    class Unchanged(
        override val backoffMillis: Long?,
    ) : ClientResult<Nothing>() {
        override val httpStatus: Int get() = NOT_MODIFIED
    }

    /**
     * A `FAILED` call, as [failure]: the code of the fetch for a failure of the exchange itself (a throw, a timeout, a
     * status, an oversize body, a header or query value), else the check's own code. [detail] says which, for people.
     */
    class Failed(
        val failure: SyncFailure,
        val detail: String,
        override val httpStatus: Int? = null,
        val cause: Throwable? = null,
        override val backoffMillis: Long? = null,
    ) : ClientResult<Nothing>() {
        override fun toString(): String = "Failed($failure, http=$httpStatus: $detail)"
    }

    internal companion object {
        const val OK = 200
        const val NOT_MODIFIED = 304
    }
}
