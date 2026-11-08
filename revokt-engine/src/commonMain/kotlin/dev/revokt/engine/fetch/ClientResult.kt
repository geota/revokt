// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.DiagnosticCode
import dev.revokt.SyncStage

/** Why a [RemoteSettingsClient] call failed; every one is `SyncOutcome.FAILED` at [ClientResult.Failed.stage]. */
internal enum class ClientFailure {
    /** A request header value holds a CR or LF (the configured `userAgent`); not sanitised, not sent (#177). */
    HEADER_VALUE,

    /** `_expected` or `_since` is negative, so it cannot enter a query string (spec §7.1). */
    QUERY_VALUE,

    /** The fetcher threw, returned null, or the executor refused the fetch (spec §3: any `Throwable` is `FAILED`). */
    FETCHER_THREW,

    /** The fetch outlived `FetchRequest.timeoutMillis` (spec §3, §5.1 `FETCH_TIMEOUT`). */
    TIMEOUT,

    /**
     * A status other than 200, or a 304 to an unconditional request: a 3xx is never followed and a 401 or 407 is never
     * answered (spec §3, §7.1); [ClientResult.Failed.httpStatus] has it.
     */
    HTTP_STATUS,

    /** The body is over `FetchRequest.maxBodyBytes`, re-checked whatever the fetcher did (spec §3). */
    BODY_TOO_LARGE,

    /** The changeset or `monitor/changes` body is not the JSON envelope, or `monitor/changes` does not list the collection once. */
    MALFORMED,

    /** The x5u URL breaks a §7.1 rule; nothing was fetched ([X5uUrlFailure] in the detail). */
    X5U_URL,

    /** A signed record declares an attachment above `MAX_FILTER_BYTES`; refused before any fetch (spec §5.1). */
    ATTACHMENT_OVER_CAP,

    /** The attachment's size is not the signed record's `attachment.size`. */
    ATTACHMENT_SIZE,

    /** The attachment's SHA-256 is not the signed record's `attachment.hash`. */
    ATTACHMENT_HASH,

    /** A record fails the collection schema (spec §7.1), `SYNC_SCHEMA_REJECTED`. */
    SCHEMA,

    /** The channel holds more than `MAX_CHANGESET_RECORDS` records (spec §5.1); refused before any body fetch. */
    TOO_MANY_RECORDS,
}

/**
 * What one [RemoteSettingsClient] call produced: never a throw (spec §3). Every result carries the server's honoured
 * `Backoff` or `Retry-After` ([backoffMillis], for #131) and the response status when a response arrived.
 */
internal sealed class ClientResult<out T> {
    /** The last response's status; null when no response arrived (refused before the fetch, a throw, a timeout). */
    abstract val httpStatus: Int?

    /** The longest `Backoff` or `Retry-After` wait in milliseconds, at most `MAX_BACKOFF`; null when none ([Backoff]). */
    abstract val backoffMillis: Long?

    /** [value] passed every check; [httpStatus] is null for the record check, which fetches nothing. */
    class Ok<out T>(
        val value: T,
        override val httpStatus: Int?,
        override val backoffMillis: Long?,
    ) : ClientResult<T>()

    /** A 304 to the changeset's `If-None-Match`: the collection is at the verified cursor (spec §3 `UNCHANGED`). */
    class Unchanged(
        override val backoffMillis: Long?,
    ) : ClientResult<Nothing>() {
        override val httpStatus: Int get() = NOT_MODIFIED
    }

    /**
     * A `FAILED` call at [stage]. [code] is the sync diagnostic the failure names beyond `SYNC_FAILED`:
     * `SYNC_SCHEMA_REJECTED` for [ClientFailure.SCHEMA], `CAP_NEAR_LIMIT` for [ClientFailure.ATTACHMENT_OVER_CAP].
     */
    class Failed(
        val stage: SyncStage,
        val failure: ClientFailure,
        val detail: String,
        override val httpStatus: Int? = null,
        val cause: Throwable? = null,
        override val backoffMillis: Long? = null,
    ) : ClientResult<Nothing>() {
        val code: DiagnosticCode?
            get() =
                when (failure) {
                    ClientFailure.SCHEMA -> DiagnosticCode.SYNC_SCHEMA_REJECTED
                    ClientFailure.ATTACHMENT_OVER_CAP -> DiagnosticCode.CAP_NEAR_LIMIT
                    else -> null
                }

        override fun toString(): String = "Failed($stage, $failure, http=$httpStatus: $detail)"
    }

    internal companion object {
        const val OK = 200
        const val NOT_MODIFIED = 304
    }
}
