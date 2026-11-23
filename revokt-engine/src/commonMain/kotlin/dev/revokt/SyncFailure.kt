// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Why a sync was [SyncOutcome.SKIPPED] or [SyncOutcome.FAILED] (spec §4): [SyncResult.failure], with the fetcher's or
 * the loader's throwable on [SyncResult.cause] and the last response status on [SyncResult.httpStatus]. One code per
 * step a sync can stop at, so the code says where it stopped. Growable: a code may be added in a minor, so a `when`
 * over codes needs an `else` branch. Persist `name`, never `ordinal`. A 401 or 407 is the code of the fetch it
 * interrupted: [CHANGESET_FETCH], [X5U_FETCH] or [ATTACHMENT_FETCH] (§3).
 */
internal enum class SyncFailure(
    /** The outcome this code ends a sync with: [SyncOutcome.SKIPPED] or [SyncOutcome.FAILED]. */
    public val outcome: SyncOutcome,
) {
    /** `SKIPPED`: the source's `backoffUntilMillis` is after now; nothing was fetched (§7.1). */
    BACKOFF(SyncOutcome.SKIPPED),

    /** `SKIPPED`: the verified `<ts>` is older than the dataset's floor (§7.1 "Rollback guard"); not a feed failure. */
    ROLLBACK_REFUSED(SyncOutcome.SKIPPED),

    /**
     * `monitor/changes` or the changeset fetch: the fetcher threw or returned null, it timed out, a status other than
     * 200 (or a 304 to an unconditional request), a body over its cap, or a header or query value that cannot be sent.
     */
    CHANGESET_FETCH(SyncOutcome.FAILED),

    /** `monitor/changes` or the changeset is not the JSON envelope, or `monitor/changes` does not list the collection once. */
    CHANGESET_MALFORMED(SyncOutcome.FAILED),

    /** The channel holds more than `MAX_CHANGESET_RECORDS` records (§5.1); refused before any body fetch. */
    TOO_MANY_RECORDS(SyncOutcome.FAILED),

    /** `metadata.signatures` is absent or empty, no entry was tried, or the loop reached a `null` entry (§7.1). */
    NO_SIGNATURE(SyncOutcome.FAILED),

    /** The x5u URL breaks a §7.1 rule (grammar, host, rewrite); nothing was fetched. */
    X5U_URL(SyncOutcome.FAILED),

    /** The x5u fetch: as [CHANGESET_FETCH], for the x5u. */
    X5U_FETCH(SyncOutcome.FAILED),

    /** The x5u body is not a PEM chain, or the chain fails a §7.1 check other than validity (`NOT_PINNED`, `EKU`, `SAN`). */
    X5U_CHAIN(SyncOutcome.FAILED),

    /** A link of the x5u path is outside its validity window at the local clock (§7.1), the one clock check. */
    CLOCK_SKEW(SyncOutcome.FAILED),

    /** The content signature did not verify under the x5u leaf, or the payload has no canonical form (§7.1). */
    SIGNATURE_INVALID(SyncOutcome.FAILED),

    /** A verified changeset's records fail the collection schema (§7.1). */
    SCHEMA_REJECTED(SyncOutcome.FAILED),

    /**
     * The generation's records do not build an index: not exactly one full filter, two attachments that map to one
     * name, or a built index over its cap (§3.2, §6.5).
     */
    INDEX_INCONSISTENT(SyncOutcome.FAILED),

    /** The attachment base: the server root does not read, or its `capabilities.attachments.base_url` is refused (§7.1). */
    ATTACHMENT_BASE(SyncOutcome.FAILED),

    /** A signed record declares an attachment above `MAX_FILTER_BYTES`; refused before any body fetch (§5.1). */
    ATTACHMENT_OVER_CAP(SyncOutcome.FAILED),

    /** An attachment fetch: as [CHANGESET_FETCH], for a body. */
    ATTACHMENT_FETCH(SyncOutcome.FAILED),

    /** An attachment's size or SHA-256 is not its signed record's. */
    ATTACHMENT_MISMATCH(SyncOutcome.FAILED),

    /** A placed filter does not decode (§6.3). */
    FILTER_UNREADABLE(SyncOutcome.FAILED),

    /** A placed filter is in an encoding the revocation engine does not list (§3.2). */
    FORMAT_UNSUPPORTED(SyncOutcome.FAILED),

    /** The revocation engine's `prepare` or `activate` threw (§6.5). */
    ENGINE_FAILED(SyncOutcome.FAILED),

    /** A store read, write or pointer flip failed, or the store holds a directory that cannot be this generation (§6.5). */
    STORE_FAILED(SyncOutcome.FAILED),

    /** Any other throwable the sync caught, an `OutOfMemoryError` included (§6.5: "every loader task catches `Throwable`"). */
    INTERNAL_ERROR(SyncOutcome.FAILED),
}
