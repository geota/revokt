// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.SignatureVerifier
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.parse.X5uPem
import dev.revokt.engine.parse.X5uPemRead
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.engine.verify.X5uChainResult
import dev.revokt.engine.verify.X5uPath
import dev.revokt.engine.verify.X5uValidity
import dev.revokt.engine.verify.checkValidity
import dev.revokt.engine.verify.validateX5uChain
import okio.ByteString

/** Why a changeset's signature did not verify (spec §7.1); [ChangesetVerification.Failed.stage] says where. */
internal enum class SignatureFailure {
    /** `metadata.signatures` is absent, not an array, or empty. */
    NO_SIGNATURES,

    /** Every entry was skipped: none has a non-empty `signature`, a non-empty `x5u` and a `mode` absent or `p384ecdsa`. */
    NONE_TRIED,

    /** An element reached in the loop is JSON `null`, which Firefox's `const { x5u, signature, mode } = sig` throws on. */
    NULL_ENTRY,

    /** The x5u fetch failed ([ChangesetVerification.Failed.clientFailure] says how), at stage `X5U`. */
    X5U_FETCH,

    /** The x5u body is not a PEM chain as [X5uPem] reads it. */
    X5U_PEM,

    /** The x5u chain failed a check of [validateX5uChain]. */
    X5U_CHAIN,

    /** A link of the x5u path is outside its validity window at the local clock: `CLOCK_SKEW`, stage `X5U`. */
    X5U_VALIDITY,

    /** The content signature did not verify under the x5u leaf ([ContentSignature]). */
    CONTENT_SIGNATURE,
}

/**
 * What [ChangesetVerifier.verify] found. [backoffMillis] is the longest `Backoff` or `Retry-After` of the x5u fetches
 * this call made, a failed entry's included; an x5u reused from an earlier call of the same verifier is not fetched, so
 * its `Backoff` was reported by that call and is not reported again.
 */
internal sealed class ChangesetVerification {
    abstract val backoffMillis: Long?

    /**
     * The entry at [index] of `metadata.signatures` verified over exactly [records] at [timestamp], so these are what
     * the sync installs (the payload's record set, never the changeset's `changes` for a `_since` changeset). [x5uBody]
     * is the entry's x5u body as served and [path] the validated path, so a seed stores [entry]'s `signature` and
     * [x5uBody] as `x5u.pem` (spec §6.5).
     */
    class Verified(
        val index: Int,
        val entry: SignatureEntry,
        val records: List<JsonObject>,
        val timestamp: Long,
        val x5uBody: ByteString,
        val path: X5uPath,
        override val backoffMillis: Long?,
    ) : ChangesetVerification() {
        /** This result with [backoff] as the verification's backoff. */
        fun of(backoff: Long?): Verified = Verified(index, entry, records, timestamp, x5uBody, path, backoff)
    }

    /**
     * Nothing verified: a [SyncOutcome.FAILED] or [SyncOutcome.CLOCK_SKEW] sync at [stage]. For a failure of a tried
     * entry, [index] is the last tried entry's (spec §7.1: its failure is the outcome) and, for [SignatureFailure.X5U_FETCH],
     * [clientFailure], [httpStatus] and [cause] are the fetch's; null otherwise.
     */
    class Failed(
        val outcome: SyncOutcome,
        val stage: SyncStage,
        val failure: SignatureFailure,
        val detail: String,
        val index: Int? = null,
        val clientFailure: ClientFailure? = null,
        val httpStatus: Int? = null,
        val cause: Throwable? = null,
        override val backoffMillis: Long? = null,
    ) : ChangesetVerification() {
        /** This failure as entry [index]'s, with [backoff] as the verification's backoff. */
        fun of(
            index: Int?,
            backoff: Long?,
        ): Failed = Failed(outcome, stage, failure, detail, index, clientFailure, httpStatus, cause, backoff)

        override fun toString(): String = "Failed($outcome, $stage, $failure at ${index ?: "-"}: $detail)"
    }
}

/**
 * The changeset signature check of spec §7.1 (revision 56, read as Firefox's `RemoteSettingsClient.sys.mjs` at
 * `cac25a6` reads `metadata.signatures`, lines 1097 to 1132), for one sync: build one per sync and call [verify] for
 * each changeset it fetches. The sync's caller (#137) does everything around it.
 *
 * - **The entries.** An empty `metadata.signatures` is [SignatureFailure.NO_SIGNATURES], before anything is fetched.
 *   The first [MAX_SIGNATURES] entries are tried in array order, and any after them are never read (Firefox tries
 *   every entry; the cap bounds the x5u fetches a changeset can cause). One with no `signature` or `x5u`, an empty one included (Firefox's `!x5u ||
 *   !signature`), or a `mode` present and other than `p384ecdsa` (Firefox's `mode && mode !== "p384ecdsa"`; a
 *   non-string or `""` mode is skipped too, where Firefox tries a falsy one), is skipped;
 *   when every one is, [SignatureFailure.NONE_TRIED]. A JSON `null` element reached in the loop is
 *   [SignatureFailure.NULL_ENTRY], as Firefox's destructuring throws on it. These are `FAILED` at stage `SIGNATURE`.
 * - **One entry.** Its `x5u` is fetched through [client] (the §7.1 URL rules, the rewrite and `MAX_X5U_BYTES` are
 *   its), read as PEM, validated under the client's source's pinned roots ([validateX5uChain]; taken from the source
 *   that served the changeset, so one source's changeset is never checked under another's pins) and checked at
 *   [nowMillis] ([checkValidity]);
 *   then its `signature` is verified over the records under the leaf ([ContentSignature.verifyRecords]). The first
 *   entry that verifies is accepted.
 * - **One x5u result per URL per sync.** An `x5u` URL (as served, exactly: before the rewrite, `:443` and case kept) is
 *   fetched and validated once by
 *   this verifier: a later entry naming it reuses the validated path, and one whose fetch or validation failed is not
 *   retried and fails the same way.
 * - **The failure.** When no tried entry verifies, the last tried entry's failure is the outcome (Firefox throws its
 *   first). A failed x5u fetch keeps the client's stage, `X5U`; a validity failure is `CLOCK_SKEW` at `X5U` (spec §4
 *   `SyncStage`); a PEM, chain or content-signature failure is `FAILED` at `SIGNATURE`.
 *
 * Nothing here throws but a fatal error, as in the client and the verifiers it calls.
 */
internal class ChangesetVerifier(
    private val client: RemoteSettingsClient,
    private val verifier: SignatureVerifier,
    private val nowMillis: Long,
) {
    private sealed class X5u {
        class Valid(
            val body: ByteString,
            val path: X5uPath,
        ) : X5u()

        class Invalid(
            val failure: ChangesetVerification.Failed,
        ) : X5u()
    }

    private val x5us = HashMap<String, X5u>()

    /**
     * Verifies [changeset]'s signature over [records], the record set its payload is built from (spec §7.1: for a
     * `_since` changeset the stored records with its changes merged, [ContentSignature.merge]), at its `timestamp`.
     */
    fun verify(
        changeset: Changeset,
        records: List<JsonObject>,
    ): ChangesetVerification {
        val entries = changeset.signatures
        if (entries.isEmpty()) {
            return failed(SignatureFailure.NO_SIGNATURES, "metadata.signatures is absent, not an array or empty")
        }
        var backoff: Long? = null
        var last: ChangesetVerification.Failed? = null
        for ((index, entry) in entries.take(MAX_SIGNATURES).withIndex()) {
            if (entry == null) {
                return failed(SignatureFailure.NULL_ENTRY, "metadata.signatures[$index] is null").of(index, backoff)
            }
            val signature = entry.signature
            val url = entry.x5u
            if (signature.isNullOrEmpty() || url.isNullOrEmpty() || !entry.modeSupported) continue
            val x5u =
                x5us.getOrPut(url) {
                    val (fetched, fetchBackoff) = fetch(url)
                    backoff = longest(backoff, fetchBackoff)
                    fetched
                }
            when (val tried = attempt(index, entry, signature, x5u, changeset.timestamp, records)) {
                is ChangesetVerification.Verified -> return tried.of(backoff)
                is ChangesetVerification.Failed -> last = tried
            }
        }
        return last?.of(last.index, backoff)
            ?: failed(
                SignatureFailure.NONE_TRIED,
                "no entry has a signature, an x5u and no mode or ${ContentSignature.MODE}",
            )
    }

    /** One tried entry: [signature] over [records] at [timestamp] under [x5u]'s leaf, or [x5u]'s own failure. */
    private fun attempt(
        index: Int,
        entry: SignatureEntry,
        signature: String,
        x5u: X5u,
        timestamp: Long,
        records: List<JsonObject>,
    ): ChangesetVerification {
        val path =
            when (x5u) {
                is X5u.Invalid -> return x5u.failure.of(index, null)
                is X5u.Valid -> x5u.path
            }
        // The entry's mode is absent or p384ecdsa ([SignatureEntry.modeSupported]), the one algorithm verified.
        val checked =
            ContentSignature.verifyRecords(
                verifier,
                records,
                timestamp,
                signature,
                ContentSignature.MODE,
                path.leafSpki,
            )
        if (checked.verified) {
            return ChangesetVerification.Verified(index, entry, records, timestamp, x5u.body, path, null)
        }
        val error = checked.verifierError?.let { ", $it" } ?: ""
        return failed(SignatureFailure.CONTENT_SIGNATURE, "${checked.failure}$error").of(index, null)
    }

    /** The x5u at [url], fetched, read as PEM, validated and checked at [nowMillis]; with the fetch's backoff. */
    private fun fetch(url: String): Pair<X5u, Long?> =
        when (val fetched = client.fetchX5u(url)) {
            is ClientResult.Ok -> {
                validated(fetched.value) to fetched.backoffMillis
            }

            is ClientResult.Failed -> {
                val failure =
                    ChangesetVerification.Failed(
                        SyncOutcome.FAILED,
                        fetched.stage,
                        SignatureFailure.X5U_FETCH,
                        "${fetched.failure}: ${fetched.detail}",
                        clientFailure = fetched.failure,
                        httpStatus = fetched.httpStatus,
                        cause = fetched.cause,
                    )
                X5u.Invalid(failure) to fetched.backoffMillis
            }

            // The x5u fetch is unconditional, so the client answers a 304 with HTTP_STATUS and this is not reached.
            is ClientResult.Unchanged -> {
                val failure =
                    ChangesetVerification.Failed(
                        SyncOutcome.FAILED,
                        SyncStage.X5U,
                        SignatureFailure.X5U_FETCH,
                        "304 to an unconditional x5u fetch",
                        clientFailure = ClientFailure.HTTP_STATUS,
                        httpStatus = fetched.httpStatus,
                    )
                X5u.Invalid(failure) to fetched.backoffMillis
            }
        }

    private fun validated(body: ByteString): X5u {
        val ders =
            when (val read = X5uPem.read(body.toByteArray(), client.limits.maxX5uBytes)) {
                is X5uPemRead.Certificates -> read.ders
                is X5uPemRead.Failed -> return invalid(SignatureFailure.X5U_PEM, "${read.reason}: ${read.detail}")
            }
        val path =
            when (val chain = validateX5uChain(ders, client.source.pinnedRootSpkis, verifier)) {
                is X5uChainResult.Valid -> chain.path
                is X5uChainResult.Failed -> return invalid(SignatureFailure.X5U_CHAIN, chain.toString())
            }
        return when (val validity = checkValidity(path, nowMillis)) {
            is X5uValidity.Valid -> {
                X5u.Valid(body, path)
            }

            is X5uValidity.ClockSkew -> {
                val failure =
                    ChangesetVerification.Failed(
                        SyncOutcome.CLOCK_SKEW,
                        SyncStage.X5U,
                        SignatureFailure.X5U_VALIDITY,
                        "link ${validity.certIndex}: ${validity.detail}",
                    )
                X5u.Invalid(failure)
            }
        }
    }

    internal companion object {
        /** The most `metadata.signatures` entries tried, the first in array order; later ones are ignored (spec §7.1). */
        const val MAX_SIGNATURES = 4

        /** `FAILED` at stage `SIGNATURE`. */
        private fun failed(
            failure: SignatureFailure,
            detail: String,
        ): ChangesetVerification.Failed =
            ChangesetVerification.Failed(SyncOutcome.FAILED, SyncStage.SIGNATURE, failure, detail)

        private fun invalid(
            failure: SignatureFailure,
            detail: String,
        ): X5u = X5u.Invalid(failed(failure, detail))

        private fun longest(
            a: Long?,
            b: Long?,
        ): Long? =
            if (a == null) {
                b
            } else if (b == null) {
                a
            } else {
                maxOf(a, b)
            }
    }
}
