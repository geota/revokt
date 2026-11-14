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

    /** More than [ChangesetVerifier.MAX_SIGNATURES] entries; none was tried. */
    TOO_MANY_SIGNATURES,

    /** Every entry was skipped: none has a `signature`, an `x5u` and a `mode` of `p384ecdsa`. */
    NONE_TRIED,

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

/** What [ChangesetVerifier.verify] found. [backoffMillis] is the longest `Backoff` or `Retry-After` of its x5u fetches. */
internal sealed class ChangesetVerification {
    abstract val backoffMillis: Long?

    /**
     * The entry at [index] of `metadata.signatures` verified: [x5uBody] is its x5u body as served and [path] the
     * validated path, so a seed stores this entry's `signature` and [x5uBody] as `x5u.pem` (spec §6.5).
     */
    class Verified(
        val index: Int,
        val entry: SignatureEntry,
        val x5uBody: ByteString,
        val path: X5uPath,
        override val backoffMillis: Long?,
    ) : ChangesetVerification()

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
 * - **The entries.** An empty `metadata.signatures` is [SignatureFailure.NO_SIGNATURES], and one of more than
 *   [MAX_SIGNATURES] entries is [SignatureFailure.TOO_MANY_SIGNATURES], before anything is fetched. The entries are
 *   then tried in array order. One with no `signature` or `x5u`, or a `mode` other than `p384ecdsa` (none included, a
 *   deliberate narrowing from Firefox), is skipped; when every one is, [SignatureFailure.NONE_TRIED]. These three are
 *   `FAILED` at stage `SIGNATURE`.
 * - **One entry.** Its `x5u` is fetched through [client] (the §7.1 URL rules, the rewrite and `MAX_X5U_BYTES` are
 *   its), read as PEM, validated under [pinned] ([validateX5uChain]) and checked at [nowMillis] ([checkValidity]);
 *   then its `signature` is verified over the records under the leaf ([ContentSignature.verifyRecords]). The first
 *   entry that verifies is accepted.
 * - **One x5u result per URL per sync.** An `x5u` URL (as served, before the rewrite) is fetched and validated once by
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
    private val pinned: Set<ByteString>,
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
        if (entries.size > MAX_SIGNATURES) {
            return failed(
                SignatureFailure.TOO_MANY_SIGNATURES,
                "metadata.signatures has ${entries.size} entries; at most $MAX_SIGNATURES are tried",
            )
        }
        var backoff: Long? = null
        var last: ChangesetVerification.Failed? = null
        for ((index, entry) in entries.withIndex()) {
            val signature = entry.signature
            val url = entry.x5u
            if (signature == null || url == null || entry.mode != ContentSignature.MODE) continue
            val x5u =
                x5us.getOrPut(url) {
                    val (fetched, fetchBackoff) = fetch(url)
                    backoff = longest(backoff, fetchBackoff)
                    fetched
                }
            last =
                when (x5u) {
                    is X5u.Invalid -> {
                        x5u.failure.of(index, null)
                    }

                    is X5u.Valid -> {
                        val checked =
                            ContentSignature.verifyRecords(
                                verifier,
                                records,
                                changeset.timestamp,
                                signature,
                                entry.mode,
                                x5u.path.leafSpki,
                            )
                        if (checked.verified) {
                            return ChangesetVerification.Verified(index, entry, x5u.body, x5u.path, backoff)
                        }
                        val error = checked.verifierError?.let { ", $it" } ?: ""
                        failed(SignatureFailure.CONTENT_SIGNATURE, "${checked.failure}$error").of(index, null)
                    }
                }
        }
        return last?.of(last.index, backoff)
            ?: failed(SignatureFailure.NONE_TRIED, "no entry has a signature, an x5u and mode ${ContentSignature.MODE}")
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
            when (val chain = validateX5uChain(ders, pinned, verifier)) {
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
        /** The most `metadata.signatures` entries a changeset may carry; all of them may be tried (spec §7.1). */
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
