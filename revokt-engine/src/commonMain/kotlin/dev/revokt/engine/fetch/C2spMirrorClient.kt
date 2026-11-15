// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import dev.revokt.SyncStage
import kotlinx.coroutines.CoroutineDispatcher
import okio.ByteString
import kotlin.time.TimeSource

/**
 * The C2SP mirror client of spec §7.3 for one [source], over the §3 fetch seam: `upki fetch`'s protocol (v1.0.1). It
 * fetches `manifest.json` and the mirror files, each from [C2spMirrorSource.baseUrl] followed by its name, and nothing
 * else; the sync ([dev.revokt.engine.update.MirrorSync]) checks and installs what it returns.
 *
 * - [fetcher] is wrapped in the one shared [RedirectingFetcher] (§7.3 "Redirects", #192), so a 301, 302, 303, 307 or
 *   308 is followed under its per-hop rules and its refusal ([RedirectRefused]) is `FAILED` at the stage of the fetch.
 *   Every request is a `GET`.
 * - Every request carries `User-Agent`; only the manifest request carries `If-Modified-Since`, and only when the sync
 *   passes one (the time the live `MIRROR` generation's manifest was stored), as an IMF-fixdate ([ImfFixdate]). A 304
 *   is [ClientResult.Unchanged] only for that request; a 304 to any other request (a file, or a manifest request
 *   without `If-Modified-Since`) is `FAILED`, as is every status but 200, so a 300, a 305, any other unfollowed 3xx,
 *   and a 3xx without `Location` fail on their status (#204's review notes on #194).
 * - Every fetch runs on [io] under [FetchLimits.fetchTimeoutMillis] ([fetchWithin]), which is also the one deadline
 *   [RedirectingFetcher] holds the whole redirect chain to (`FETCH_TIMEOUT`, 30 s, upki's too), and its body is
 *   re-checked against the request's cap: `MAX_JSON_BYTES` for the manifest, the declared size for a file, whose
 *   size and SHA-256 must then equal the manifest's.
 *
 * [limits] and [maxManifestEntries] (`MAX_MANIFEST_ENTRIES`) are the caps, overridable upward only, as the builder's
 * `limits { }` is (§4). Every result is a [ClientResult], never a throw: a fetcher's throwable is `FAILED` with it as the cause (§3).
 * `Backoff` and `Retry-After` are not read: §7.1's rule is Remote Settings', and upki reads neither.
 */
@OptIn(RevoktTestingApi::class) // FetchRequest has no constructor but its Builder.
internal class C2spMirrorClient(
    val source: C2spMirrorSource,
    fetcher: HttpFetcher,
    private val io: CoroutineDispatcher,
    val limits: FetchLimits = FetchLimits(),
    val maxManifestEntries: Int = RevoktLimits.MAX_MANIFEST_ENTRIES,
    timeSource: TimeSource = TimeSource.Monotonic,
) {
    init {
        require(maxManifestEntries >= RevoktLimits.MAX_MANIFEST_ENTRIES) {
            "maxManifestEntries below MAX_MANIFEST_ENTRIES: $maxManifestEntries"
        }
    }

    private val fetcher: HttpFetcher = RedirectingFetcher(fetcher, timeSource)

    /**
     * The manifest's bytes, unparsed, under `MAX_JSON_BYTES`, sent with `If-Modified-Since` at [ifModifiedSinceMillis]
     * when it is set and an IMF-fixdate can carry it (1970 to 9999); a 304 to it is [ClientResult.Unchanged]. Stage
     * `CHANGESET`, the stage of a feed's index fetch.
     */
    fun fetchManifest(ifModifiedSinceMillis: Long?): ClientResult<ByteString> {
        val since = ifModifiedSinceMillis?.let(ImfFixdate::format)
        return when (val exchange = exchange(SyncStage.CHANGESET, source.manifestUrl, limits.maxJsonBytes, since)) {
            is Exchange.Ended -> exchange.result
            is Exchange.Body -> ClientResult.Ok(exchange.bytes, exchange.status, null)
        }
    }

    /**
     * [file]'s body from `<base><filename>`, capped at its declared size; a declared size above `MAX_FILTER_BYTES` is
     * `FAILED` before any fetch (`CAP_NEAR_LIMIT`). The body's size and SHA-256 must equal the manifest's. Stage
     * `ATTACHMENT`.
     */
    fun fetchFile(file: MirrorFile): ClientResult<ByteString> {
        if (file.size > limits.maxFilterBytes) {
            return ClientResult.Failed(
                SyncStage.ATTACHMENT,
                ClientFailure.ATTACHMENT_OVER_CAP,
                "${file.filename}: ${file.size} bytes declared, cap ${limits.maxFilterBytes}",
            )
        }
        val body =
            when (
                val exchange =
                    exchange(SyncStage.ATTACHMENT, source.fileUrl(file.filename), file.size, ifModifiedSince = null)
            ) {
                is Exchange.Ended -> return exchange.result
                is Exchange.Body -> exchange
            }
        if (body.bytes.size.toLong() != file.size) {
            return body.failed(
                ClientFailure.ATTACHMENT_SIZE,
                "${file.filename}: ${body.bytes.size} bytes, manifest size ${file.size}",
            )
        }
        if (body.bytes.sha256() != file.sha256) {
            return body.failed(ClientFailure.ATTACHMENT_HASH, "${file.filename}: SHA-256 differs from the manifest's")
        }
        return ClientResult.Ok(body.bytes, body.status, null)
    }

    private sealed class Exchange {
        /** A 200 whose body is within the request's cap. */
        class Body(
            val bytes: ByteString,
            val status: Int,
        ) : Exchange() {
            fun failed(
                failure: ClientFailure,
                detail: String,
            ): ClientResult.Failed = ClientResult.Failed(SyncStage.ATTACHMENT, failure, detail, status)
        }

        class Ended(
            val result: ClientResult<Nothing>,
        ) : Exchange()
    }

    /**
     * One `GET` of [url] under [maxBodyBytes], through the redirect wrapper; [ifModifiedSince] makes it conditional.
     * Header values are checked before the fetch: a CR or LF is `FAILED`, never sanitised (#177).
     */
    private fun exchange(
        stage: SyncStage,
        url: String,
        maxBodyBytes: Long,
        ifModifiedSince: String?,
    ): Exchange {
        val request =
            FetchRequest
                .Builder()
                .url(url)
                .header("User-Agent", source.userAgent)
                .apply { if (ifModifiedSince != null) header("If-Modified-Since", ifModifiedSince) }
                .maxBodyBytes(maxBodyBytes)
                .timeoutMillis(limits.fetchTimeoutMillis)
                .build()
        for ((name, value) in request.headers) {
            if ('\r' in value || '\n' in value) {
                return end(ClientResult.Failed(stage, ClientFailure.HEADER_VALUE, "$name holds a CR or LF"))
            }
        }
        val response =
            when (val fetched = fetch(stage, request)) {
                is Fetched.Response -> fetched.response
                is Fetched.Failed -> return end(fetched.result)
            }
        return checked(stage, response, maxBodyBytes, conditional = ifModifiedSince != null)
    }

    private sealed class Fetched {
        class Response(
            val response: FetchResponse,
        ) : Fetched()

        class Failed(
            val result: ClientResult.Failed,
        ) : Fetched()
    }

    /** [request] through the redirect wrapper on [io], under its deadline; a throw, a null or a timeout is `FAILED`. */
    private fun fetch(
        stage: SyncStage,
        request: FetchRequest,
    ): Fetched =
        when (val timed = fetchWithin(io, request.timeoutMillis) { fetcher.fetch(request) }) {
            is Timed.Done -> {
                timed.response?.let { Fetched.Response(it) }
                    ?: Fetched.Failed(
                        ClientResult.Failed(stage, ClientFailure.FETCHER_THREW, "the fetcher returned null"),
                    )
            }

            is Timed.Threw -> {
                val cause = timed.cause
                val refused = (cause as? RedirectRefused)?.let { "the redirect chain was refused: ${it.message}" }
                Fetched.Failed(
                    ClientResult.Failed(
                        stage,
                        ClientFailure.FETCHER_THREW,
                        refused ?: "the fetcher threw",
                        cause = cause,
                    ),
                )
            }

            Timed.TimedOut -> {
                val detail = "no response within ${request.timeoutMillis} ms"
                Fetched.Failed(ClientResult.Failed(stage, ClientFailure.TIMEOUT, detail))
            }
        }

    /**
     * The final [response]'s status and body cap: a 304 is [ClientResult.Unchanged] only for a [conditional] request,
     * any other status but 200 is `FAILED` with it, and a body over [maxBodyBytes] is `FAILED` whatever the fetcher did.
     */
    private fun checked(
        stage: SyncStage,
        response: FetchResponse,
        maxBodyBytes: Long,
        conditional: Boolean,
    ): Exchange {
        val status = response.status
        if (status == ClientResult.NOT_MODIFIED && conditional) return end(ClientResult.Unchanged(null))
        if (status == ClientResult.NOT_MODIFIED) {
            return end(ClientResult.Failed(stage, ClientFailure.HTTP_STATUS, "304 to an unconditional request", status))
        }
        if (status != ClientResult.OK) {
            return end(ClientResult.Failed(stage, ClientFailure.HTTP_STATUS, "status $status", status))
        }
        val bytes = response.bodyBytes
        if (bytes.size > maxBodyBytes) {
            val detail = "${bytes.size} bytes, cap $maxBodyBytes"
            return end(ClientResult.Failed(stage, ClientFailure.BODY_TOO_LARGE, detail, status))
        }
        return Exchange.Body(bytes, status)
    }

    private fun end(result: ClientResult<Nothing>): Exchange = Exchange.Ended(result)
}
