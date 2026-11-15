// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.RevoktTestingApi
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource

/** Why [RedirectingFetcher] refused a chain; each is `SyncOutcome.FAILED` at the stage of the fetch (spec §7.3). */
internal enum class RedirectFailure {
    /** The request's URL, or a hop's resolved `Location`, breaks a hop rule ([StrictUrlFailure] in the detail). */
    URL,

    /** A redirect response carries more than one distinct `Location` value. */
    LOCATION_CONFLICT,

    /** An eleventh redirect: at most [RedirectingFetcher.MAX_HOPS] are followed. */
    TOO_MANY_HOPS,

    /** A hop's URL was already requested in the chain. */
    LOOP,

    /** The chain outlasted the request's `timeoutMillis`, one deadline for every hop. */
    DEADLINE,
}

/** A chain [RedirectingFetcher] refused: [failure], with [detail]. Thrown from [HttpFetcher.fetch], so it is `FAILED`. */
internal class RedirectRefused(
    val failure: RedirectFailure,
    val detail: String,
) : Exception() {
    override val message: String get() = "$failure: $detail"
}

/**
 * The one shared redirect follower of spec §7.3 ("Redirects", revision 56, the maintainer's decision; #192): wraps a
 * C2SP mirror source's [HttpFetcher], which never follows a redirect itself (§3), and follows a 301, 302, 303, 307 or
 * 308 under the per-hop rules. Remote Settings is never wrapped (§7.1: a 3xx there is `FAILED`).
 *
 * - Every hop is a new request through [fetcher], so it goes through the source's `FetcherTls` and the §8 host checks.
 * - Every URL in the chain, the request's own included, is read by [HopUrl] (the strict grammar shared with the x5u
 *   URL, [StrictUrl]): `https`, no userinfo, a DNS host name or an IP literal, a query allowed, a fragment dropped,
 *   and no port rule (the `c2spMirror` URL's own rule, §4). Each hop is sent as [HopUrl] re-serialised it, never as
 *   the `Location` string.
 * - A relative `Location` resolves against the URL of the request it answered (RFC 3986 §5.2). Distinct `Location`
 *   values on one response refuse the chain, as Firefox's Necko does; a redirect with no `Location` is returned as the
 *   final response, as reqwest and Necko do, and its caller fails it on its status.
 * - Every mirror request is a `GET` ([FetchRequest] has no method), so each of the five statuses is followed as one;
 *   any other status, another 3xx included (a 300, 304 or 305), is returned as the final response.
 * - At most [MAX_HOPS] redirects: an eleventh is refused, and so is a hop to a URL already requested in the chain.
 * - The request's `timeoutMillis` is one deadline for the whole chain, as upki's client timeout is: each hop is sent
 *   with the time left, and a response that arrives at or after the deadline refuses the chain. The caller still runs
 *   [fetch] under one `fetchWithin(timeoutMillis)`, which interrupts a hop that outlives it.
 * - A hop to another host or port drops [CREDENTIAL_HEADERS] (compared ignoring case) from that hop and every later
 *   one, as reqwest 0.13.0's `remove_sensitive_headers` does; every other header is sent on every hop unchanged.
 * - Every hop carries the request's `maxBodyBytes`, so the body cap applies to the final response, which is returned
 *   as [fetcher] gave it; the caller re-checks it (§3).
 *
 * A refused chain throws [RedirectRefused]; a throw from [fetcher] propagates.
 */
@OptIn(RevoktTestingApi::class) // FetchRequest.newBuilder: a hop is the request with another URL, headers and deadline.
internal class RedirectingFetcher(
    private val fetcher: HttpFetcher,
    private val timeSource: TimeSource = TimeSource.Monotonic,
) : HttpFetcher {
    override fun fetch(request: FetchRequest): FetchResponse {
        val start = timeSource.markNow()
        val deadline = request.timeoutMillis.milliseconds
        var url = hopUrl(request.url) { HopUrl.parse(request.url) }
        val seen = mutableSetOf(url)
        var hop = request
        var hops = 0
        while (true) {
            val response = fetcher.fetch(hop)
            val elapsed = start.elapsedNow()
            if (elapsed >= deadline) {
                throw RedirectRefused(
                    RedirectFailure.DEADLINE,
                    "${elapsed.inWholeMilliseconds} ms after ${hops + 1} requests, deadline ${request.timeoutMillis} ms",
                )
            }
            if (response.status !in REDIRECTS) return response
            val location = location(response) ?: return response
            if (hops == MAX_HOPS) {
                throw RedirectRefused(RedirectFailure.TOO_MANY_HOPS, "a redirect after $MAX_HOPS hops")
            }
            val next = hopUrl(location) { url.resolve(location) }
            if (!seen.add(next)) throw RedirectRefused(RedirectFailure.LOOP, "$next was already requested")
            val headers =
                if (next.isCrossOrigin(url)) {
                    hop.headers.filterKeys { name -> CREDENTIAL_HEADERS.none { it.equals(name, ignoreCase = true) } }
                } else {
                    hop.headers
                }
            hop =
                hop
                    .newBuilder()
                    .url(next.toString())
                    .headers(headers)
                    .timeoutMillis((deadline - elapsed).inWholeMilliseconds.coerceAtLeast(1))
                    .build()
            url = next
            hops++
        }
    }

    /** The parsed URL, or a [RedirectFailure.URL] refusal naming [text]. */
    private inline fun hopUrl(
        text: String,
        read: () -> HopUrlRead,
    ): HopUrl =
        when (val result = read()) {
            is HopUrlRead.Parsed -> {
                result.url
            }

            is HopUrlRead.Refused -> {
                throw RedirectRefused(RedirectFailure.URL, "${result.failure}: ${result.detail}: \"$text\"")
            }
        }

    /**
     * The response's `Location`, its optional whitespace trimmed (RFC 9110 §5.5); null when it has none. Values that
     * differ refuse the chain, as Necko's `nsHttpHeaderArray` refuses a duplicate `Location` that differs; equal
     * duplicates collapse.
     */
    private fun location(response: FetchResponse): String? {
        val values = response.headerValues("Location").map { it.trim(' ', '\t') }.distinct()
        if (values.size > 1) {
            throw RedirectRefused(RedirectFailure.LOCATION_CONFLICT, "${values.size} distinct Location values")
        }
        return values.singleOrNull()
    }

    internal companion object {
        /** At most 10 redirects, reqwest's `Policy::limited(10)` (spec §7.3). */
        const val MAX_HOPS = 10

        /** The statuses followed, each answering a `GET` (spec §7.3). */
        private val REDIRECTS = setOf(301, 302, 303, 307, 308)

        /** Dropped on a hop to another host or port: reqwest 0.13.0's `remove_sensitive_headers` list (spec §7.3). */
        val CREDENTIAL_HEADERS = listOf("Authorization", "Cookie", "Cookie2", "Proxy-Authorization", "WWW-Authenticate")
    }
}
