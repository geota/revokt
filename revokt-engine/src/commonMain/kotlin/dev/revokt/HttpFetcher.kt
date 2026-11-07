// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The transport seam every fetching source fetches through (spec §3). Synchronous: the engine calls [fetch] on its I/O
 * dispatcher, never the loader, and enforces [FetchRequest.timeoutMillis] itself, so an implementation must honour
 * thread interruption. The body is handed to the loader, which alone writes the store. Any `Throwable` from [fetch] is
 * a `FAILED` sync. Redirects are never followed; a 304 is `UNCHANGED`. A 401 or 407 is `FAILED` on every platform, and
 * no fetcher ever answers a challenge.
 */
public fun interface HttpFetcher {
    /** Fetches [request] and returns the whole decoded body, stopping with a throw past [FetchRequest.maxBodyBytes]. */
    public fun fetch(request: FetchRequest): FetchResponse

    /**
     * Creates one [HttpFetcher] per configured source, called once per source when the `Revokt` is built; a throw
     * propagates from that build. The contract (spec §3, §8 fetcher policy): every TLS handshake the returned fetcher
     * performs goes through the given [FetcherTls] and nothing else, and one call serves one source only. The shipped
     * factories are the supported ones.
     */
    public fun interface Factory {
        public fun create(tls: FetcherTls): HttpFetcher
    }
}
