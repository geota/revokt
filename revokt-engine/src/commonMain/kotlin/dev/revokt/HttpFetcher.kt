// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The transport seam every fetching source fetches through (spec §3), supplied by the consumer and handshaking with the
 * platform's TLS and trust manager: revokt adds no trust policy of its own to the fetch. Synchronous: the engine calls
 * [fetch] on its I/O dispatcher, never the loader, and enforces [FetchRequest.timeoutMillis] itself, so an
 * implementation must honour thread interruption. The body is handed to the loader, which alone writes the store. Any
 * `Throwable` from [fetch] is a `FAILED` sync. Redirects are never followed; a 304 is `UNCHANGED`. A 401 or 407 is
 * `FAILED` on every platform, and no fetcher ever answers a challenge.
 */
public fun interface HttpFetcher {
    /** Fetches [request] and returns the whole decoded body, stopping with a throw past [FetchRequest.maxBodyBytes]. */
    public fun fetch(request: FetchRequest): FetchResponse
}
