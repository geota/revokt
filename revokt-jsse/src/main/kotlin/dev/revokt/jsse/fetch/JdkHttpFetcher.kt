// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// The public FQN is dev.revokt.jsse.JdkHttpFetcher (detekt.yml), and the file sits under fetch/ so that the
// protected path **/fetch/** covers it (CONTRIBUTING §5).
@file:Suppress("InvalidPackageDeclaration")

package dev.revokt.jsse

import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.jsse.fetch.EndpointIdentifyingSocketFactory
import dev.revokt.jsse.fetch.JdkOnly
import dev.revokt.jsse.fetch.ProxyOnlyAuthenticator
import dev.revokt.jsse.fetch.decodedBody
import dev.revokt.jsse.fetch.throwIfInterrupted
import java.io.IOException
import java.net.URI
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

/**
 * The default [HttpFetcher] on the JVM (spec §3 module table, §4 `http`): one `HttpsURLConnection` per fetch, over the
 * platform's default TLS, never used on Android.
 *
 * - **TLS:** every handshake uses `HttpsURLConnection.getDefaultSSLSocketFactory()`, read at each fetch, and so the
 *   platform's trust manager; revokt adds no trust policy (§3 `HttpFetcher`, §5.1 "Fetches run no revokt trust
 *   manager"). Hostname verification is the JDK's endpoint identification (`"HTTPS"`), set on every socket, so a
 *   consumer's global `HttpsURLConnection.setDefaultHostnameVerifier` cannot turn it off.
 * - **Proxy:** `ProxySelector.getDefault()`; revokt configures none. A per-connection authenticator answers
 *   `RequestorType.PROXY` from `Authenticator.getDefault()` and never answers a server, so a 401 never reaches the
 *   JVM's default credentials. Basic auth to an HTTPS tunnel stays disabled by the JDK unless
 *   `jdk.http.auth.tunneling.disabledSchemes` is cleared; proxy-authenticated fleets use the OkHttp fetcher.
 * - **Responses:** a 3xx, 401 or 407 is returned unfollowed and unanswered, with its status (the engine's `FAILED`).
 *   No response cache is consulted. The fetcher sends `Accept-Encoding: gzip`, whatever the request's headers say, and
 *   inflates a gzip body; a body longer than [FetchRequest.maxBodyBytes], after inflating, throws before more than
 *   that is buffered. Any other `Content-Encoding` throws.
 * - **Time and interruption:** [FetchRequest.timeoutMillis] is the connect and the read timeout; the engine's
 *   `Future.get` stays the bound. An interrupt seen before connecting or between body reads disconnects and throws
 *   `InterruptedIOException`, the interrupt flag left set; a read blocked in the socket ends at the read timeout.
 *
 * Residuals the JDK gives no per-connection switch for: a default `CookieHandler` sees these requests, and the JDK's
 * transparent Negotiate or NTLM can answer a 401 from OS or JAAS credentials without asking any authenticator.
 */
public class JdkHttpFetcher internal constructor(
    private val socketFactory: () -> SSLSocketFactory,
) : HttpFetcher {
    /** A fetcher over the platform's default TLS. */
    public constructor() : this(HttpsURLConnection::getDefaultSSLSocketFactory)

    override fun fetch(request: FetchRequest): FetchResponse {
        val url = URI(request.url)
        // The fetcher is HTTPS only: an http URL would open a plain HttpURLConnection.
        if (!"https".equals(
                url.scheme,
                ignoreCase = true,
            )
        ) {
            throw IOException("JdkHttpFetcher fetches https only, got ${url.scheme}")
        }
        throwIfInterrupted()
        val connection = url.toURL().openConnection() as HttpsURLConnection
        try {
            connection.configure(request)
            val status = connection.responseCode
            // -1: the response was not valid HTTP.
            if (status < HTTP_CONTINUE) throw IOException("no valid HTTP status from ${request.url}")
            throwIfInterrupted()
            // getInputStream throws for a 4xx or 5xx; the error stream is null when there is no body.
            val stream = if (status >= HTTP_BAD_REQUEST) connection.errorStream else connection.inputStream
            val (body, headers) = decodedBody(stream, connection.headerFields, request.maxBodyBytes)
            return FetchResponse.of(status, headers, body)
        } finally {
            // Always drops the socket: no connection outlives its fetch (a body over the cap is never drained, and the
            // JDK's keep-alive cache matches a pooled connection by socket factory identity, which is per fetch here).
            connection.disconnect()
        }
    }

    @JdkOnly
    private fun HttpsURLConnection.configure(request: FetchRequest) {
        sslSocketFactory = EndpointIdentifyingSocketFactory(socketFactory())
        instanceFollowRedirects = false
        useCaches = false
        setAuthenticator(ProxyOnlyAuthenticator)
        val timeout = request.timeoutMillis.coerceIn(1L, Int.MAX_VALUE.toLong()).toInt()
        connectTimeout = timeout
        readTimeout = timeout
        for ((name, value) in request.headers) setRequestProperty(name, value)
        setRequestProperty("Accept-Encoding", "gzip")
    }
}

private const val HTTP_CONTINUE = 100
private const val HTTP_BAD_REQUEST = 400
