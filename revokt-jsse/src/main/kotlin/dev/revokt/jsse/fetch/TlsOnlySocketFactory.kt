// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The platform's [delegate], refusing, with an `SSLException` that closes the socket, any socket that is not an
 * `SSLSocket` or that already carries an endpoint identification algorithm. A handshake runs on the delegate's sockets,
 * its trust manager and nothing else (spec §3 `HttpFetcher`). With the algorithm unset, `HttpsURLConnection` checks the
 * host against the session's peer certificate after every handshake, full or resumed (see [RefusingHostnameVerifier]);
 * with it preset, `HttpsURLConnection` would skip that check and leave the name to the provider, which may resume a
 * session a laxer connection cached without checking it (Conscrypt does), so such a socket fails the fetch. Clearing
 * the algorithm is no remedy: SunJSSE ignores a null one. One instance per fetch, so the JDK's keep-alive cache, which
 * matches a pooled connection by socket factory identity, never hands this fetch a connection another made.
 */
internal class TlsOnlySocketFactory(
    private val delegate: SSLSocketFactory,
) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createSocket(): Socket = identify(delegate.createSocket())

    override fun createSocket(
        s: Socket,
        host: String,
        port: Int,
        autoClose: Boolean,
    ): Socket = identify(delegate.createSocket(s, host, port, autoClose))

    override fun createSocket(
        host: String,
        port: Int,
    ): Socket = identify(delegate.createSocket(host, port))

    override fun createSocket(
        host: String,
        port: Int,
        localHost: InetAddress,
        localPort: Int,
    ): Socket = identify(delegate.createSocket(host, port, localHost, localPort))

    override fun createSocket(
        host: InetAddress,
        port: Int,
    ): Socket = identify(delegate.createSocket(host, port))

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress,
        localPort: Int,
    ): Socket = identify(delegate.createSocket(address, port, localAddress, localPort))

    private fun identify(socket: Socket): Socket {
        // A factory that makes a plain socket would carry the request in clear: refuse it.
        if (socket !is SSLSocket) {
            socket.close()
            throw SSLException("the default SSLSocketFactory made a socket that is not an SSLSocket")
        }
        val preset = socket.sslParameters.endpointIdentificationAlgorithm
        if (!preset.isNullOrEmpty()) {
            socket.close()
            throw SSLException(
                "the default SSLSocketFactory presets endpoint identification ($preset), which would skip " +
                    "HttpsURLConnection's host check on every handshake",
            )
        }
        return socket
    }
}
