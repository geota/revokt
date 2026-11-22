// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The platform's [delegate], refusing any socket that is not an `SSLSocket`. A handshake runs on the delegate's sockets,
 * its trust manager and nothing else (spec §3 `HttpFetcher`). It leaves each socket's endpoint identification as the
 * delegate made it: unset, `HttpsURLConnection` then checks the host against the session's peer certificate after
 * every handshake, full or resumed, on any provider (see [RefusingHostnameVerifier]). One instance per fetch, so the
 * JDK's keep-alive cache, which matches a pooled connection by socket factory identity, never hands this fetch a
 * connection another made.
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
        return socket
    }
}
