// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The platform's [delegate], with endpoint identification `"HTTPS"` set on every socket it makes (spec §3: hostname
 * verification is HttpsURLConnection's endpoint identification). With the algorithm already set, `HttpsURLConnection`
 * neither replaces it nor consults a hostname verifier, so the check holds whatever
 * `HttpsURLConnection.setDefaultHostnameVerifier` was given. A handshake still runs on the delegate's sockets, its
 * trust manager and nothing else.
 */
internal class EndpointIdentifyingSocketFactory(
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
        val tls =
            socket as? SSLSocket ?: run {
                socket.close()
                throw SSLException("the default SSLSocketFactory made a socket that is not an SSLSocket")
            }
        val parameters = tls.sslParameters
        parameters.endpointIdentificationAlgorithm = "HTTPS"
        tls.sslParameters = parameters
        return tls
    }
}
