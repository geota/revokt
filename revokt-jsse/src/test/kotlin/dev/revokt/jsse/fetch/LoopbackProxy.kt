// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.Authenticator
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PasswordAuthentication
import java.net.Proxy
import java.net.ProxySelector
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.URI
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/** The user and password [withDefaultAuthenticator] answers with, and the ones [LoopbackProxy] accepts. */
internal const val PROXY_USER = "proxy-user"
internal const val PROXY_PASSWORD = "secret"

/**
 * A loopback HTTP proxy on `127.0.0.1` that tunnels CONNECT to `127.0.0.1` only, recording every CONNECT it gets. A
 * CONNECT without a `Proxy-Authorization` that verifies as Digest for [PROXY_USER] and [PROXY_PASSWORD] (RFC 7616,
 * SHA-256 since JDK 20 and later refuse MD5, no qop) gets a 407 with a Digest challenge and the connection closed; one
 * that verifies gets a 200 and its bytes relayed both ways. Each instance has its own realm, nonce and port: the JDK
 * caches proxy credentials per authenticator, by proxy host and port, beyond one test. Closing it closes every socket
 * and so ends its threads.
 */
internal class LoopbackProxy : AutoCloseable {
    /** One recorded CONNECT: its target, its headers (names lowercased) and whether its credentials verified. */
    class Connect(
        val target: String,
        val headers: Map<String, List<String>>,
        val authorized: Boolean,
    )

    val connects: MutableList<Connect> = Collections.synchronizedList(ArrayList())

    private val serial = SERIALS.incrementAndGet()
    private val realm = "revokt-proxy-$serial"
    private val nonce = "nonce-$serial-${System.nanoTime()}"
    private val sockets = ConcurrentLinkedQueue<Socket>()
    private val server: ServerSocket = freshPort()

    val address: InetSocketAddress get() = server.localSocketAddress as InetSocketAddress

    init {
        daemon("loopback-proxy-accept") {
            while (!server.isClosed) {
                val client =
                    try {
                        server.accept()
                    } catch (_: IOException) {
                        break
                    }
                sockets.add(client)
                daemon("loopback-proxy-conn") { serve(client) }
            }
        }
    }

    override fun close() {
        server.close()
        for (socket in sockets) socket.close()
    }

    private fun serve(client: Socket) {
        client.use {
            client.soTimeout = SOCKET_TIMEOUT_MILLIS
            val head = readHead(client.getInputStream()) ?: return
            val lines = head.split("\r\n")
            val (method, target) = lines.first().split(' ').let { it[0] to it.getOrElse(1) { "" } }
            val headers =
                lines
                    .drop(1)
                    .filter { ':' in it }
                    .groupBy({ it.substringBefore(':').trim().lowercase() }, { it.substringAfter(':').trim() })
            val authorized = headers["proxy-authorization"].orEmpty().any { verifies(it, target) }
            connects.add(Connect(target, headers, authorized))
            val out = client.getOutputStream()
            val port = target.removePrefix("127.0.0.1:").toIntOrNull()
            val challenge = "Proxy-Authenticate: Digest realm=\"$realm\", nonce=\"$nonce\", algorithm=SHA-256"
            when {
                method != "CONNECT" || port == null -> out.write(status("405 Method Not Allowed"))
                !authorized -> out.write(status("407 Proxy Authentication Required", challenge))
                else -> tunnel(client, port)
            }
            out.flush()
        }
    }

    private fun tunnel(
        client: Socket,
        port: Int,
    ) {
        Socket(LOOPBACK, port).use { origin ->
            sockets.add(origin)
            origin.soTimeout = SOCKET_TIMEOUT_MILLIS
            client.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".encodeToByteArray())
            client.getOutputStream().flush()
            daemon("loopback-proxy-up") { relay(client.getInputStream(), origin) }
            relay(origin.getInputStream(), client)
        }
    }

    /** Checks a Digest answer the way RFC 7616 §3.4.1 computes it without qop: H(H(A1):nonce:H(A2)). */
    private fun verifies(
        header: String,
        target: String,
    ): Boolean {
        if (!header.startsWith("Digest ", ignoreCase = true)) return false
        val params =
            DIGEST_PARAM.findAll(header.substringAfter(' ')).associate { m ->
                m.groupValues[1].lowercase() to m.groupValues[2].ifEmpty { m.groupValues[3] }
            }
        val ha1 = sha256("$PROXY_USER:$realm:$PROXY_PASSWORD")
        val ha2 = sha256("CONNECT:$target")
        return params["username"] == PROXY_USER &&
            params["realm"] == realm &&
            params["nonce"] == nonce &&
            params["uri"] == target &&
            params["algorithm"] == "SHA-256" &&
            params["response"] == sha256("$ha1:$nonce:$ha2")
    }

    private companion object {
        const val SOCKET_TIMEOUT_MILLIS = 10_000
        const val MAX_HEAD_BYTES = 16_384
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val SERIALS = AtomicInteger()
        val DIGEST_PARAM = Regex("""(\w+)=(?:"([^"]*)"|([^,\s]*))""")

        /** Every port a proxy in this JVM has had, so no proxy meets credentials the JDK cached for an earlier one. */
        val USED_PORTS: MutableSet<Int> = ConcurrentHashMap.newKeySet()

        fun freshPort(): ServerSocket {
            while (true) {
                val socket = ServerSocket(0, 0, LOOPBACK)
                if (USED_PORTS.add(socket.localPort)) return socket
                socket.close()
            }
        }

        fun daemon(
            name: String,
            body: () -> Unit,
        ) {
            Thread {
                try {
                    body()
                } catch (_: IOException) {
                    // The peer or close() ended the connection.
                }
            }.apply {
                this.name = name
                isDaemon = true
                start()
            }
        }

        /** The request line and headers up to the blank line, read a byte at a time so nothing past them is taken. */
        fun readHead(input: InputStream): String? {
            val head = ByteArrayOutputStream()
            while (head.size() < MAX_HEAD_BYTES) {
                val b = input.read()
                if (b < 0) return null
                head.write(b)
                if (head.toString(Charsets.ISO_8859_1).endsWith("\r\n\r\n")) {
                    return head.toString(Charsets.ISO_8859_1).removeSuffix("\r\n\r\n")
                }
            }
            return null
        }

        fun relay(
            from: InputStream,
            to: Socket,
        ) {
            try {
                from.transferTo(to.getOutputStream())
            } finally {
                to.close()
            }
        }

        fun status(
            line: String,
            vararg headers: String,
        ): ByteArray =
            buildString {
                append("HTTP/1.1 ").append(line).append("\r\n")
                for (header in headers) append(header).append("\r\n")
                append("Content-Length: 0\r\nConnection: close\r\n\r\n")
            }.encodeToByteArray()

        fun sha256(text: String): String =
            MessageDigest
                .getInstance("SHA-256")
                .digest(text.encodeToByteArray())
                .joinToString("") { "%02x".format(it) }
    }
}

/** Runs [block] with [proxy] as the default `ProxySelector` for every URI, then restores the old one. */
internal fun <T> withProxy(
    proxy: LoopbackProxy,
    block: () -> T,
): T {
    val previous = ProxySelector.getDefault()
    ProxySelector.setDefault(
        object : ProxySelector() {
            override fun select(uri: URI): List<Proxy> = listOf(Proxy(Proxy.Type.HTTP, proxy.address))

            override fun connectFailed(
                uri: URI,
                sa: SocketAddress,
                ioe: IOException,
            ) = Unit
        },
    )
    return try {
        block()
    } finally {
        ProxySelector.setDefault(previous)
    }
}

/** Runs [block] with a recording default `Authenticator` that answers every challenge, then restores the old one. */
internal fun withDefaultAuthenticator(block: (asked: List<Authenticator.RequestorType>) -> Unit) {
    val asked = Collections.synchronizedList(ArrayList<Authenticator.RequestorType>())
    withDefault(
        object : Authenticator() {
            override fun getPasswordAuthentication(): PasswordAuthentication {
                asked.add(requestorType)
                return PasswordAuthentication(PROXY_USER, PROXY_PASSWORD.toCharArray())
            }
        },
    ) { block(asked) }
}

/** Runs [block] with no default `Authenticator`, then restores the old one. */
internal fun withoutDefaultAuthenticator(block: () -> Unit): Unit = withDefault(null, block)

private fun withDefault(
    authenticator: Authenticator?,
    block: () -> Unit,
) {
    val previous = Authenticator.getDefault()
    Authenticator.setDefault(authenticator)
    try {
        block()
    } finally {
        Authenticator.setDefault(previous)
    }
}
