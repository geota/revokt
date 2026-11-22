// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.Collections
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * A loopback HTTPS server presenting [leaf] (signed by [TestPki.ca]) on `127.0.0.1`, recording every request it gets.
 * Each path answers with its handler; an unknown path is a 404. Closing it stops the server and its threads.
 */
internal class LoopbackHttps(
    leaf: TestPki.Leaf = TestPki.loopback,
    private val handlers: Map<String, (HttpExchange) -> Unit>,
) : AutoCloseable {
    /** One recorded request: the path and the request headers, names lowercased. */
    class Seen(
        val path: String,
        val headers: Map<String, List<String>>,
    )

    val seen: MutableList<Seen> = Collections.synchronizedList(ArrayList())

    private val executor: ExecutorService =
        Executors.newCachedThreadPool { r -> Thread(r, "loopback-https").also { it.isDaemon = true } }
    private val server: HttpsServer =
        HttpsServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0).apply {
            httpsConfigurator = HttpsConfigurator(TestPki.serverContext(leaf))
            executor = this@LoopbackHttps.executor
            createContext("/") { exchange ->
                exchange.use {
                    val path = it.requestURI.path
                    seen.add(Seen(path, it.requestHeaders.entries.associate { (k, v) -> k.lowercase() to v.toList() }))
                    val handler = handlers[path]
                    if (handler == null) it.sendResponseHeaders(404, -1) else handler(it)
                }
            }
            start()
        }

    fun url(path: String): String = "https://127.0.0.1:${server.address.port}$path"

    fun hits(path: String): Int = synchronized(seen) { seen.count { it.path == path } }

    override fun close() {
        server.stop(0)
        executor.shutdownNow()
    }
}

/** Answers [status] with [body] and the given headers. */
internal fun respond(
    status: Int,
    body: ByteArray = ByteArray(0),
    vararg headers: Pair<String, String>,
): (HttpExchange) -> Unit =
    { exchange ->
        for ((name, value) in headers) exchange.responseHeaders.add(name, value)
        exchange.sendResponseHeaders(status, if (body.isEmpty()) -1 else body.size.toLong())
        if (body.isNotEmpty()) exchange.responseBody.write(body)
    }
