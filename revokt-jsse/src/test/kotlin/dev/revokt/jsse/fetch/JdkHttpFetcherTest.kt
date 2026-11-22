// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import com.sun.net.httpserver.HttpExchange
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.RevoktTestingApi
import dev.revokt.jsse.JdkHttpFetcher
import org.conscrypt.Conscrypt
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.net.Authenticator
import java.net.CacheRequest
import java.net.CacheResponse
import java.net.InetAddress
import java.net.PasswordAuthentication
import java.net.ResponseCache
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.net.URLConnection
import java.security.Provider
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.GZIPOutputStream
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `JdkHttpFetcher` against a loopback HTTPS server with a test CA (spec §3 `HttpFetcher` and `FetchResponse`, §4 `http`,
 * test plan data-path (g) for the JDK fetcher). The fetcher under test gets a context that trusts the test CA through
 * its internal constructor, except where a test installs it as the platform default.
 */
@OptIn(RevoktTestingApi::class)
class JdkHttpFetcherTest {
    private val trustManager = TestPki.recordingTrustManager()
    private val fetcher = JdkHttpFetcher { TestPki.clientContext(trustManager).socketFactory }

    private fun request(
        url: String,
        maxBodyBytes: Long = 1 shl 20,
        timeoutMillis: Long = 10_000,
    ): FetchRequest =
        FetchRequest
            .Builder()
            .url(url)
            .header("User-Agent", "revokt-test")
            .header("If-None-Match", "\"1700000000000\"")
            .maxBodyBytes(maxBodyBytes)
            .timeoutMillis(timeoutMillis)
            .build()

    private fun FetchResponse.header(name: String): List<String> =
        headers.entries.filter { it.key.equals(name, ignoreCase = true) }.flatMap { it.value }

    @Test
    fun `a 200 returns status, headers and body, and the request carries its headers, gzip and Connection close`() {
        val handlers = mapOf("/ok" to respond(200, "hello".encodeToByteArray(), "Backoff" to "30"))
        LoopbackHttps(handlers = handlers).use { server ->
            val response = fetcher.fetch(request(server.url("/ok")))
            assertEquals(200, response.status)
            assertContentEquals("hello".encodeToByteArray(), response.body)
            assertEquals(listOf("30"), response.header("Backoff"))
            val seen = server.seen.single()
            assertEquals(listOf("revokt-test"), seen.headers["user-agent"])
            assertEquals(listOf("\"1700000000000\""), seen.headers["if-none-match"])
            assertEquals(listOf("gzip"), seen.headers["accept-encoding"])
            assertEquals(listOf("close"), seen.headers["connection"])
            assertTrue(trustManager.serverChecks.isNotEmpty(), "the handshake ran through the given trust manager")
        }
    }

    @Test
    fun `the fetcher's Accept-Encoding replaces one the request carries`() {
        LoopbackHttps(handlers = mapOf("/ok" to respond(200, "x".encodeToByteArray()))).use { server ->
            val req = request(server.url("/ok")).newBuilder().header("accept-encoding", "br").build()
            fetcher.fetch(req)
            assertEquals(listOf("gzip"), server.seen.single().headers["accept-encoding"])
        }
    }

    @Test
    fun `data-path (g) a Remote Settings 3xx is returned with its status, never followed`() {
        for (status in listOf(301, 302, 303, 307, 308)) {
            val handlers =
                mapOf(
                    "/from" to respond(status, ByteArray(0), "Location" to "/to"),
                    "/to" to respond(200, "followed".encodeToByteArray()),
                )
            LoopbackHttps(handlers = handlers).use { server ->
                val response = fetcher.fetch(request(server.url("/from")))
                assertEquals(status, response.status)
                assertEquals(listOf("/to"), response.header("Location"))
                assertEquals(0, server.hits("/to"), "a $status was followed")
            }
        }
    }

    @Test
    fun `a 304 is returned with no body`() {
        val handlers = mapOf("/cs" to respond(304, ByteArray(0), "Content-Encoding" to "gzip"))
        LoopbackHttps(handlers = handlers).use { server ->
            val response = fetcher.fetch(request(server.url("/cs")))
            assertEquals(304, response.status)
            assertEquals(0, response.body.size)
        }
    }

    @Test
    fun `a 4xx or 5xx is returned with its status and its body, read under the cap`() {
        val handlers =
            mapOf(
                "/missing" to respond(404, "no such bucket".encodeToByteArray()),
                "/down" to respond(503, ByteArray(0), "Retry-After" to "120"),
                "/big-error" to respond(500, ByteArray(2048)),
            )
        LoopbackHttps(handlers = handlers).use { server ->
            val missing = fetcher.fetch(request(server.url("/missing")))
            assertEquals(404, missing.status)
            assertContentEquals("no such bucket".encodeToByteArray(), missing.body)
            val down = fetcher.fetch(request(server.url("/down")))
            assertEquals(503, down.status)
            assertEquals(listOf("120"), down.header("Retry-After"))
            assertFailsWith<BodyOverCapException> {
                fetcher.fetch(
                    request(server.url("/big-error"), maxBodyBytes = 1024),
                )
            }
        }
    }

    @Test
    fun `a gzip body is inflated and its Content-Encoding and Content-Length are dropped`() {
        val plain = ByteArray(10_000) { (it % 7).toByte() }
        val handlers = mapOf("/gz" to respond(200, gzip(plain), "Content-Encoding" to "gzip", "ETag" to "\"5\""))
        LoopbackHttps(handlers = handlers).use { server ->
            val response = fetcher.fetch(request(server.url("/gz"), maxBodyBytes = plain.size.toLong()))
            assertEquals(200, response.status)
            assertContentEquals(plain, response.body)
            assertEquals(emptyList(), response.header("Content-Encoding"))
            assertEquals(emptyList(), response.header("Content-Length"))
            assertEquals(listOf("\"5\""), response.header("ETag"))
        }
    }

    @Test
    fun `data-path (g) a gzip body inflating past its cap throws before the cap is exceeded`() {
        // 64 MiB of zeros in about 64 KiB of gzip: an uncapped read would buffer all of it.
        val bomb = gzip(ByteArray(64 shl 20))
        val handlers = mapOf("/bomb" to respond(200, bomb, "Content-Encoding" to "gzip"))
        LoopbackHttps(handlers = handlers).use { server ->
            assertFailsWith<BodyOverCapException> { fetcher.fetch(request(server.url("/bomb"), maxBodyBytes = 4096)) }
            // One byte over the cap is over it; the cap itself is not.
            val exact = gzip(ByteArray(4096))
            val exactHandlers =
                mapOf(
                    "/exact" to respond(200, exact, "Content-Encoding" to "gzip"),
                    "/over" to respond(200, gzip(ByteArray(4097)), "Content-Encoding" to "gzip"),
                )
            LoopbackHttps(handlers = exactHandlers).use { second ->
                assertEquals(4096, fetcher.fetch(request(second.url("/exact"), maxBodyBytes = 4096)).body.size)
                assertFailsWith<BodyOverCapException> {
                    fetcher.fetch(
                        request(second.url("/over"), maxBodyBytes = 4096),
                    )
                }
            }
        }
    }

    @Test
    fun `an identity body over the cap throws too`() {
        LoopbackHttps(handlers = mapOf("/raw" to respond(200, ByteArray(4097)))).use { server ->
            assertFailsWith<BodyOverCapException> { fetcher.fetch(request(server.url("/raw"), maxBodyBytes = 4096)) }
            assertEquals(0, fetcher.fetch(request(server.url("/raw"), maxBodyBytes = 4097)).body.size - 4097)
        }
    }

    @Test
    fun `a Content-Encoding other than gzip or identity throws`() {
        val handlers =
            mapOf(
                "/br" to respond(200, "x".encodeToByteArray(), "Content-Encoding" to "br"),
                "/twice" to respond(200, gzip(gzip("x".encodeToByteArray())), "Content-Encoding" to "gzip, gzip"),
                "/identity" to respond(200, "plain".encodeToByteArray(), "Content-Encoding" to "identity"),
            )
        LoopbackHttps(handlers = handlers).use { server ->
            assertFailsWith<IOException> { fetcher.fetch(request(server.url("/br"))) }
            assertFailsWith<IOException> { fetcher.fetch(request(server.url("/twice"))) }
            assertContentEquals("plain".encodeToByteArray(), fetcher.fetch(request(server.url("/identity"))).body)
        }
    }

    @Test
    fun `data-path (g) a 401 on the JDK fetcher is returned unanswered, the default Authenticator never asked`() {
        val handlers = mapOf("/auth" to respond(401, ByteArray(0), "WWW-Authenticate" to "Basic realm=\"revokt\""))
        withDefaultAuthenticator { asked ->
            LoopbackHttps(handlers = handlers).use { server ->
                val response = fetcher.fetch(request(server.url("/auth")))
                assertEquals(401, response.status)
                assertEquals(emptyList(), asked, "the JVM default Authenticator was consulted")
                val seen = server.seen.single()
                assertNull(seen.headers["authorization"], "credentials were sent")
            }
        }
    }

    @Test
    fun `data-path (g) a 407 on the JDK fetcher is returned with its status, unanswered`() {
        val handlers =
            mapOf("/proxy-auth" to respond(407, ByteArray(0), "Proxy-Authenticate" to "Basic realm=\"revokt\""))
        withDefaultAuthenticator { asked ->
            LoopbackHttps(handlers = handlers).use { server ->
                val response = fetcher.fetch(request(server.url("/proxy-auth")))
                assertEquals(407, response.status)
                assertEquals(emptyList(), asked, "the JVM default Authenticator was consulted")
                val seen = server.seen.single()
                assertNull(seen.headers["proxy-authorization"], "credentials were sent")
                assertNull(seen.headers["authorization"], "credentials were sent")
            }
        }
    }

    @Test
    fun `the per-connection authenticator passes a proxy challenge to the default and never answers a server`() {
        withDefaultAuthenticator { asked ->
            val server = ask(Authenticator.RequestorType.SERVER)
            assertNull(server)
            assertEquals(emptyList(), asked)
            val proxy = ask(Authenticator.RequestorType.PROXY)
            assertEquals("proxy-user", proxy?.userName)
            assertEquals(listOf(Authenticator.RequestorType.PROXY), asked)
        }
        // With no default authenticator a proxy challenge goes unanswered.
        val previous = Authenticator.getDefault()
        Authenticator.setDefault(null)
        try {
            assertNull(ask(Authenticator.RequestorType.PROXY))
        } finally {
            Authenticator.setDefault(previous)
        }
    }

    @Test
    fun `data-path (g) the JDK fetcher fails against a certificate lacking the host's SAN (endpoint identification)`() {
        LoopbackHttps(TestPki.wrongHost, mapOf("/x" to respond(200, "x".encodeToByteArray()))).use { server ->
            assertFailsWith<IOException> { fetcher.fetch(request(server.url("/x"))) }
            // A global allow-all hostname verifier does not turn the check off.
            withAllowAllDefaultVerifier {
                assertFailsWith<IOException> { fetcher.fetch(request(server.url("/x"))) }
            }
            assertEquals(0, server.hits("/x"), "a request went out over a connection to the wrong host")
        }
    }

    @Test
    fun `the SAN check holds on a resumed session that a lax connection made, on SunJSSE and Conscrypt`() {
        for (provider in listOf<Provider?>(null, Conscrypt.newProvider())) {
            val label = provider?.name ?: "SunJSSE"
            // One client context, so its session cache is shared between the lax connection and the fetcher.
            val tls = TestPki.clientContext(TestPki.recordingTrustManager(provider), provider).socketFactory
            LoopbackHttps(TestPki.wrongHost, mapOf("/x" to respond(200, "x".encodeToByteArray()))).use { server ->
                // Other code in the process accepts any name and leaves a session for this host:port in the cache.
                val lax = URI(server.url("/x")).toURL().openConnection() as HttpsURLConnection
                lax.sslSocketFactory = tls
                lax.hostnameVerifier = HostnameVerifier { _, _ -> true }
                assertEquals(200, lax.responseCode, label)
                lax.inputStream.close()
                lax.disconnect()
                assertEquals(1, server.hits("/x"), label)
                withAllowAllDefaultVerifier {
                    assertFailsWith<IOException>(label) { JdkHttpFetcher { tls }.fetch(request(server.url("/x"))) }
                }
                assertEquals(1, server.hits("/x"), "$label: the fetcher's request reached the wrong host")
            }
        }
    }

    @Test
    fun `a default factory whose sockets preset endpoint identification is refused before any request`() {
        val tls = TestPki.clientContext(TestPki.recordingTrustManager()).socketFactory
        val presetting =
            object : SSLSocketFactory() {
                override fun getDefaultCipherSuites(): Array<String> = tls.defaultCipherSuites

                override fun getSupportedCipherSuites(): Array<String> = tls.supportedCipherSuites

                override fun createSocket(): Socket = preset(tls.createSocket())

                override fun createSocket(
                    s: Socket,
                    host: String,
                    port: Int,
                    autoClose: Boolean,
                ): Socket = preset(tls.createSocket(s, host, port, autoClose))

                override fun createSocket(
                    host: String,
                    port: Int,
                ): Socket = preset(tls.createSocket(host, port))

                override fun createSocket(
                    host: String,
                    port: Int,
                    localHost: InetAddress,
                    localPort: Int,
                ): Socket = preset(tls.createSocket(host, port, localHost, localPort))

                override fun createSocket(
                    host: InetAddress,
                    port: Int,
                ): Socket = preset(tls.createSocket(host, port))

                override fun createSocket(
                    address: InetAddress,
                    port: Int,
                    localAddress: InetAddress,
                    localPort: Int,
                ): Socket = preset(tls.createSocket(address, port, localAddress, localPort))

                private fun preset(socket: Socket): Socket =
                    socket.also {
                        val tlsSocket = it as SSLSocket
                        tlsSocket.sslParameters =
                            tlsSocket.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    }
            }
        LoopbackHttps(handlers = mapOf("/ok" to respond(200, "x".encodeToByteArray()))).use { server ->
            assertFailsWith<SSLException> { JdkHttpFetcher { presetting }.fetch(request(server.url("/ok"))) }
            assertEquals(0, server.hits("/ok"))
        }
    }

    @Test
    fun `a handshake uses the platform's default TLS and no other trust manager`() {
        val platform = TestPki.recordingTrustManager()
        val previous = HttpsURLConnection.getDefaultSSLSocketFactory()
        HttpsURLConnection.setDefaultSSLSocketFactory(TestPki.clientContext(platform).socketFactory)
        try {
            LoopbackHttps(handlers = mapOf("/ok" to respond(200, "ok".encodeToByteArray()))).use { server ->
                // The JVM's trust store lacks the test CA: the fetch succeeds only over the default set here.
                val response = JdkHttpFetcher().fetch(request(server.url("/ok")))
                assertEquals(200, response.status)
                assertEquals(
                    listOf(TestPki.loopback.certificate.subjectX500Principal.name),
                    platform.serverChecks.distinct(),
                )
            }
        } finally {
            HttpsURLConnection.setDefaultSSLSocketFactory(previous)
        }
        // Without the test CA in the platform's trust, the same fetch fails the handshake.
        LoopbackHttps(handlers = mapOf("/ok" to respond(200, "ok".encodeToByteArray()))).use { server ->
            assertFailsWith<SSLHandshakeException> { JdkHttpFetcher().fetch(request(server.url("/ok"))) }
            assertEquals(0, server.hits("/ok"))
        }
    }

    @Test
    fun `the JVM default ResponseCache is never consulted`() {
        val asked = Collections.synchronizedList(ArrayList<String>())
        val previous = ResponseCache.getDefault()
        ResponseCache.setDefault(
            object : ResponseCache() {
                override fun get(
                    uri: URI,
                    rqstMethod: String,
                    rqstHeaders: Map<String, List<String>>,
                ): CacheResponse? {
                    asked.add("get $uri")
                    return null
                }

                override fun put(
                    uri: URI,
                    conn: URLConnection,
                ): CacheRequest? {
                    asked.add("put $uri")
                    return null
                }
            },
        )
        try {
            LoopbackHttps(handlers = mapOf("/ok" to respond(200, "x".encodeToByteArray()))).use { server ->
                assertEquals(200, fetcher.fetch(request(server.url("/ok"))).status)
            }
        } finally {
            ResponseCache.setDefault(previous)
        }
        assertEquals(emptyList(), asked)
    }

    @Test
    fun `a non-https URL is refused before any connection`() {
        assertFailsWith<IOException> { fetcher.fetch(request("http://127.0.0.1:9/x")) }
        assertEquals(emptyList(), trustManager.serverChecks)
    }

    @Test
    fun `timeoutMillis bounds a server that never answers`() {
        val release = CountDownLatch(1)
        val handlers = mapOf("/hang" to { _: HttpExchange -> check(release.await(30, TimeUnit.SECONDS)) })
        LoopbackHttps(handlers = handlers).use { server ->
            try {
                assertFailsWith<SocketTimeoutException> {
                    fetcher.fetch(
                        request(server.url("/hang"), timeoutMillis = 300),
                    )
                }
            } finally {
                release.countDown()
            }
        }
    }

    @Test
    fun `an interrupted thread fetches nothing and keeps its interrupt flag`() {
        LoopbackHttps(handlers = mapOf("/ok" to respond(200, "x".encodeToByteArray()))).use { server ->
            Thread.currentThread().interrupt()
            try {
                assertFailsWith<InterruptedIOException> { fetcher.fetch(request(server.url("/ok"))) }
                assertTrue(Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
            }
            assertEquals(0, server.hits("/ok"))
        }
    }

    @Test
    fun `an interrupt during the body read disconnects and throws`() {
        val firstChunk = CountDownLatch(1)
        val release = CountDownLatch(1)
        val handlers =
            mapOf(
                "/slow" to { exchange: HttpExchange ->
                    exchange.sendResponseHeaders(200, 0)
                    val out = exchange.responseBody
                    try {
                        // A trickle that never ends while the test runs: each read returns, so the interrupt is seen.
                        while (release.count > 0) {
                            out.write(ByteArray(16))
                            out.flush()
                            firstChunk.countDown()
                            Thread.sleep(20)
                        }
                    } catch (ignored: IOException) {
                        // The client went away.
                    }
                },
            )
        LoopbackHttps(handlers = handlers).use { server ->
            val thrown = AtomicReference<Throwable?>()
            val flagAfter = AtomicReference<Boolean>()
            val worker =
                Thread {
                    try {
                        fetcher.fetch(request(server.url("/slow")))
                    } catch (t: Throwable) {
                        thrown.set(t)
                    }
                    flagAfter.set(Thread.currentThread().isInterrupted)
                }
            worker.start()
            try {
                assertTrue(firstChunk.await(10, TimeUnit.SECONDS))
                worker.interrupt()
                worker.join(5_000)
                assertTrue(!worker.isAlive, "the fetch did not stop on interrupt")
                assertTrue(thrown.get() is InterruptedIOException, "threw ${thrown.get()}")
                assertEquals(true, flagAfter.get())
            } finally {
                release.countDown()
            }
        }
    }

    @Test
    fun `readCapped asks the decoder for at most one byte past the cap`() {
        val produced = intArrayOf(0)
        val endless =
            object : InputStream() {
                override fun read(): Int = throw AssertionError("single-byte reads are not used")

                override fun read(
                    b: ByteArray,
                    off: Int,
                    len: Int,
                ): Int {
                    produced[0] += len
                    // An uncapped reader would read forever.
                    if (produced[0] > 1 shl 20) throw AssertionError("read far past the cap")
                    return len
                }
            }
        assertFailsWith<BodyOverCapException> { readCapped(endless, 10_000) }
        assertEquals(10_001, produced[0])
        produced[0] = 0
        assertFailsWith<BodyOverCapException> { readCapped(endless, 0) }
        assertEquals(1, produced[0])
    }

    @Test
    fun `readCapped stops at the first read after an interrupt and keeps the flag`() {
        var reads = 0
        val interruptingOnSecond =
            object : InputStream() {
                override fun read(): Int = throw AssertionError("single-byte reads are not used")

                override fun read(
                    b: ByteArray,
                    off: Int,
                    len: Int,
                ): Int {
                    reads++
                    // The interrupt lands while the body is being read, as the engine's cancel(true) does.
                    if (reads == 2) Thread.currentThread().interrupt()
                    return 1
                }
            }
        try {
            assertFailsWith<InterruptedIOException> { readCapped(interruptingOnSecond, 1_000) }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(2, reads)
        } finally {
            Thread.interrupted()
        }
    }

    private fun withAllowAllDefaultVerifier(block: () -> Unit) {
        val previous = HttpsURLConnection.getDefaultHostnameVerifier()
        HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { _, _ -> true })
        try {
            block()
        } finally {
            HttpsURLConnection.setDefaultHostnameVerifier(previous)
        }
    }

    private fun gzip(bytes: ByteArray): ByteArray =
        ByteArrayOutputStream()
            .also { out ->
                GZIPOutputStream(out).use {
                    it.write(bytes)
                }
            }.toByteArray()

    private fun ask(type: Authenticator.RequestorType): PasswordAuthentication? =
        Authenticator.requestPasswordAuthentication(
            ProxyOnlyAuthenticator,
            "proxy.example",
            null,
            3128,
            "https",
            "revokt",
            "basic",
            null,
            type,
        )

    /** Runs [block] with a recording default Authenticator that answers every challenge, then restores the old one. */
    private fun withDefaultAuthenticator(block: (asked: List<Authenticator.RequestorType>) -> Unit) {
        val asked = Collections.synchronizedList(ArrayList<Authenticator.RequestorType>())
        val previous = Authenticator.getDefault()
        Authenticator.setDefault(
            object : Authenticator() {
                override fun getPasswordAuthentication(): PasswordAuthentication {
                    asked.add(requestorType)
                    return PasswordAuthentication("proxy-user", "secret".toCharArray())
                }
            },
        )
        try {
            block(asked)
        } finally {
            Authenticator.setDefault(previous)
        }
    }
}
