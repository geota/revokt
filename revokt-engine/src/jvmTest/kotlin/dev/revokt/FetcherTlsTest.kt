// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.security.KeyStore
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertSame

/** The JVM's `FetcherTls` and the `HttpFetcher.Factory` seam (spec §3, #111), and `FetchResponse` from Java maps. */
@OptIn(RevoktInternalApi::class, RevoktTestingApi::class)
class FetcherTlsTest {
    private val trustManager: X509TrustManager =
        TrustManagerFactory
            .getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(null as KeyStore?) }
            .trustManagers
            .filterIsInstance<X509TrustManager>()
            .first()

    @Test
    fun `a factory receives the source's FetcherTls and its members`() {
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }
        val sockets = context.socketFactory
        val tls = FetcherTls(sockets, trustManager)
        val handed = mutableListOf<FetcherTls>()
        val factory =
            HttpFetcher.Factory { t ->
                handed += t
                HttpFetcher { FetchResponse.of(304, emptyMap(), ByteArray(0)) }
            }
        val fetcher = factory.create(tls)
        assertEquals(
            304,
            fetcher
                .fetch(
                    FetchRequest
                        .Builder()
                        .url("https://example.test/")
                        .maxBodyBytes(1)
                        .build(),
                ).status,
        )
        assertSame(tls, handed.single())
        assertSame(sockets, handed.single().sslSocketFactory)
        assertSame(trustManager, handed.single().trustManager)
    }

    @Test
    fun `FetchResponse drops the null name HttpURLConnection gives the status line`() {
        val fields = linkedMapOf<String?, List<String>>(null to listOf("HTTP/1.1 200 OK"), "ETag" to listOf("\"1\""))

        @Suppress("UNCHECKED_CAST") // HttpURLConnection.getHeaderFields() as a Java fetcher passes it
        val response = FetchResponse.of(200, fields as Map<String, List<String>>, byteArrayOf(1))
        assertEquals(mapOf("ETag" to listOf("\"1\"")), response.headers)
        assertContentEquals(byteArrayOf(1), response.body)
    }

    @Test
    fun `FetchResponse drops a null value list and a null value a Java map can hold`() {
        val fields = linkedMapOf<String, List<String?>?>("Backoff" to null, "Retry-After" to listOf(null, "60", null))

        @Suppress("UNCHECKED_CAST") // a Java fetcher's map, whose nulls the Kotlin type does not show
        val response = FetchResponse.of(200, fields as Map<String, List<String>>, byteArrayOf())
        assertEquals(mapOf("Retry-After" to listOf("60")), response.headers)
        assertEquals(listOf("60"), response.newBuilder().build().headers["Retry-After"])
    }
}
