// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import dev.revokt.FetchRequest
import dev.revokt.RevoktTestingApi
import dev.revokt.jsse.JdkHttpFetcher
import org.junit.jupiter.api.Timeout
import java.net.Authenticator
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `JdkHttpFetcher` through a loopback CONNECT proxy that answers 407 (spec §4 `http`: the per-connection authenticator
 * "answers `RequestorType.PROXY` only"). `HttpURLConnection` asks for proxy credentials only when it dialled a proxy,
 * so only a real tunnel reaches the fetcher's authenticator. The proxy challenges with Digest: Basic is off for HTTPS
 * tunnels by default (`jdk.http.auth.tunneling.disabledSchemes`).
 */
@OptIn(RevoktTestingApi::class)
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class JdkHttpFetcherProxyTest {
    private val trustManager = TestPki.recordingTrustManager()
    private val fetcher = JdkHttpFetcher { TestPki.clientContext(trustManager).socketFactory }

    private fun request(url: String): FetchRequest =
        FetchRequest
            .Builder()
            .url(url)
            .maxBodyBytes(1 shl 20)
            .timeoutMillis(10_000)
            .build()

    @Test
    fun `a proxy's 407 is answered from the default Authenticator, asked for PROXY only`() {
        val handlers = mapOf("/ok" to respond(200, "tunnelled".encodeToByteArray()))
        withDefaultAuthenticator { asked ->
            LoopbackHttps(handlers = handlers).use { origin ->
                LoopbackProxy().use { proxy ->
                    val response = withProxy(proxy) { fetcher.fetch(request(origin.url("/ok"))) }
                    assertEquals(200, response.status)
                    assertContentEquals("tunnelled".encodeToByteArray(), response.body)
                    assertEquals(listOf(Authenticator.RequestorType.PROXY), asked)
                    val connects = proxy.connects.toList()
                    assertEquals(2, connects.size, "not one challenge and one retry")
                    val (challenged, retried) = connects
                    assertEquals(origin.url("").removePrefix("https://"), challenged.target)
                    assertNull(challenged.headers["proxy-authorization"], "credentials were sent before a challenge")
                    assertTrue(retried.authorized, "the retry's Proxy-Authorization does not verify")
                    val answer = retried.headers["proxy-authorization"]?.singleOrNull()
                    assertTrue(answer?.startsWith("Digest ") == true, "not one Digest answer: $answer")
                    val seen = origin.seen.single()
                    assertNull(seen.headers["proxy-authorization"], "proxy credentials reached the origin")
                    assertNull(seen.headers["authorization"], "credentials reached the origin")
                }
            }
        }
    }

    @Test
    fun `with no default Authenticator a proxy's 407 fails the fetch and no credentials are sent`() {
        val handlers = mapOf("/ok" to respond(200, "tunnelled".encodeToByteArray()))
        withoutDefaultAuthenticator {
            LoopbackHttps(handlers = handlers).use { origin ->
                LoopbackProxy().use { proxy ->
                    // HttpURLConnection reports a tunnel refused with a 407 as that response: the engine's FAILED.
                    val response = withProxy(proxy) { fetcher.fetch(request(origin.url("/ok"))) }
                    assertEquals(407, response.status)
                    assertTrue(proxy.connects.isNotEmpty())
                    assertTrue(proxy.connects.none { it.headers.containsKey("proxy-authorization") })
                    assertEquals(emptyList(), origin.seen, "the origin was reached without a tunnel")
                    assertEquals(emptyList(), trustManager.serverChecks, "a handshake ran without a tunnel")
                }
            }
        }
    }

    @Test
    fun `a 401 from the origin behind an authenticated tunnel is returned unanswered`() {
        val handlers = mapOf("/auth" to respond(401, ByteArray(0), "WWW-Authenticate" to "Basic realm=\"revokt\""))
        withDefaultAuthenticator { asked ->
            LoopbackHttps(handlers = handlers).use { origin ->
                LoopbackProxy().use { proxy ->
                    val response = withProxy(proxy) { fetcher.fetch(request(origin.url("/auth"))) }
                    assertEquals(401, response.status)
                    assertEquals(listOf(Authenticator.RequestorType.PROXY), asked, "the default was asked for a 401")
                    assertTrue(proxy.connects.last().authorized)
                    assertNull(origin.seen.single().headers["authorization"], "credentials were sent to the origin")
                }
            }
        }
    }
}
