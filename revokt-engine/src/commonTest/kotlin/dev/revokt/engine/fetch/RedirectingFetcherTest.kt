// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/**
 * The redirect rules of spec §7.3 ("Redirects", revision 56; §9's mirror fixtures: 10 `https` redirects fetched, 11
 * `FAILED`, `http`, userinfo or a loop `FAILED`, a query followed, a fragment dropped, a 300 or 305 `FAILED`, a relative
 * `Location` resolved, the body cap on the final response, one 30 s deadline), one test per rule (#192).
 */
@OptIn(RevoktTestingApi::class)
class RedirectingFetcherTest {
    private val base = "https://mirror.example/revocation/"
    private val manifest = base + "manifest.json"

    private fun request(
        url: String = manifest,
        vararg headers: Pair<String, String>,
    ): FetchRequest =
        FetchRequest
            .Builder()
            .url(url)
            .apply { for ((name, value) in headers) header(name, value) }
            .maxBodyBytes(RevoktLimits.MAX_JSON_BYTES)
            .build()

    private fun redirect(
        location: String?,
        status: Int = 302,
    ): FetchResponse =
        if (location ==
            null
        ) {
            response(status)
        } else {
            response(status, ByteArray(0), "Location" to location)
        }

    /** A fetcher answering each URL from [routes] and anything else with 200 `final`. */
    private fun routed(vararg routes: Pair<String, FetchResponse>): ScriptedFetcher {
        val map = routes.toMap()
        return ScriptedFetcher { map[it.url] ?: ok("final") }
    }

    private fun refused(
        failure: RedirectFailure,
        fetcher: ScriptedFetcher,
        request: FetchRequest = request(),
    ): RedirectRefused {
        val thrown = assertFailsWith<RedirectRefused> { RedirectingFetcher(fetcher).fetch(request) }
        assertEquals(failure, thrown.failure, thrown.message)
        return thrown
    }

    /** The URLs requested after [location] answers the manifest request, the final one answered 200. */
    private fun followed(
        location: String,
        from: String = manifest,
    ): List<String> {
        val fetcher = routed(from to redirect(location))
        assertEquals("final", RedirectingFetcher(fetcher).fetch(request(from)).body.decodeToString())
        return fetcher.requests.map { it.url }
    }

    @Test
    fun `a request answered without a redirect is sent unchanged and its response returned as is`() {
        val answer = ok("{}", "ETag" to "\"1\"")
        val fetcher = ScriptedFetcher { answer }
        val sent = request(manifest, "User-Agent" to "revokt", "If-Modified-Since" to "Sat, 14 Nov 2026 00:00:00 GMT")
        assertSame(answer, RedirectingFetcher(fetcher).fetch(sent))
        assertEquals(listOf(sent), fetcher.requests)
    }

    @Test
    fun `301 302 303 307 and 308 are followed`() {
        for (status in listOf(301, 302, 303, 307, 308)) {
            val fetcher = routed(manifest to redirect("https://cdn.example/m.json", status))
            assertEquals("final", RedirectingFetcher(fetcher).fetch(request()).body.decodeToString(), "$status")
            assertEquals(listOf(manifest, "https://cdn.example/m.json"), fetcher.requests.map { it.url }, "$status")
        }
    }

    @Test
    fun `any other status, a 300 304 305 or 306 included, is the final response`() {
        for (status in listOf(200, 204, 300, 304, 305, 306, 309, 399, 404, 500)) {
            val answer = redirect("https://cdn.example/m.json", status)
            val fetcher = ScriptedFetcher { answer }
            assertSame(answer, RedirectingFetcher(fetcher).fetch(request()), "$status")
            assertEquals(1, fetcher.requests.size, "$status: not followed")
        }
    }

    @Test
    fun `a redirect without a Location is the final response, as reqwest and Necko return it`() {
        val answer = redirect(null, 301)
        val fetcher = ScriptedFetcher { answer }
        assertSame(answer, RedirectingFetcher(fetcher).fetch(request()))
        assertEquals(1, fetcher.requests.size)
    }

    @Test
    fun `10 redirects are followed and an eleventh is FAILED`() {
        fun chain(length: Int): ScriptedFetcher =
            ScriptedFetcher { hop ->
                val n = hop.url.substringAfter("/hop/", "0").toInt()
                if (n < length) redirect("https://mirror.example/hop/${n + 1}") else ok("final")
            }
        val ten = chain(10)
        assertEquals("final", RedirectingFetcher(ten).fetch(request()).body.decodeToString())
        assertEquals(11, ten.requests.size)
        val eleven = chain(11)
        refused(RedirectFailure.TOO_MANY_HOPS, eleven)
        assertEquals(11, eleven.requests.size, "the eleventh Location is not requested")
    }

    @Test
    fun `a hop to http is FAILED and not requested`() {
        val fetcher = routed(manifest to redirect("http://mirror.example/revocation/manifest.json"))
        assertTrue(refused(RedirectFailure.URL, fetcher).detail.startsWith("SCHEME"))
        assertEquals(1, fetcher.requests.size)
        for (location in listOf("ftp://mirror.example/x", "HTTPS://mirror.example/x", "Https://cdn.example/m.json")) {
            assertTrue(refused(RedirectFailure.URL, routed(manifest to redirect(location))).detail.startsWith("SCHEME"))
        }
        // A scheme with no authority is no URL this grammar reads.
        for (location in listOf("data:text/plain,x", "javascript:x", "https:cdn.example/m.json")) {
            assertTrue(refused(RedirectFailure.URL, routed(manifest to redirect(location))).detail.startsWith("SYNTAX"))
        }
    }

    @Test
    fun `a hop with userinfo is FAILED and not requested`() {
        for (location in listOf(
            "https://user@cdn.example/m.json",
            "https://user:pass@cdn.example/m.json",
            "https://mirror.example@evil.example/m.json",
            "//user@cdn.example/m.json",
        )) {
            val fetcher = routed(manifest to redirect(location))
            assertTrue(refused(RedirectFailure.URL, fetcher).detail.startsWith("USERINFO"), location)
            assertEquals(1, fetcher.requests.size, location)
        }
    }

    @Test
    fun `a hop back to a URL already requested is a loop`() {
        // Straight back, refused before it is requested again; back to an earlier hop; the same URL spelled differently.
        val straight = routed(manifest to redirect(manifest))
        refused(RedirectFailure.LOOP, straight)
        assertEquals(1, straight.requests.size)
        val back =
            routed(
                manifest to redirect("https://a.example/1"),
                "https://a.example/1" to redirect("https://b.example/2"),
                "https://b.example/2" to redirect("https://a.example/1"),
            )
        refused(RedirectFailure.LOOP, back)
        assertEquals(3, back.requests.size)
        for (same in listOf(
            "",
            "#top",
            "manifest.json",
            "./manifest.json",
            "/revocation/x/../manifest.json",
            "https://MIRROR.example/revocation/manifest.json",
            "https://mirror.example:443/revocation/manifest.json",
            "https://mirror.example/revocation/manifest.json#f",
        )) {
            refused(RedirectFailure.LOOP, routed(manifest to redirect(same)))
        }
    }

    @Test
    fun `a path or query that differs is another URL, not a loop`() {
        assertEquals(listOf(manifest, "$manifest?v=2"), followed("$manifest?v=2"))
        assertEquals(
            listOf(manifest, "https://mirror.example/Revocation/manifest.json"),
            followed("/Revocation/manifest.json"),
        )
    }

    @Test
    fun `a query is followed and a fragment dropped`() {
        assertEquals(
            "https://cdn.example/m.json?sig=a%2Fb&x=1",
            followed("https://cdn.example/m.json?sig=a%2Fb&x=1#frag")[1],
        )
        assertEquals("https://cdn.example/m.json", followed("https://cdn.example/m.json#frag")[1])
        assertEquals("https://cdn.example/m.json??a=/b", followed("https://cdn.example/m.json??a=/b")[1])
    }

    @Test
    fun `no port rule applies, and an explicit 443 is the default port`() {
        assertEquals("https://cdn.example:8443/m.json", followed("https://cdn.example:8443/m.json")[1])
        assertEquals("https://cdn.example/m.json", followed("https://cdn.example:443/m.json")[1])
        assertEquals("https://cdn.example:1/m.json", followed("https://cdn.example:0001/m.json")[1])
        assertEquals("https://cdn.example:65535/", followed("https://cdn.example:65535")[1])
    }

    @Test
    fun `a relative Location resolves against the URL of the request it answered`() {
        assertEquals(listOf(manifest, base + "v2/manifest.json"), followed("v2/manifest.json"))
        assertEquals(listOf(manifest, "https://mirror.example/other/m.json"), followed("/other/m.json"))
        assertEquals(listOf(manifest, "https://cdn.example/m.json"), followed("//cdn.example/m.json"))
        assertEquals(listOf(manifest, "$manifest?x=1"), followed("?x=1"))
        // Against the second hop, not the first request.
        val fetcher =
            routed(
                manifest to redirect("https://cdn.example/a/b/m.json"),
                "https://cdn.example/a/b/m.json" to redirect("../c.json"),
            )
        RedirectingFetcher(fetcher).fetch(request())
        assertEquals("https://cdn.example/a/c.json", fetcher.requests.last().url)
    }

    @Test
    fun `a Location that is not an RFC 3986 URI reference is FAILED with no repair`() {
        for (location in listOf(
            "https://cdn.example/a b",
            "https://cdn.example/é",
            "https://cdn.example\\@evil.example/",
            "https:\\\\evil.example/",
            "https://cdn.example/%zz",
            "https://cdn.example/%2",
            "https://cdn.example/a%",
            "https://cdn.example/\"",
            "https://cdn.example/a|b",
            "https://cdn.example/a[b]",
            "https://cdn.example/?q=<x>",
            "https://cdn.example/#a#b",
            "https://cdn.example/\r\nX: y",
            "https:cdn.example/m.json",
            "https://",
            "https:///m.json",
            "https://cdn.example:/m.json",
            "https://cdn.example:0/m.json",
            "https://cdn.example:65536/m.json",
            "https://cdn.example:123456/m.json",
            "https://cdn.example:44a/m.json",
        )) {
            val fetcher = routed(manifest to redirect(location))
            refused(RedirectFailure.URL, fetcher)
            assertEquals(1, fetcher.requests.size, location)
        }
    }

    @Test
    fun `a hop host is a DNS host name, an IPv4 dotted quad or a bracketed IPv6 address`() {
        assertEquals("https://127.0.0.1/m.json", followed("https://127.0.0.1/m.json")[1])
        assertEquals("https://[::1]:8443/m.json", followed("https://[::1]:8443/m.json")[1])
        assertEquals("https://[2001:db8::a]/m.json", followed("https://[2001:DB8::A]:443/m.json")[1])
        assertEquals("https://[::ffff:192.0.2.1]/", followed("https://[::ffff:192.0.2.1]")[1])
        assertEquals("https://10.0.0.1:8443/m.json", followed("//10.0.0.1:8443/m.json")[1])
        for (location in listOf(
            "https://0x7f.1/m.json",
            "https://127.1/m.json",
            "https://010.0.0.1/m.json",
            "https://1.2.3.256/m.json",
            "https://1.2.3.4.5/m.json",
            "https://[::1/m.json",
            "https://::1/m.json",
            "https://[fe80::1%25eth0]/m.json",
            "https://[v1.x]/m.json",
            "https://[1:2:3:4:5:6:7:8:9]/m.json",
            "https://[1::2::3]/m.json",
            "https://[::1]x/m.json",
            "https://cdn%2Eexample/m.json",
            "https://cdn..example/m.json",
            "https://cdn.example./m.json",
            "https://cdn_x.example/m.json",
        )) {
            assertTrue(
                refused(RedirectFailure.URL, routed(manifest to redirect(location))).detail.startsWith("HOST"),
                location,
            )
        }
    }

    @Test
    fun `the request's own URL is read by the same rule, so nothing is fetched when it breaks one`() {
        for (url in listOf(
            "http://mirror.example/m.json",
            "https://u@mirror.example/m.json",
            "https://1.2.3.4.5/m.json",
        )) {
            val fetcher = ScriptedFetcher { ok("final") }
            refused(RedirectFailure.URL, fetcher, request(url))
            assertEquals(0, fetcher.requests.size, url)
        }
    }

    @Test
    fun `distinct Location values are FAILED and equal ones collapse`() {
        val two =
            FetchResponse
                .Builder()
                .status(302)
                .header("Location", "https://a.example/m.json")
                .header("location", "https://b.example/m.json")
                .build()
        refused(RedirectFailure.LOCATION_CONFLICT, ScriptedFetcher { if (it.url == manifest) two else ok("final") })
        val same =
            FetchResponse
                .Builder()
                .status(302)
                .header("Location", "https://a.example/m.json")
                .header("LOCATION", " https://a.example/m.json\t")
                .build()
        val fetcher = ScriptedFetcher { if (it.url == manifest) same else ok("final") }
        RedirectingFetcher(fetcher).fetch(request())
        assertEquals("https://a.example/m.json", fetcher.requests.last().url)
    }

    @Test
    fun `a hop to another host or port drops the credential headers from it and every later hop`() {
        val credentials =
            arrayOf(
                "Authorization" to "Bearer a",
                "cookie" to "c=1",
                "COOKIE2" to "c=2",
                "Proxy-Authorization" to "Basic p",
                "www-authenticate" to "w",
            )
        val kept = arrayOf("User-Agent" to "revokt", "If-Modified-Since" to "Sat, 14 Nov 2026 00:00:00 GMT")
        val fetcher =
            routed(
                manifest to redirect("/same/origin.json"),
                "https://mirror.example/same/origin.json" to redirect("https://mirror.example:8443/port.json"),
                "https://mirror.example:8443/port.json" to redirect("https://mirror.example/back.json"),
            )
        RedirectingFetcher(fetcher).fetch(request(manifest, *kept, *credentials))
        val sent = fetcher.requests.map { it.headers }
        assertEquals(mapOf(*kept, *credentials), sent[0])
        assertEquals(mapOf(*kept, *credentials), sent[1], "same host and port: nothing dropped")
        assertEquals(mapOf(*kept), sent[2], "another port: the credentials dropped")
        assertEquals(mapOf(*kept), sent[3], "back on the first origin: still dropped")
        val host = routed(manifest to redirect("https://cdn.example/m.json"))
        RedirectingFetcher(host).fetch(request(manifest, *kept, *credentials))
        assertEquals(mapOf(*kept), host.requests[1].headers, "another host: the credentials dropped")
        val case = routed(manifest to redirect("https://MIRROR.EXAMPLE:443/x.json"))
        RedirectingFetcher(case).fetch(request(manifest, *kept, *credentials))
        assertEquals(mapOf(*kept, *credentials), case.requests[1].headers, "the host compared ignoring case")
    }

    @Test
    fun `every hop carries the request's body cap, so it applies to the final response`() {
        val final = response(304)
        val fetcher =
            ScriptedFetcher {
                if (it.url == manifest) redirect("https://cdn.example/m.json", 307) else final
            }
        assertSame(final, RedirectingFetcher(fetcher).fetch(request()))
        assertEquals(
            listOf(RevoktLimits.MAX_JSON_BYTES, RevoktLimits.MAX_JSON_BYTES),
            fetcher.requests.map { it.maxBodyBytes },
        )
    }

    @Test
    fun `the timeout is one deadline for the whole chain`() {
        val clock = TestTimeSource()
        val fetcher =
            ScriptedFetcher { hop ->
                clock += 4.seconds
                val n = hop.url.substringAfter("/hop/", "0").toInt()
                redirect("https://mirror.example/hop/${n + 1}")
            }
        val thrown = assertFailsWith<RedirectRefused> { RedirectingFetcher(fetcher, clock).fetch(request()) }
        assertEquals(RedirectFailure.DEADLINE, thrown.failure, thrown.message)
        // 4 s a hop: the eighth response arrives at 32 s, past the 30 s deadline.
        assertEquals(8, fetcher.requests.size)
        assertEquals(
            (0 until 8).map { RevoktLimits.FETCH_TIMEOUT - it * 4_000 },
            fetcher.requests.map { it.timeoutMillis },
        )
    }

    @Test
    fun `a final response at the deadline is FAILED, one just before it returned`() {
        for ((spent, late) in listOf(29_999L to false, 30_000L to true)) {
            val clock = TestTimeSource()
            val fetcher =
                ScriptedFetcher {
                    if (it.url == manifest) {
                        redirect("https://cdn.example/m.json")
                    } else {
                        clock += spent.milliseconds
                        ok("final")
                    }
                }
            val fetch = { RedirectingFetcher(fetcher, clock).fetch(request()) }
            if (late) {
                assertEquals(RedirectFailure.DEADLINE, assertFailsWith<RedirectRefused> { fetch() }.failure)
            } else {
                assertEquals("final", fetch().body.decodeToString())
            }
        }
    }

    @Test
    fun `a throw from the wrapped fetcher propagates`() {
        val cause = IllegalStateException("boom")
        val fetcher =
            ScriptedFetcher {
                if (it.url ==
                    manifest
                ) {
                    redirect("https://cdn.example/m.json")
                } else {
                    throw cause
                }
            }
        assertSame(cause, assertFailsWith<IllegalStateException> { RedirectingFetcher(fetcher).fetch(request()) })
    }
}
