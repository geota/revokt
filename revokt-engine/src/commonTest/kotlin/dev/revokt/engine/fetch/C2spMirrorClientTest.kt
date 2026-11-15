// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.DiagnosticCode
import dev.revokt.FetchResponse
import dev.revokt.RevoktLimits
import dev.revokt.SyncStage
import kotlinx.coroutines.Dispatchers
import okio.ByteString.Companion.encodeUtf8
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/**
 * The C2SP mirror client (spec §7.3): `If-Modified-Since` on the manifest request only, the 304 rule, the statuses a
 * mirror fails on, and §9 (e)'s redirect rows end to end through [RedirectingFetcher] (#204's review notes on #194).
 */
class C2spMirrorClientTest {
    private val source = C2spMirrorSource.Builder("https://mirror.example/revocation").build()
    private val manifestUrl = "https://mirror.example/revocation/manifest.json"
    private val body = "filter bytes".encodeUtf8()
    private val file = MirrorFile("a.filter", "a.filter", body.sha256(), body.size.toLong())
    private val fileUrl = "https://mirror.example/revocation/a.filter"

    /** 2025-11-15T00:00:00Z. */
    private val storedAt = 1_763_164_800_000

    private fun client(
        fetcher: ScriptedFetcher,
        clock: TestTimeSource = TestTimeSource(),
    ): C2spMirrorClient = C2spMirrorClient(source, fetcher, Dispatchers.Default, timeSource = clock)

    private fun redirect(
        location: String,
        status: Int = 302,
    ): FetchResponse = response(status, ByteArray(0), "Location" to location)

    /** The unconditional manifest fetch through [fetcher], `FAILED` at `CHANGESET` for [failure]. */
    private fun manifestFails(
        fetcher: ScriptedFetcher,
        failure: ClientFailure,
        clock: TestTimeSource = TestTimeSource(),
    ): ClientResult.Failed = client(fetcher, clock).fetchManifest(null).assertFailed(SyncStage.CHANGESET, failure)

    /** [file]'s fetch through [fetcher], `FAILED` at `ATTACHMENT` for [failure]. */
    private fun fileFails(
        fetcher: ScriptedFetcher,
        failure: ClientFailure,
        of: MirrorFile = file,
    ): ClientResult.Failed = client(fetcher).fetchFile(of).assertFailed(SyncStage.ATTACHMENT, failure)

    /** Why the redirect chain of [failed] was refused. */
    private fun refusal(failed: ClientResult.Failed): RedirectFailure = assertIs<RedirectRefused>(failed.cause).failure

    @Test
    fun `fixture (e) - after a live MIRROR install the manifest request has If-Modified-Since, a file's none`() {
        val fetcher = ScriptedFetcher { if (it.url == manifestUrl) ok("{}") else response(200, body.toByteArray()) }
        val c = client(fetcher)
        c.fetchManifest(storedAt).assertOk()
        c.fetchFile(file).assertOk()
        c.fetchManifest(null).assertOk()
        val (manifest, filter, unconditional) = fetcher.requests
        assertEquals(manifestUrl, manifest.url)
        assertEquals("Sat, 15 Nov 2025 00:00:00 GMT", manifest.headers["If-Modified-Since"])
        assertEquals(fileUrl, filter.url)
        assertNull(filter.headers["If-Modified-Since"])
        assertNull(unconditional.headers["If-Modified-Since"])
        for (r in fetcher.requests) {
            assertEquals("revokt", r.headers["User-Agent"])
            assertEquals(RevoktLimits.FETCH_TIMEOUT, r.timeoutMillis)
        }
        assertEquals(RevoktLimits.MAX_JSON_BYTES, manifest.maxBodyBytes)
        assertEquals(body.size.toLong(), filter.maxBodyBytes)
    }

    @Test
    fun `the If-Modified-Since value is the stored time as an IMF-fixdate`() {
        val fetcher = ScriptedFetcher { ok("{}") }
        client(fetcher).fetchManifest(784_111_777_000).assertOk()
        assertEquals("Sun, 06 Nov 1994 08:49:37 GMT", fetcher.requests.single().headers["If-Modified-Since"])
    }

    @Test
    fun `a 304 to the conditional manifest request is Unchanged, and FAILED without If-Modified-Since`() {
        val fetcher = ScriptedFetcher { response(304) }
        assertIs<ClientResult.Unchanged>(client(fetcher).fetchManifest(storedAt))
        assertEquals(304, manifestFails(fetcher, ClientFailure.HTTP_STATUS).httpStatus)
        assertEquals(304, fileFails(fetcher, ClientFailure.HTTP_STATUS).httpStatus)
    }

    @Test
    fun `fixture (e) - a 300 or a 305, another unfollowed 3xx or a 3xx without Location is FAILED`() {
        for (status in listOf(300, 305, 306, 309, 399)) {
            val fetcher = ScriptedFetcher { redirect("https://mirror.example/elsewhere", status) }
            assertEquals(status, manifestFails(fetcher, ClientFailure.HTTP_STATUS).httpStatus)
            assertEquals(1, fetcher.requests.size, "$status is not followed")
        }
        for (status in listOf(301, 302, 303, 307, 308)) {
            assertEquals(status, fileFails(ScriptedFetcher { response(status) }, ClientFailure.HTTP_STATUS).httpStatus)
        }
        for (status in listOf(401, 404, 407, 500)) {
            val failed = manifestFails(ScriptedFetcher { response(status) }, ClientFailure.HTTP_STATUS)
            assertEquals(status, failed.httpStatus)
        }
    }

    @Test
    fun `fixture (e) - a manifest reached through 10 https redirects is fetched, through 11 FAILED`() {
        for ((hops, fetched) in listOf(10 to true, 11 to false)) {
            val fetcher =
                ScriptedFetcher {
                    val n = it.url.substringAfter("/hop/", "0").toInt()
                    if (n < hops) redirect("https://cdn${n % 3}.example/hop/${n + 1}") else ok("{}")
                }
            if (fetched) {
                assertEquals("{}", client(fetcher).fetchManifest(null).assertOk().utf8())
                assertEquals(11, fetcher.requests.size)
            } else {
                val failed = manifestFails(fetcher, ClientFailure.FETCHER_THREW)
                assertEquals(RedirectFailure.TOO_MANY_HOPS, refusal(failed))
            }
        }
    }

    @Test
    fun `fixture (e) - a redirect to http, with userinfo or back to a URL already in the chain is FAILED`() {
        val refusals =
            listOf(
                "http://mirror.example/x" to RedirectFailure.URL,
                "https://user@mirror.example/x" to RedirectFailure.URL,
                manifestUrl to RedirectFailure.LOOP,
                "https://MIRROR.example:443/revocation/./manifest.json" to RedirectFailure.LOOP,
            )
        for ((location, failure) in refusals) {
            val fetcher = ScriptedFetcher { if (it.url == manifestUrl) redirect(location) else ok("{}") }
            assertEquals(failure, refusal(manifestFails(fetcher, ClientFailure.FETCHER_THREW)), location)
        }
    }

    @Test
    fun `fixture (e) - a query is followed, a fragment dropped, a relative Location resolved`() {
        val moved = "https://mirror.example/mirror2/a.filter?v=2"
        val fetcher =
            ScriptedFetcher {
                when (it.url) {
                    fileUrl -> redirect("../mirror2/a.filter?v=2#frag")
                    moved -> response(200, body.toByteArray())
                    else -> response(404)
                }
            }
        assertEquals(body, client(fetcher).fetchFile(file).assertOk())
        assertEquals(listOf(fileUrl, moved), fetcher.requests.map { it.url })
    }

    @Test
    fun `fixture (e) - a 200 at the end of a chain has the body cap applied to it`() {
        val big = ByteArray(RevoktLimits.MAX_JSON_BYTES.toInt() + 1)
        val over = ScriptedFetcher { if (it.url == manifestUrl) redirect("/m.json") else response(200, big) }
        manifestFails(over, ClientFailure.BODY_TOO_LARGE)
        assertTrue(over.requests.all { it.maxBodyBytes == RevoktLimits.MAX_JSON_BYTES })
        // A file's final response is capped at its declared size.
        val longer = body.toByteArray() + byteArrayOf(1)
        val chained = ScriptedFetcher { if (it.url == fileUrl) redirect("/b") else response(200, longer) }
        fileFails(chained, ClientFailure.BODY_TOO_LARGE)
    }

    @Test
    fun `fixture (e) - a 304 at the end of a chain is the conditional manifest's Unchanged, a file's FAILED`() {
        val fetcher =
            ScriptedFetcher { if (it.url == manifestUrl || it.url == fileUrl) redirect("/moved") else response(304) }
        assertIs<ClientResult.Unchanged>(client(fetcher).fetchManifest(storedAt))
        assertEquals(304, fileFails(fetcher, ClientFailure.HTTP_STATUS).httpStatus)
    }

    @Test
    fun `fixture (e) - a chain that outlasts 30 s in total is FAILED`() {
        val clock = TestTimeSource()
        val fetcher =
            ScriptedFetcher {
                clock += 4.seconds
                val n = it.url.substringAfter("/hop/", "0").toInt()
                redirect("https://mirror.example/hop/${n + 1}")
            }
        assertEquals(RedirectFailure.DEADLINE, refusal(manifestFails(fetcher, ClientFailure.FETCHER_THREW, clock)))
        assertEquals(8, fetcher.requests.size)
    }

    @Test
    fun `a file whose size or SHA-256 differs from the manifest's is FAILED`() {
        val shorter = body.toByteArray().copyOf(body.size - 1)
        fileFails(ScriptedFetcher { response(200, shorter) }, ClientFailure.ATTACHMENT_SIZE)
        val other = "filter bytez".encodeToByteArray()
        fileFails(ScriptedFetcher { response(200, other) }, ClientFailure.ATTACHMENT_HASH)
    }

    @Test
    fun `a file declared over MAX_FILTER_BYTES is FAILED and not fetched`() {
        val none = ScriptedFetcher { error("not fetched") }
        val over = MirrorFile("a.filter", "a.filter", body.sha256(), RevoktLimits.MAX_FILTER_BYTES + 1)
        assertEquals(DiagnosticCode.CAP_NEAR_LIMIT, fileFails(none, ClientFailure.ATTACHMENT_OVER_CAP, over).code)
        assertTrue(none.requests.isEmpty())
    }

    @Test
    fun `a file declared at exactly MAX_FILTER_BYTES is fetched`() {
        val fetcher = ScriptedFetcher { response(200, body.toByteArray()) }
        val at = MirrorFile("a.filter", "a.filter", body.sha256(), RevoktLimits.MAX_FILTER_BYTES)
        fileFails(fetcher, ClientFailure.ATTACHMENT_SIZE, at)
        assertEquals(RevoktLimits.MAX_FILTER_BYTES, fetcher.requests.single().maxBodyBytes)
    }

    @Test
    fun `the manifest cap is overridable upward only`() {
        val fetcher = ScriptedFetcher { ok("{}") }
        val raised = C2spMirrorClient(source, fetcher, Dispatchers.Default, maxManifestEntries = 1_000)
        assertEquals(1_000, raised.maxManifestEntries)
        assertFailsWith<IllegalArgumentException> {
            C2spMirrorClient(source, fetcher, Dispatchers.Default, maxManifestEntries = 255)
        }
    }

    @Test
    fun `a throw or a CR in the User-Agent is FAILED, never a throw`() {
        manifestFails(ScriptedFetcher { throw IllegalStateException("boom") }, ClientFailure.FETCHER_THREW)
        val crlf = C2spMirrorSource.Builder("https://mirror.example/").userAgent("a\r\nb").build()
        val fetcher = ScriptedFetcher { ok("{}") }
        C2spMirrorClient(crlf, fetcher, Dispatchers.Default)
            .fetchManifest(null)
            .assertFailed(SyncStage.CHANGESET, ClientFailure.HEADER_VALUE)
        assertTrue(fetcher.requests.isEmpty())
    }
}
