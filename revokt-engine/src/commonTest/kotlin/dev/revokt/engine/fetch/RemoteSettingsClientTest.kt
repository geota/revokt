// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.Dataset
import dev.revokt.FetchResponse
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.SyncStage
import dev.revokt.engine.json.JsonString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The Remote Settings client's requests and responses (spec §7.1 protocol, §3 `FetchRequest`/`HttpFetcher`, #129): the
 * exact URLs and headers, the status rules, the envelope parse, the caps and `Backoff`/`Retry-After`.
 */
class RemoteSettingsClientTest {
    private val base = "https://firefox.settings.services.mozilla.com/v1"
    private val changesetUrl = "$base/buckets/security-state/collections/cert-revocations/changeset"

    private val monitor =
        """{"metadata":{},"timestamp":1794026313551,"changes":[
          {"id":"a","last_modified":1793980033808,"bucket":"security-state-preview","collection":"cert-revocations"},
          {"id":"b","last_modified":1793980622465,"bucket":"security-state","collection":"cert-revocations"},
          {"id":"c","last_modified":1794026313551,"bucket":"main","collection":"nimbus-preview"}]}"""

    private val changeset =
        """{"metadata":{"id":"cert-revocations","last_modified":1,
             "signature":{"x5u":"https://content-signature-2.cdn.mozilla.net/g/chains/x.chain","mode":"p384ecdsa",
                          "signature":"sig","ref":"r"},
             "signatures":[{"x5u":"https://elsewhere.example/x.chain","mode":"other","signature":"other"}]},
           "timestamp":1793980622465,
           "changes":[{"id":"r1","last_modified":1793980622465},{"id":"r2","last_modified":1793980622000}]}"""

    @Test
    fun `pollChanges requests monitor changes with _expected=0 and the User-Agent only, and reads the collection`() {
        val fetcher = ScriptedFetcher { ok(monitor) }
        assertEquals(1793980622465, client(fetcher).pollChanges().assertOk())
        val request = fetcher.requests.single()
        assertEquals("$base/buckets/monitor/collections/changes/changeset?_expected=0", request.url)
        assertEquals(mapOf("User-Agent" to "revokt"), request.headers)
        assertEquals(RevoktLimits.MAX_JSON_BYTES, request.maxBodyBytes)
        assertEquals(RevoktLimits.FETCH_TIMEOUT, request.timeoutMillis)
    }

    @Test
    fun `pollChanges fails unless monitor changes lists the collection exactly once with an integer timestamp`() {
        fun entry(lastModified: String) =
            """{"bucket":"security-state","collection":"cert-revocations","last_modified":$lastModified}"""
        for (body in listOf(
            """{"changes":[]}""",
            """{"changes":[${entry("1")},${entry("2")}]}""",
            """{"changes":[${entry("\"1793980622465\"")}]}""",
            """{"changes":[${entry("-1")}]}""",
            """{"changes":[${entry("1.0")}]}""",
            """{"changes":[${entry("9223372036854775808")}]}""",
            """{"changes":[{"bucket":"security-state","collection":"cert-revocations"}]}""",
            """{"changes":{}}""",
            """{}""",
            """[]""",
            """not json""",
        )) {
            client(
                ScriptedFetcher { ok(body) },
            ).pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.MALFORMED)
        }
        // Other buckets and malformed neighbours do not count.
        assertEquals(
            7,
            client(
                ScriptedFetcher { ok("""{"changes":[1,{"bucket":"main"},${entry("7")}]}""") },
            ).pollChanges().assertOk(),
        )
    }

    @Test
    fun `fetchChangeset without a cursor sends _expected and the User-Agent only, never Accept-Encoding`() {
        val fetcher = ScriptedFetcher { ok(changeset) }
        val got = client(fetcher).fetchChangeset(1793980622465, null).assertOk()
        val request = fetcher.requests.single()
        assertEquals("$changesetUrl?_expected=1793980622465", request.url)
        assertEquals(mapOf("User-Agent" to "revokt"), request.headers)
        assertTrue(request.headers.keys.none { it.equals("Accept-Encoding", ignoreCase = true) })
        assertEquals(RevoktLimits.MAX_JSON_BYTES, request.maxBodyBytes)
        assertEquals(1793980622465, got.timestamp)
        assertEquals(listOf("r1", "r2"), got.changes.map { (it["id"] as JsonString).value })
    }

    @Test
    fun `the changeset's three signature fields are metadata signature's, never metadata signatures'`() {
        val got = client(ScriptedFetcher { ok(changeset) }).fetchChangeset(1, null).assertOk()
        assertEquals("sig", got.signature)
        assertEquals("https://content-signature-2.cdn.mozilla.net/g/chains/x.chain", got.x5u)
        assertEquals("p384ecdsa", got.mode)
        // The timestamp is the envelope's, the payload's <ts>; metadata.last_modified is not read.
        assertEquals(1793980622465, got.timestamp)
        // Absent or mistyped fields read as null; nothing here is checked before verification.
        val bare = client(ScriptedFetcher { ok("""{"timestamp":5,"changes":[]}""") }).fetchChangeset(1, null).assertOk()
        assertEquals(listOf(null, null, null), listOf(bare.signature, bare.x5u, bare.mode))
        val mistyped =
            client(
                ScriptedFetcher {
                    ok(
                        """{"metadata":{"signature":{"x5u":1,"mode":null}},"timestamp":5,"changes":[]}""",
                    )
                },
            ).fetchChangeset(1, null)
                .assertOk()
        assertEquals(listOf(null, null, null), listOf(mistyped.signature, mistyped.x5u, mistyped.mode))
    }

    @Test
    fun `fetchChangeset from a cursor sends _since and If-None-Match as the quoted cursor, and a 304 is UNCHANGED`() {
        val fetcher = ScriptedFetcher { response(304, headers = arrayOf("Backoff" to "60")) }
        val result = client(fetcher).fetchChangeset(1793980622465, 1793900000000)
        val unchanged = assertIs<ClientResult.Unchanged>(result)
        assertEquals(304, unchanged.httpStatus)
        assertEquals(60_000, unchanged.backoffMillis)
        val request = fetcher.requests.single()
        assertEquals("$changesetUrl?_expected=1793980622465&_since=%221793900000000%22", request.url)
        assertEquals(mapOf("User-Agent" to "revokt", "If-None-Match" to "\"1793900000000\""), request.headers)
    }

    @Test
    fun `a 304 to a request without If-None-Match is FAILED`() {
        client(ScriptedFetcher { response(304) })
            .fetchChangeset(1, null)
            .assertFailed(SyncStage.CHANGESET, ClientFailure.HTTP_STATUS)
        client(
            ScriptedFetcher { response(304) },
        ).pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.HTTP_STATUS)
    }

    @Test
    fun `data-path (g) a 3xx is FAILED with its status and never followed, as is a 401, a 407 and any other non-200`() {
        for (status in listOf(301, 302, 303, 307, 308, 401, 407, 404, 500, 503, 201, 204, 206)) {
            val fetcher =
                ScriptedFetcher {
                    response(status, changeset.encodeToByteArray(), "Location" to "https://evil.example/changeset")
                }
            val failed =
                client(
                    fetcher,
                ).fetchChangeset(1, null).assertFailed(SyncStage.CHANGESET, ClientFailure.HTTP_STATUS)
            assertEquals(status, failed.httpStatus)
            assertEquals(1, fetcher.requests.size, "status $status: one request, no redirect followed")
        }
    }

    @Test
    fun `_expected and _since must be integers of at least 0 before they enter a query string`() {
        val fetcher = ScriptedFetcher { ok(changeset) }
        val c = client(fetcher)
        c.fetchChangeset(-1, null).assertFailed(SyncStage.CHANGESET, ClientFailure.QUERY_VALUE)
        c.fetchChangeset(1, -1).assertFailed(SyncStage.CHANGESET, ClientFailure.QUERY_VALUE)
        assertEquals(0, fetcher.requests.size)
        c.fetchChangeset(0, 0).assertOk()
        assertEquals("$changesetUrl?_expected=0&_since=%220%22", fetcher.requests.single().url)
    }

    @Test
    fun `a changeset that is not the envelope is FAILED at CHANGESET`() {
        for (body in listOf(
            "not json",
            "[]",
            """{"timestamp":1}""",
            """{"timestamp":1,"changes":{}}""",
            """{"timestamp":1,"changes":[1]}""",
            """{"timestamp":1,"changes":[[]]}""",
            """{"changes":[]}""",
            """{"timestamp":-1,"changes":[]}""",
            """{"timestamp":"1","changes":[]}""",
            """{"timestamp":1.5,"changes":[]}""",
            """{"timestamp":1,"changes":[],"timestamp":2}""",
            "{\"timestamp\":1,\"changes\":[{\"id\":\"\\ud800\"}]}",
        )) {
            client(
                ScriptedFetcher { ok(body) },
            ).fetchChangeset(1, null).assertFailed(SyncStage.CHANGESET, ClientFailure.MALFORMED)
        }
    }

    @Test
    fun `a body over the request's cap is FAILED before it is parsed, whatever the fetcher did`() {
        val over = ByteArray((RevoktLimits.MAX_JSON_BYTES + 1).toInt()) { ' '.code.toByte() }
        val failed =
            client(ScriptedFetcher { response(200, over) })
                .fetchChangeset(1, null)
                .assertFailed(SyncStage.CHANGESET, ClientFailure.BODY_TOO_LARGE)
        assertEquals(200, failed.httpStatus)
        client(
            ScriptedFetcher {
                response(200, over)
            },
        ).pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.BODY_TOO_LARGE)
        // At the cap exactly the body is parsed (and here fails as JSON, not as a size).
        val atCap = ByteArray(RevoktLimits.MAX_JSON_BYTES.toInt()) { ' '.code.toByte() }
        client(
            ScriptedFetcher {
                response(200, atCap)
            },
        ).fetchChangeset(1, null).assertFailed(SyncStage.CHANGESET, ClientFailure.MALFORMED)
    }

    @Test
    fun `a CR or LF in the User-Agent is FAILED and nothing is sent`() {
        for (ua in listOf("revokt\r\nX-Injected: 1", "revokt\n", "\rrevokt")) {
            val fetcher = ScriptedFetcher { ok(changeset) }
            val source =
                MozillaRemoteSettings.DEFAULT
                    .newBuilder()
                    .userAgent(ua)
                    .build()
            val c = client(fetcher, source)
            c.pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.HEADER_VALUE)
            c.fetchChangeset(1, 2).assertFailed(SyncStage.CHANGESET, ClientFailure.HEADER_VALUE)
            c
                .fetchX5u(
                    "https://content-signature-2.cdn.mozilla.net/x.chain",
                ).assertFailed(SyncStage.X5U, ClientFailure.HEADER_VALUE)
            assertEquals(0, fetcher.requests.size)
        }
        // Other control characters are the fetcher's to refuse; a tab is a legal header character.
        val fetcher = ScriptedFetcher { ok(monitor) }
        client(
            fetcher,
            MozillaRemoteSettings.DEFAULT
                .newBuilder()
                .userAgent("revokt\t1")
                .build(),
        ).pollChanges().assertOk()
        assertEquals("revokt\t1", fetcher.requests.single().headers["User-Agent"])
    }

    @Test
    fun `a fetcher that throws is FAILED with its throwable as the cause, an Error included`() {
        for (thrown in listOf(IllegalStateException("boom"), NotImplementedError("no"), RuntimeException())) {
            val failed =
                client(ScriptedFetcher { throw thrown })
                    .fetchChangeset(1, null)
                    .assertFailed(SyncStage.CHANGESET, ClientFailure.FETCHER_THREW)
            assertSame(thrown, failed.cause)
            assertNull(failed.httpStatus)
        }
    }

    @Test
    fun `Backoff 100000000 is returned clamped to MAX_BACKOFF`() {
        val result = client(ScriptedFetcher { ok(changeset, "Backoff" to "100000000") }).fetchChangeset(1, null)
        assertEquals(RevoktLimits.MAX_BACKOFF, assertIs<ClientResult.Ok<*>>(result).backoffMillis)
    }

    @Test
    fun `Backoff and Retry-After are read ignoring case, the longest wins, and unreadable values are ignored`() {
        fun backoff(vararg headers: Pair<String, String>): Long? =
            client(ScriptedFetcher { response(503, headers = arrayOf(*headers)) }).fetchChangeset(1, null).backoffMillis
        assertEquals(60_000, backoff("backoff" to "60"))
        assertEquals(60_000, backoff("BACKOFF" to " 60\t"))
        assertEquals(120_000, backoff("retry-after" to "120"))
        assertEquals(120_000, backoff("Backoff" to "60", "Retry-After" to "120", "backoff" to "30"))
        assertEquals(0, backoff("Retry-After" to "0"))
        assertEquals(RevoktLimits.MAX_BACKOFF, backoff("Retry-After" to "86400"))
        assertEquals(RevoktLimits.MAX_BACKOFF, backoff("Retry-After" to "99999999999999999999999999"))
        assertEquals(86_399_000, backoff("Retry-After" to "86399"))
        for (garbage in listOf(
            "",
            " ",
            "soon",
            "-5",
            "+5",
            "1.5",
            "60s",
            "Wed, 21 Oct 2026 07:28:00 GMT",
            "1 2",
            "٣",
        )) {
            assertNull(backoff("Retry-After" to garbage), "\"$garbage\"")
        }
        assertEquals(5_000, backoff("Retry-After" to "soon", "Backoff" to "5"))
        assertNull(backoff())
        // Carried on a failure with its status, and on a success.
        val failed = client(ScriptedFetcher { response(503, headers = arrayOf("Retry-After" to "10")) }).pollChanges()
        assertEquals(503 to 10_000L, failed.httpStatus to failed.backoffMillis)
        val okResult = client(ScriptedFetcher { ok(monitor, "Backoff" to "7") }).pollChanges()
        assertEquals(200 to 7_000L, okResult.httpStatus to okResult.backoffMillis)
    }

    @Test
    fun `baseUrl joins with exactly one slash whatever slashes it ends with`() {
        for (configured in listOf(base, "$base/", "$base//")) {
            val fetcher = ScriptedFetcher { ok(monitor) }
            client(
                fetcher,
                MozillaRemoteSettings.DEFAULT
                    .newBuilder()
                    .baseUrl(configured)
                    .build(),
            ).pollChanges().assertOk()
            assertEquals(
                "$base/buckets/monitor/collections/changes/changeset?_expected=0",
                fetcher.requests.single().url,
            )
        }
        assertEquals("https://a/b", joinUrl("https://a", "b"))
        assertEquals("https://a/b", joinUrl("https://a/", "/b"))
        assertEquals("https://a/x/b/c", joinUrl("https://a/x//", "//b/c"))
    }

    @Test
    fun `the configured bucket, collection and timeout are the request's`() {
        val fetcher = ScriptedFetcher { ok(changeset) }
        val source =
            MozillaRemoteSettings.DEFAULT
                .newBuilder()
                .bucket("security-state-preview")
                .collection(Dataset.CRLITE, "cert-revocations-test")
                .build()
        client(fetcher, source, FetchLimits(fetchTimeoutMillis = 1_234)).fetchChangeset(9, null).assertOk()
        val request = fetcher.requests.single()
        assertEquals(
            "$base/buckets/security-state-preview/collections/cert-revocations-test/changeset?_expected=9",
            request.url,
        )
        assertEquals(1_234, request.timeoutMillis)
    }

    @Test
    fun `the limits are overridable upward only`() {
        assertFailsWith<IllegalArgumentException> { FetchLimits(maxJsonBytes = RevoktLimits.MAX_JSON_BYTES - 1) }
        assertFailsWith<IllegalArgumentException> { FetchLimits(maxX5uBytes = RevoktLimits.MAX_X5U_BYTES - 1) }
        assertFailsWith<IllegalArgumentException> { FetchLimits(maxFilterBytes = RevoktLimits.MAX_FILTER_BYTES - 1) }
        assertFailsWith<IllegalArgumentException> {
            FetchLimits(maxChangesetRecords = RevoktLimits.MAX_CHANGESET_RECORDS - 1)
        }
        assertFailsWith<IllegalArgumentException> { FetchLimits(fetchTimeoutMillis = 0) }
        val raised = FetchLimits(maxJsonBytes = RevoktLimits.MAX_JSON_BYTES * 2)
        val big = ByteArray((RevoktLimits.MAX_JSON_BYTES + 1).toInt()) { ' '.code.toByte() }
        val fetcher = ScriptedFetcher { FetchResponse.of(200, emptyMap(), big) }
        // Over the default cap but under the raised one: parsed, so a JSON failure, not a size one.
        client(
            fetcher,
            limits = raised,
        ).fetchChangeset(1, null).assertFailed(SyncStage.CHANGESET, ClientFailure.MALFORMED)
        assertEquals(RevoktLimits.MAX_JSON_BYTES * 2, fetcher.requests.single().maxBodyBytes)
    }
}
