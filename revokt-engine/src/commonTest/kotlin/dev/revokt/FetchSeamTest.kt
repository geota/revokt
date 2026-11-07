// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The fetch seam as spec §3 declares it (#111): `FetchRequest`, `FetchResponse` and `HttpFetcher`. */
@OptIn(RevoktTestingApi::class)
class FetchSeamTest {
    private val url = "https://firefox.settings.services.mozilla.com/v1/buckets/monitor/collections/changes/changeset"

    private fun request() =
        FetchRequest
            .Builder()
            .url(url)
            .header("User-Agent", "revokt")
            .header("If-None-Match", "\"1700000000000\"")
            .maxBodyBytes(RevoktLimits.MAX_JSON_BYTES)
            .build()

    @Test
    fun `FetchRequest copies its headers and keeps their order`() {
        val headers = linkedMapOf("User-Agent" to "revokt", "If-None-Match" to "\"1\"")
        val builder =
            FetchRequest
                .Builder()
                .url(url)
                .headers(headers)
                .maxBodyBytes(1)
        headers["Accept-Encoding"] = "gzip"
        val r = builder.build()
        assertEquals(mapOf("User-Agent" to "revokt", "If-None-Match" to "\"1\""), r.headers)
        assertEquals(listOf("User-Agent", "If-None-Match"), r.headers.keys.toList())
        // The builder is not shared with the built request either.
        builder.header("Accept-Encoding", "gzip")
        assertEquals(2, r.headers.size)
        // headers() replaces; header() replaces one name's value.
        val replaced =
            r
                .newBuilder()
                .headers(mapOf("A" to "1"))
                .header("A", "2")
                .build()
        assertEquals(mapOf("A" to "2"), replaced.headers)
    }

    @Test
    fun `FetchRequest defaults the timeout to FETCH_TIMEOUT and checks its numbers`() {
        assertEquals(RevoktLimits.FETCH_TIMEOUT, request().timeoutMillis)
        assertEquals(
            emptyMap(),
            FetchRequest
                .Builder()
                .url(url)
                .maxBodyBytes(0)
                .build()
                .headers,
        )
        assertFailsWith<IllegalArgumentException> { FetchRequest.Builder().url(url).build() }
        assertFailsWith<IllegalArgumentException> { FetchRequest.Builder().maxBodyBytes(1).build() }
        assertFailsWith<IllegalArgumentException> { request().newBuilder().maxBodyBytes(-1).build() }
        assertFailsWith<IllegalArgumentException> { request().newBuilder().timeoutMillis(0).build() }
    }

    @Test
    fun `FetchRequest is a value type`() {
        val r = request()
        assertEquals(r, request())
        assertEquals(r.hashCode(), request().hashCode())
        assertEquals(r, r.newBuilder().build())
        assertNotEquals(r, r.newBuilder().url("$url?_expected=1").build())
        assertNotEquals(r, r.newBuilder().header("X", "y").build())
        assertNotEquals(r, r.newBuilder().maxBodyBytes(2).build())
        assertNotEquals(r, r.newBuilder().timeoutMillis(1).build())
        assertNotEquals<Any>(r, url)
        assertEquals(
            "FetchRequest(url=$url, headers={User-Agent=revokt, If-None-Match=\"1700000000000\"}, " +
                "maxBodyBytes=${RevoktLimits.MAX_JSON_BYTES}, timeoutMillis=${RevoktLimits.FETCH_TIMEOUT})",
            r.toString(),
        )
    }

    @Test
    fun `FetchResponse of and its builder agree`() {
        val headers = mapOf("ETag" to listOf("\"1\""), "Set-Cookie" to listOf("a=1", "b=2"))
        val body = byteArrayOf(1, 2, 3)
        val built =
            FetchResponse
                .Builder()
                .status(200)
                .header("ETag", "\"1\"")
                .header("Set-Cookie", "a=1")
                .header("Set-Cookie", "b=2")
                .body(body)
                .build()
        val of = FetchResponse.of(200, headers, body)
        assertEquals(of, built)
        assertEquals(of.hashCode(), built.hashCode())
        assertEquals(
            of,
            FetchResponse
                .Builder()
                .status(200)
                .headers(headers)
                .body(body)
                .build(),
        )
        assertEquals(200, of.status)
        assertEquals(headers, of.headers)
        assertContentEquals(body, of.body)
        assertEquals(of, of.newBuilder().build())
    }

    @Test
    fun `FetchResponse copies its input and returns fresh bodies`() {
        val values = mutableListOf("\"1\"")
        val headers = linkedMapOf("ETag" to values)
        val body = byteArrayOf(1, 2, 3)
        val r = FetchResponse.of(304, headers, body)
        values += "\"2\""
        headers["Backoff"] = mutableListOf("60")
        body[0] = 9
        assertEquals(mapOf("ETag" to listOf("\"1\"")), r.headers)
        assertContentEquals(byteArrayOf(1, 2, 3), r.body)
        r.body[0] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), r.body)
    }

    @Test
    fun `FetchResponse defaults to an empty body, needs a status, and is a value type`() {
        val r = FetchResponse.Builder().status(304).build()
        assertContentEquals(ByteArray(0), r.body)
        assertEquals(emptyMap(), r.headers)
        assertFailsWith<IllegalArgumentException> { FetchResponse.Builder().build() }
        assertNotEquals(r, r.newBuilder().status(200).build())
        assertNotEquals(r, r.newBuilder().header("Retry-After", "1").build())
        assertNotEquals(r, r.newBuilder().body(byteArrayOf(0)).build())
        assertNotEquals<Any>(r, 304)
        // A body can be a whole filter: it prints as its size.
        val big = FetchResponse.of(200, mapOf("Content-Type" to listOf("application/json")), ByteArray(70))
        assertEquals(
            "FetchResponse(status=200, headers={Content-Type=[application/json]}, body=70 bytes)",
            big.toString(),
        )
    }

    @Test
    fun `an HttpFetcher is a lambda`() {
        val seen = mutableListOf<FetchRequest>()
        val fetcher =
            HttpFetcher { request ->
                seen += request
                FetchResponse.of(200, emptyMap(), byteArrayOf(0x7b, 0x7d))
            }
        val response = fetcher.fetch(request())
        assertEquals(listOf(request()), seen)
        assertTrue(response.body.contentEquals(byteArrayOf(0x7b, 0x7d)))
    }
}
