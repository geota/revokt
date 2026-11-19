// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** `FetchResponse` from the header maps a Java fetcher passes (spec §3). */
class FetchResponseJavaTest {
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
