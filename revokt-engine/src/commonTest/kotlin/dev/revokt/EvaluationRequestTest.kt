// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `EvaluationRequest` and its `Builder` as spec §4 declares them (#122). */
class EvaluationRequestTest {
    private fun der(b: Int) = ByteArray(8) { b.toByte() }

    private fun request() =
        EvaluationRequest
            .Builder()
            .presented(listOf(der(1), der(2)))
            .verifiedPaths(listOf(listOf(der(1), der(3))))
            .host("Corp.Example.")
            .nowMillis(1_700_000_000_000)
            .build()

    @Test
    fun `build throws unless a presented chain or verified paths are set`() {
        val e = assertFailsWith<IllegalArgumentException> { EvaluationRequest.Builder().build() }
        assertEquals("at least one of presented and verifiedPaths is set (spec §4)", e.message)
        val hostOnly = EvaluationRequest.Builder().host("corp").nowMillis(0)
        assertFailsWith<IllegalArgumentException> { hostOnly.build() }
        hostOnly.presented(listOf(der(1))).build()
        EvaluationRequest.Builder().verifiedPaths(listOf(listOf(der(1)))).build()
    }

    @Test
    fun `chainSource is derived, PLATFORM whenever verified paths are given`() {
        val presented = EvaluationRequest.Builder().presented(listOf(der(1))).build()
        val verified = EvaluationRequest.Builder().verifiedPaths(listOf(listOf(der(1)))).build()
        assertEquals(ChainSource.RECONSTRUCTED, presented.chainSource)
        assertEquals(ChainSource.PLATFORM, verified.chainSource)
        assertEquals(ChainSource.PLATFORM, request().chainSource, "both set: the verified paths skip the walk")
    }

    @Test
    fun `the request keeps what it was given, copied`() {
        val leaf = der(1)
        val chain = mutableListOf(leaf, der(2))
        val path = mutableListOf(der(1), der(3))
        val request =
            EvaluationRequest
                .Builder()
                .presented(chain)
                .verifiedPaths(listOf(path))
                .host("Corp.Example.")
                .build()
        leaf[0] = 9
        chain.clear()
        path.clear()
        assertEquals(listOf(der(1), der(2)).map { it.toByteString() }, request.presented)
        assertEquals(listOf(listOf(der(1), der(3)).map { it.toByteString() }), request.verifiedPaths)
        assertEquals("Corp.Example.", request.host, "host' is derived by the evaluation, not here")
        assertNull(request.nowMillis, "unset: the evaluator reads its clock")
        assertNull(
            EvaluationRequest
                .Builder()
                .verifiedPaths(emptyList())
                .build()
                .presented,
        )
    }

    @Test
    fun `a request built from equal inputs is equal, and newBuilder round-trips`() {
        for (same in listOf(request(), request().newBuilder().build())) {
            assertEquals(request(), same)
            assertEquals(request().hashCode(), same.hashCode())
            assertEquals(request().toString(), same.toString())
        }
        val presentedOnly = EvaluationRequest.Builder().presented(listOf(der(1))).build()
        assertEquals(presentedOnly, presentedOnly.newBuilder().build())
        assertNull(presentedOnly.newBuilder().build().verifiedPaths)
        assertNotEquals<Any>(request(), "request")
    }

    @Test
    fun `every field takes part in equality`() {
        val base = request()
        val changed =
            mapOf<String, EvaluationRequest.Builder.() -> EvaluationRequest.Builder>(
                "presented" to { presented(listOf(der(1))) },
                "verifiedPaths" to { verifiedPaths(emptyList()) },
                "host" to { host(null) },
                "nowMillis" to { nowMillis(1) },
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
    }

    @Test
    fun `toString shows each certificate by the SHA-256 of its DER`() {
        val text = request().toString()
        val leaf = der(1).toByteString().sha256().hex()
        assertTrue(text.startsWith("EvaluationRequest(presented=[$leaf, "), text)
        assertTrue("verifiedPaths=[[$leaf, " in text, text)
        assertTrue("host=Corp.Example., nowMillis=1700000000000)" in text, text)
        assertTrue(der(1).toByteString().hex() !in text, text)
    }
}
