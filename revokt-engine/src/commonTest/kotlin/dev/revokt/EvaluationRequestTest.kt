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
            .verifiedPath(listOf(der(1), der(3)))
            .host("Corp.Example.")
            .nowMillis(1_700_000_000_000)
            .build()

    @Test
    fun `build throws unless a presented chain or a verified path is set`() {
        val e = assertFailsWith<IllegalArgumentException> { EvaluationRequest.Builder().build() }
        assertEquals("at least one of presented and verifiedPath is set (spec §4)", e.message)
        val hostOnly = EvaluationRequest.Builder().host("corp").nowMillis(0)
        assertFailsWith<IllegalArgumentException> { hostOnly.build() }
        hostOnly.presented(listOf(der(1))).build()
        EvaluationRequest.Builder().verifiedPath(listOf(der(1))).build()
    }

    @Test
    fun `build throws for an empty chain or an empty path`() {
        val cases =
            mapOf(
                "presented is set but empty: a chain has a leaf" to
                    { b: EvaluationRequest.Builder -> b.presented(emptyList()) },
                "verifiedPath is set but empty: it runs leaf to anchor" to
                    { b: EvaluationRequest.Builder -> b.verifiedPath(emptyList()) },
            )
        for ((expected, set) in cases) {
            val alone = assertFailsWith<IllegalArgumentException> { set(EvaluationRequest.Builder()).build() }
            assertEquals(expected, alone.message)
            // The other list being valid does not rescue an empty one.
            val withChain = EvaluationRequest.Builder().presented(listOf(der(1))).verifiedPath(listOf(der(1)))
            val beside = assertFailsWith<IllegalArgumentException> { set(withChain).build() }
            assertEquals(expected, beside.message)
        }
    }

    @Test
    fun `build throws when the verified path does not start with the presented leaf, byte for byte`() {
        for (path in listOf(listOf(der(2), der(3)), listOf(der(1).copyOf(7)), listOf(der(1) + byteArrayOf(0)))) {
            val e =
                assertFailsWith<IllegalArgumentException> {
                    EvaluationRequest
                        .Builder()
                        .presented(listOf(der(1), der(2)))
                        .verifiedPath(path)
                        .build()
                }
            assertEquals("verifiedPath does not start with the presented leaf", e.message)
        }
        // Equal bytes in another array are the same leaf, and the rest of either chain is not compared.
        EvaluationRequest
            .Builder()
            .presented(listOf(der(1), der(9)))
            .verifiedPath(listOf(der(1)))
            .build()
    }

    @Test
    fun `build throws for a verified path longer than MAX_DEPTH + 1 certificates`() {
        val longest = List(RevoktLimits.MAX_DEPTH + 1) { der(it) }
        EvaluationRequest.Builder().verifiedPath(longest).build()
        val e =
            assertFailsWith<IllegalArgumentException> {
                EvaluationRequest.Builder().verifiedPath(longest + der(99)).build()
            }
        assertEquals(
            "verifiedPath holds more than MAX_DEPTH + 1 certificates, the longest path a walk builds",
            e.message,
        )
    }

    @Test
    fun `chainSource is derived, PLATFORM whenever a verified path is given`() {
        val presented = EvaluationRequest.Builder().presented(listOf(der(1))).build()
        val verified = EvaluationRequest.Builder().verifiedPath(listOf(der(1))).build()
        assertEquals(ChainSource.RECONSTRUCTED, presented.chainSource)
        assertEquals(ChainSource.PLATFORM, verified.chainSource)
        assertEquals(ChainSource.PLATFORM, request().chainSource, "both set: the verified path skips the walk")
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
                .verifiedPath(path)
                .host("Corp.Example.")
                .build()
        leaf[0] = 9
        chain.clear()
        path.clear()
        assertEquals(listOf(der(1), der(2)).map { it.toByteString() }, request.presented)
        assertEquals(listOf(der(1), der(3)).map { it.toByteString() }, request.verifiedPath)
        assertEquals("Corp.Example.", request.host, "host' is derived by the evaluation, not here")
        assertNull(request.nowMillis, "unset: the evaluator reads its clock")
        assertNull(
            EvaluationRequest
                .Builder()
                .verifiedPath(listOf(der(1)))
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
        assertNull(presentedOnly.newBuilder().build().verifiedPath)
        assertNotEquals<Any>(request(), "request")
    }

    @Test
    fun `every field takes part in equality`() {
        val base = request()
        val changed =
            mapOf<String, EvaluationRequest.Builder.() -> EvaluationRequest.Builder>(
                "presented" to { presented(listOf(der(1))) },
                "verifiedPath" to { verifiedPath(listOf(der(1), der(4))) },
                "host" to { host(null) },
                "nowMillis" to { nowMillis(1) },
            )
        for ((field, change) in changed) {
            assertNotEquals(base, change(base.newBuilder()).build(), field)
        }
    }

    @Test
    fun `toString shows each certificate by the SHA-256 of its DER`() {
        val text = request().toString()
        val leaf = der(1).toByteString().sha256().hex()
        assertTrue(text.startsWith("EvaluationRequest(presented=[$leaf, "), text)
        assertTrue("verifiedPath=[$leaf, " in text, text)
        assertTrue("host=Corp.Example., nowMillis=1700000000000)" in text, text)
        assertTrue(der(1).toByteString().hex() !in text, text)
    }
}
