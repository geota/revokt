// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** `CrliteQuery` and `CrliteSct` as spec §3.2 declares them (#90): value types with checked fields and fresh copies. */
@OptIn(RevoktTestingApi::class)
class CrliteQueryTest {
    private val log = ByteArray(32) { 3 }
    private val issuer = ByteArray(32) { 5 }

    private fun sct(ts: Long = 1_793_000_000_000) =
        CrliteSct
            .Builder()
            .logId(log)
            .timestampMillis(ts)
            .build()

    private fun query() =
        CrliteQuery
            .Builder()
            .issuerSpkiHash(issuer)
            .serial(byteArrayOf(0, 1))
            .sct(sct())
            .build()

    @Test
    fun `fields are checked and every required one must be set`() {
        fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!
        assertTrue(
            "32 bytes" in
                message {
                    CrliteSct
                        .Builder()
                        .logId(ByteArray(31))
                        .timestampMillis(0)
                        .build()
                },
        )
        assertTrue("logId is not set" in message { CrliteSct.Builder().timestampMillis(0).build() })
        assertTrue("timestampMillis is not set" in message { CrliteSct.Builder().logId(log).build() })
        assertTrue("32 bytes" in message { query().newBuilder().issuerSpkiHash(ByteArray(33)).build() })
        assertEquals(
            0,
            query()
                .newBuilder()
                .serial(ByteArray(0))
                .build()
                .serial.size,
            "an empty serial is a query",
        )
        assertTrue("issuerSpkiHash is not set" in message { CrliteQuery.Builder().serial(byteArrayOf(1)).build() })
        assertTrue("serial is not set" in message { CrliteQuery.Builder().issuerSpkiHash(issuer).build() })
    }

    @Test
    fun `the builders copy what they are given and the getters hand out copies`() {
        val given = log.copyOf()
        val s =
            CrliteSct
                .Builder()
                .logId(given)
                .timestampMillis(1)
                .build()
        given[0] = 9
        s.logId[0] = 9
        assertContentEquals(log, s.logId)
        val q = query()
        q.issuerSpkiHash[0] = 0
        q.serial[0] = 7
        assertContentEquals(issuer, q.issuerSpkiHash)
        assertContentEquals(byteArrayOf(0, 1), q.serial)
        assertFailsWith<UnsupportedOperationException> { (q.scts as MutableList<CrliteSct>).clear() }
    }

    @Test
    fun `equality, hashCode and toString are by content`() {
        assertEquals(sct(), sct())
        assertEquals(sct().hashCode(), sct().hashCode())
        assertNotEquals(sct(), sct(2))
        assertNotEquals<Any>(sct(), "sct")
        assertEquals(query(), query().newBuilder().build())
        assertEquals(query().hashCode(), query().newBuilder().build().hashCode())
        assertNotEquals(query(), query().newBuilder().sct(sct(2)).build())
        assertNotEquals(query(), query().newBuilder().issuerSpkiHash(ByteArray(32)).build())
        assertNotEquals<Any>(query(), "query")
        assertEquals("CrliteSct(logId=${"03".repeat(32)}, timestampMillis=18446744073709551615)", sct(-1).toString())
        assertTrue("serial=0001" in query().toString())
        assertEquals(
            listOf(sct(2)),
            query()
                .newBuilder()
                .scts(listOf(sct(2)))
                .build()
                .scts,
        )
    }
}
