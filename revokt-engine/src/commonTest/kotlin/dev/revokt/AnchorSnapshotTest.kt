// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `AnchorSnapshot` as spec §4 declares it (#104): a value type with fresh copies and the platform encodings kept. */
@OptIn(RevoktTestingApi::class)
class AnchorSnapshotTest {
    private val digest = ByteArray(32) { 7 }
    private val a = byteArrayOf(0x30, 1, 1)
    private val b = byteArrayOf(0x30, 1, 2)

    private fun snapshot() =
        AnchorSnapshot
            .Builder()
            .id(3)
            .sha256(digest)
            .anchors(listOf(a, b))
            .createdMillis(1_793_000_000_000)
            .build()

    @Test
    fun `equal inputs are equal, newBuilder round-trips, and every field takes part`() {
        val s = snapshot()
        assertEquals(s, snapshot())
        assertEquals(s.hashCode(), snapshot().hashCode())
        assertEquals(s, s.newBuilder().build())
        assertEquals(s.hashCode(), s.newBuilder().build().hashCode())
        // Every field away from its default, the internal encodings included, so a round trip that drops one shows.
        val full =
            s
                .newBuilder()
                .preloadGenerationId("g")
                .platformEncodings(listOf(b, a))
                .build()
        val again = full.newBuilder().build()
        assertEquals(full, again)
        assertEquals(full.toString(), again.toString())
        assertEquals("g", again.preloadGenerationId)
        assertEquals(full.platformEncodings, again.platformEncodings)
        assertNotEquals(s, s.newBuilder().id(4).build())
        assertNotEquals(s, s.newBuilder().sha256(ByteArray(32)).build())
        assertNotEquals(s, s.newBuilder().anchors(listOf(b, a)).build())
        assertNotEquals(s, s.newBuilder().createdMillis(1).build())
        assertNotEquals(s, s.newBuilder().preloadGenerationId("g").build())
        assertNotEquals<Any>(s, "snapshot")
        assertNull(s.preloadGenerationId)
    }

    @Test
    fun `toString names every field, an anchor by the hash of its DER`() {
        assertEquals(
            "AnchorSnapshot(id=3, sha256=${"07".repeat(32)}, " +
                "anchors=[${a.toByteString().sha256().hex()}, ${b.toByteString().sha256().hex()}], " +
                "createdMillis=1793000000000, preloadGenerationId=null)",
            snapshot().toString(),
        )
    }

    @Test
    fun `the builder copies what it is given and the getters hand out copies`() {
        val given = a.copyOf()
        val hash = digest.copyOf()
        val s =
            snapshot()
                .newBuilder()
                .sha256(hash)
                .anchors(listOf(given))
                .build()
        given[2] = 9
        hash[0] = 9
        s.anchors[0][2] = 9
        s.sha256[0] = 9
        assertContentEquals(a, s.anchors.single())
        assertContentEquals(digest, s.sha256)
    }

    @Test
    fun `the platform encodings default to the bytes read and survive newBuilder`() {
        assertEquals(listOf(a.toByteString(), b.toByteString()), snapshot().platformEncodings)
        val platform = listOf(byteArrayOf(0x30, 0x81.toByte(), 1, 1), b)
        val s =
            snapshot()
                .newBuilder()
                .platformEncodings(platform)
                .build()
        assertEquals(platform.map { it.toByteString() }, s.platformEncodings)
        assertEquals(platform.map { it.toByteString() }, s.newBuilder().build().platformEncodings)
        assertEquals(snapshot(), s, "the platform encodings are the same anchors, so not part of equality")
        assertEquals(
            listOf(a.toByteString()),
            s
                .newBuilder()
                .anchors(listOf(a))
                .build()
                .platformEncodings,
            "new anchors drop the old anchors' encodings",
        )
        val e =
            assertFailsWith<IllegalArgumentException> {
                snapshot().newBuilder().platformEncodings(listOf(a)).build()
            }
        assertTrue("2 anchors, 1 encodings" in e.message!!)
    }

    @Test
    fun `the required fields must be set`() {
        fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!
        assertEquals(
            "id is not set",
            message {
                AnchorSnapshot
                    .Builder()
                    .sha256(digest)
                    .createdMillis(0)
                    .build()
            },
        )
        assertEquals(
            "sha256 is not set",
            message {
                AnchorSnapshot
                    .Builder()
                    .id(1)
                    .createdMillis(0)
                    .build()
            },
        )
        assertEquals(
            "createdMillis is not set",
            message {
                AnchorSnapshot
                    .Builder()
                    .id(1)
                    .sha256(digest)
                    .build()
            },
        )
        assertEquals(
            emptyList(),
            AnchorSnapshot
                .Builder()
                .id(1)
                .sha256(digest)
                .createdMillis(0)
                .build()
                .anchors,
        )
    }
}
