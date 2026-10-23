// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.port.CrliteKey
import dev.revokt.clubcard.port.CrliteStatus
import dev.revokt.clubcard.port.Encoding
import dev.revokt.clubcard.port.IssuerSpkiHash
import dev.revokt.clubcard.port.LogId
import dev.revokt.clubcard.port.LogTimestamp
import dev.revokt.clubcard.port.Timestamp
import okio.Buffer
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Spec §6.3 decode rules, one test per rule, each against both encodings where the rule applies to both. */
@OptIn(RevoktInternalApi::class)
class ClubcardFiltersTest {
    private val log0 = bytesOf(0)
    private val log1 = bytesOf(1)
    private val issuerA = bytesOf(0xA)
    private val issuerB = bytesOf(0xB)

    private val wellFormed =
        TestFilter(
            coverage = listOf(TestCoverage(log0, 1000, 2000), TestCoverage(log1, 0, -1)),
            index =
                listOf(
                    TestIndexEntry(
                        issuerA,
                        approxM = 100,
                        rank = 2,
                        approxOffset = 0,
                        exactM = 50,
                        exactOffset = 0,
                        inverted = 0,
                        exceptions = listOf(bytesOf(7, 3)),
                    ),
                    TestIndexEntry(issuerB, approxM = 0, rank = 0, inverted = 1),
                ),
            approx = listOf(LongArray(3) { it.toLong() }, LongArray(3) { -1L }),
            exact = LongArray(2) { 0x55L },
        )

    private fun both(filter: TestFilter) =
        listOf(
            "v3" to TestFilterWriter.v3(filter),
            "v4" to TestFilterWriter.v4(filter),
        )

    @Test
    fun `decode reads the same structure from v3 and v4`() {
        for ((name, bytes) in both(wellFormed)) {
            val filter = ClubcardFilters.decode(bytes)
            assertEquals(2, filter.universe.logs.size, name)
            assertEquals(
                Timestamp(1000),
                filter.universe.logs
                    .getValue(LogId(log0))
                    .low,
                name,
            )
            assertEquals(
                Timestamp.MAX,
                filter.universe.logs
                    .getValue(LogId(log1))
                    .high,
                name,
            )
            val a = filter.index.getValue(issuerA)
            assertEquals(100, a.approxFilterM, name)
            assertEquals(2, a.approxFilterRank, name)
            assertEquals(50, a.exactFilterM, name)
            assertEquals(listOf(bytesOf(7, 3)), a.exceptions, name)
            assertTrue(filter.index.getValue(issuerB).inverted, name)
            assertEquals(2, filter.inner.approxFilter.size, name)
        }
    }

    @Test
    fun `decode pads every column with one zero word`() {
        for ((name, bytes) in both(wellFormed)) {
            val filter = ClubcardFilters.decode(bytes)
            assertContentEquals(longArrayOf(0, 1, 2, 0), filter.inner.approxFilter[0], name)
            assertContentEquals(longArrayOf(-1, -1, -1, 0), filter.inner.approxFilter[1], name)
            assertContentEquals(longArrayOf(0x55, 0x55, 0), filter.inner.exactFilter, name)
        }
    }

    @Test
    fun `decode detects the encoding from the two-byte prefix`() {
        assertEquals(Encoding.V3, ClubcardFilters.encodingOf(TestFilterWriter.v3(wellFormed)))
        assertEquals(Encoding.V4, ClubcardFilters.encodingOf(TestFilterWriter.v4(wellFormed)))
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.encodingOf(byteArrayOf(4)) }
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.encodingOf(ByteArray(0)) }
    }

    @Test
    fun `decode rejects a non-zero reserved byte and the cascade versions`() {
        val v4 = TestFilterWriter.v4(wellFormed)
        v4[1] = 1
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.decode(v4) }
        for (version in listOf(0, 1, 2, 5, 0xff)) {
            val bytes = TestFilterWriter.v4(wellFormed)
            bytes[0] = version.toByte()
            val e = assertFailsWith<ClubcardFormatException>("version $version") { ClubcardFilters.decode(bytes) }
            assertTrue(e.message!!.contains("unsupported clubcard version ($version)"), e.message)
        }
    }

    @Test
    fun `decode rejects v4 trailing bytes and accepts v3 trailing bytes`() {
        assertFailsWith<ClubcardFormatException> {
            ClubcardFilters.decode(TestFilterWriter.v4(wellFormed, trailing = byteArrayOf(0)))
        }
        ClubcardFilters.decode(TestFilterWriter.v3(wellFormed, trailing = byteArrayOf(0, 1, 2)))
    }

    @Test
    fun `decode rejects an inverted byte other than 0 or 1`() {
        val filter = TestFilter(index = listOf(TestIndexEntry(issuerA, inverted = 2)))
        for ((name, bytes) in both(filter)) {
            val e = assertFailsWith<ClubcardFormatException>(name) { ClubcardFilters.decode(bytes) }
            assertTrue(e.message!!.contains("inverted byte is 2"), name)
        }
    }

    @Test
    fun `decode rejects an unsorted or duplicated index`() {
        val unsorted = TestFilter(index = listOf(TestIndexEntry(issuerB), TestIndexEntry(issuerA)))
        val duplicated = TestFilter(index = listOf(TestIndexEntry(issuerA), TestIndexEntry(issuerA)))
        for (filter in listOf(unsorted, duplicated)) {
            for ((name, bytes) in both(filter)) {
                val e = assertFailsWith<ClubcardFormatException>(name) { ClubcardFilters.decode(bytes) }
                assertTrue(e.message!!.contains("not sorted"), name)
            }
        }
    }

    @Test
    fun `decode rejects a log id listed twice`() {
        val filter = TestFilter(coverage = listOf(TestCoverage(log0, 1, 2), TestCoverage(log0, 3, 4)))
        for ((name, bytes) in both(filter)) {
            val e = assertFailsWith<ClubcardFormatException>(name) { ClubcardFilters.decode(bytes) }
            assertTrue(e.message!!.contains("twice"), name)
        }
    }

    @Test
    fun `decode rejects a rank past the last column`() {
        val filter =
            TestFilter(
                index = listOf(TestIndexEntry(issuerA, approxM = 10, rank = 3)),
                approx = listOf(LongArray(1), LongArray(1)),
                exact = LongArray(1),
            )
        for ((name, bytes) in both(filter)) {
            val e = assertFailsWith<ClubcardFormatException>(name) { ClubcardFilters.decode(bytes) }
            assertTrue(e.message!!.contains("rank 3"), name)
        }
        val fits =
            TestFilter(
                index = listOf(TestIndexEntry(issuerA, approxM = 10, rank = 2)),
                approx = listOf(LongArray(1), LongArray(1)),
                exact = LongArray(1),
            )
        for ((_, bytes) in both(fits)) ClubcardFilters.decode(bytes)
    }

    @Test
    fun `decode accepts a row window past the end of a column`() {
        // offset + 256 > 64 * words: C2SP lets a builder drop trailing zero words; the window reads as zero.
        val filter =
            TestFilter(
                index =
                    listOf(
                        TestIndexEntry(
                            issuerA,
                            approxM = 10,
                            rank = 1,
                            approxOffset = 1000,
                            exactM = 10,
                            exactOffset = 5000,
                        ),
                    ),
                approx = listOf(LongArray(1)),
                exact = LongArray(1),
            )
        for ((_, bytes) in both(filter)) {
            val decoded = ClubcardFilters.decode(bytes)
            val key = CrliteKey.of(IssuerSpkiHash(issuerA), bytesOf(1, 8))
            assertEquals(CrliteStatus.NOT_COVERED, decoded.contains(key, emptyList()))
        }
    }

    @Test
    fun `decode checks a declared length against the remaining input before allocating`() {
        // v4: a u32 word count of 0xFFFFFFFF with no data behind it.
        val v4 =
            Buffer()
                .writeByte(4)
                .writeByte(0)
                .writeShort(0)
                .writeInt(0)
                .writeByte(1)
                .writeInt(-1)
                .readByteArray()
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.decode(v4) }
        // v3: a u64 coverage count of 2^40 with no data behind it; then a u64 column length of 2^62.
        val v3coverage =
            Buffer()
                .writeByte(3)
                .writeByte(0)
                .writeLongLe(1L shl 40)
                .readByteArray()
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.decode(v3coverage) }
        val v3words =
            Buffer()
                .writeByte(
                    3,
                ).writeByte(0)
                .writeLongLe(0)
                .writeLongLe(0)
                .writeLongLe(1)
                .writeLongLe(1L shl 62)
                .readByteArray()
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.decode(v3words) }
        // A count whose byte length overflows a signed 64-bit product must not wrap into "fits".
        val v3wrap =
            Buffer()
                .writeByte(3)
                .writeByte(0)
                .writeLongLe(-1L)
                .readByteArray()
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.decode(v3wrap) }
    }

    @Test
    fun `decode rejects v3 values outside the v4 range`() {
        val filter = TestFilter(index = listOf(TestIndexEntry(issuerA, approxM = 1L shl 32)))
        val e = assertFailsWith<ClubcardFormatException> { ClubcardFilters.decode(TestFilterWriter.v3(filter)) }
        assertTrue(e.message!!.contains("approx_filter_m"), e.message)
        val rank = TestFilter(index = listOf(TestIndexEntry(issuerA)))
        assertFailsWith<ClubcardFormatException> {
            ClubcardFilters.decode(
                TestFilterWriter.v3(rank, rankOverride = 256),
            )
        }
        val columns = TestFilter(approx = List(256) { LongArray(0) })
        assertFailsWith<ClubcardFormatException> { ClubcardFilters.decode(TestFilterWriter.v3(columns)) }
    }

    @Test
    fun `decode rejects a truncated filter at every byte`() {
        for ((name, whole) in both(wellFormed)) {
            for (len in 0 until whole.size) {
                val cut = whole.copyOf(len)
                if (name == "v3" && len >= whole.size) continue
                assertFailsWith<ClubcardFormatException>("$name truncated to $len") { ClubcardFilters.decode(cut) }
            }
        }
    }

    @Test
    fun `contains answers NOT_ENROLLED for an unknown issuer and NOT_COVERED without a covered sct`() {
        val filter = ClubcardFilters.decode(TestFilterWriter.v4(wellFormed))
        val unknown = CrliteKey.of(IssuerSpkiHash(bytesOf(0xC)), bytesOf(1, 4))
        val covered = LogTimestamp(LogId(log0), Timestamp(1500))
        val outside = LogTimestamp(LogId(log0), Timestamp(2001))
        val unknownLog = LogTimestamp(LogId(bytesOf(9)), Timestamp(1500))
        assertEquals(CrliteStatus.NOT_ENROLLED, filter.contains(unknown, listOf(covered)))
        assertEquals(CrliteStatus.NOT_COVERED, filter.contains(unknown, listOf(outside, unknownLog)))
        assertEquals(CrliteStatus.NOT_COVERED, filter.contains(unknown, emptyList()))
        // An empty approximate filter (approxM == 0) never includes anything; inverted, it includes everything.
        val inB = CrliteKey.of(IssuerSpkiHash(issuerB), bytesOf(1, 4))
        assertEquals(CrliteStatus.REVOKED, filter.contains(inB, listOf(outside, covered)))
    }

    @Test
    fun `timestamp comparisons are unsigned`() {
        assertTrue(Timestamp(-1) > Timestamp(Long.MAX_VALUE))
        assertTrue(Timestamp.MIN < Timestamp(1))
        val filter = ClubcardFilters.decode(TestFilterWriter.v4(wellFormed))
        val key = CrliteKey.of(IssuerSpkiHash(issuerB), bytesOf(1, 4))
        assertEquals(CrliteStatus.REVOKED, filter.contains(key, listOf(LogTimestamp(LogId(log1), Timestamp(-2)))))
    }

    @Test
    fun `issuer-serial hash is sha256 of issuer then serial`() {
        val key = CrliteKey.of(IssuerSpkiHash(issuerA), "abc".encodeToByteArray().toByteString())
        val expected = Buffer().write(issuerA).writeUtf8("abc").sha256()
        assertEquals(expected, key.issuerSerialHash)
    }
}
