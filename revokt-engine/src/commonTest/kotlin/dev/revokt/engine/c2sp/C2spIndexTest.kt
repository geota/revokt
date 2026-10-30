// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.c2sp

import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The C2SP `upki-revocation@v1.0.0` index file format (#86), on hand-built indexes. */
class C2spIndexTest {
    private fun log(b: Int): ByteString = ByteArray(32) { b.toByte() }.toByteString()

    private val a = log(0x0A)
    private val b = log(0x0B)
    private val c = log(0xF0)

    private val filters =
        listOf(
            "full" to mapOf(b to Window(100u, 200u), a to Window(10u, 20u)),
            "delta" to mapOf(b to Window(150u, 250u), c to Window(1u, ULong.MAX_VALUE)),
        )

    private fun built(): ByteArray = C2spIndex.write(C2spIndex.index(filters))

    private fun assertMalformed(
        bytes: ByteArray,
        fragment: String,
    ) {
        val e = assertFailsWith<IndexFormatException> { C2spIndex.read(bytes) }
        assertTrue(fragment in e.message!!, "'$fragment' not in '${e.message}'")
    }

    @Test
    fun `an index of no filters is the 14-byte header, as upki writes it`() {
        // upki 1.0.1's upki-cli/tests/data/verify_of_empty_manifest/revocation/index.bin, byte for byte.
        val upki = "upkiidx1".encodeToByteArray() + ByteArray(6)
        assertContentEquals(upki, C2spIndex.write(C2spIndex.index(emptyList())))
        assertEquals(IndexFile(emptyList(), emptyMap()), C2spIndex.read(upki))
    }

    @Test
    fun `the writer lays out filenames in order, logs sorted unsigned, entries in filter order`() {
        val bytes = built()
        assertEquals(14 + 32 * 2 + 42 * 3 + 18 * 4, bytes.size)
        val index = C2spIndex.read(bytes)
        assertEquals(listOf("full", "delta"), index.filenames)
        assertEquals(listOf(a, b, c), index.logs.keys.toList(), "0xF0 sorts after 0x0B as an unsigned byte")
        assertEquals(listOf(IndexEntry(0, Window(100u, 200u)), IndexEntry(1, Window(150u, 250u))), index.logs[b])
        assertEquals(
            listOf(IndexEntry(1, Window(1u, ULong.MAX_VALUE))),
            index.logs[c],
            "u64 windows survive the round trip",
        )
    }

    @Test
    fun `read and write round trip`() {
        val bytes = built()
        assertContentEquals(bytes, C2spIndex.write(C2spIndex.read(bytes)))
    }

    @Test
    fun `selection collects every matching entry, inclusive at both ends, across SCTs`() {
        val index = C2spIndex.read(built())
        assertEquals(setOf("full", "delta"), C2spIndex.covering(index, listOf(b to 150uL)))
        assertEquals(setOf("full"), C2spIndex.covering(index, listOf(b to 100uL)))
        assertEquals(setOf("delta"), C2spIndex.covering(index, listOf(b to 250uL)))
        assertEquals(emptySet(), C2spIndex.covering(index, listOf(b to 251uL, a to 9uL, log(1) to 15uL)))
        assertEquals(
            listOf("delta", "full"),
            C2spIndex.covering(index, listOf(c to 5uL, a to 20uL)).toList(),
            "first-match order",
        )
    }

    @Test
    fun `the header is checked`() {
        assertMalformed(ByteArray(13), "shorter than its 14-byte header")
        assertMalformed(built().also { it[7] = '0'.code.toByte() }, "magic upkiidx1")
        assertMalformed(built().copyOf(14 + 32), "more than its")
    }

    @Test
    fun `filenames are checked`() {
        fun withName(name: ByteArray): ByteArray =
            built().also {
                name.copyInto(it, 14)
                ByteArray(32 - name.size).copyInto(
                    it,
                    14 + name.size,
                )
            }
        assertMalformed(withName(ByteArray(0)), "is not 1 to 32 bytes")
        assertMalformed(withName("..".encodeToByteArray()), "is not 1 to 32 bytes")
        assertMalformed(withName("a/b".encodeToByteArray()), "is not 1 to 32 bytes")
        assertMalformed(withName("delta".encodeToByteArray()), "names a file twice")
        assertMalformed(built().also { it[14 + 10] = 'x'.code.toByte() }, "zero-padded")
        assertEquals("A".repeat(32), C2spIndex.read(withName("A".repeat(32).encodeToByteArray())).filenames[0])
    }

    @Test
    fun `the log directory must be sorted without duplicates, and sections inside the file and apart`() {
        val dir = 14 + 32 * 2
        // Swap the first two log IDs: unsorted.
        val swapped =
            built().also {
                val first = it.copyOfRange(dir, dir + 32)
                it.copyInto(it, dir, dir + 42, dir + 74)
                first.copyInto(
                    it,
                    dir + 42,
                )
            }
        assertMalformed(swapped, "not sorted")
        val duplicate = built().also { it.copyInto(it, dir + 42, dir, dir + 32) }
        assertMalformed(duplicate, "not sorted")
        val outside = built().also { it[dir + 32 + 7] = 0x7F }
        assertMalformed(outside, "not inside the file")
        val intoTables =
            built().also {
                for (i in 0 until 8) it[dir + 32 + i] = 0
                it[dir + 32 + 7] = 20
            }
        assertMalformed(intoTables, "not inside the file")
        // Point the second log's section at the first's: overlapping.
        val overlap = built().also { it.copyInto(it, dir + 42 + 32, dir + 32, dir + 40) }
        assertMalformed(overlap, "overlap")
    }

    @Test
    fun `an entry naming a filter past the table is malformed`() {
        val sections = 14 + 32 * 2 + 42 * 3
        assertMalformed(
            built().also {
                it[sections] = 0
                it[sections + 1] = 2
            },
            "names filter 2 of 2",
        )
    }

    @Test
    fun `the writer refuses names a reader would reject`() {
        assertFailsWith<IllegalArgumentException> { C2spIndex.index(listOf("x".repeat(33) to emptyMap())) }
        assertFailsWith<IllegalArgumentException> { C2spIndex.index(listOf("a" to emptyMap(), "a" to emptyMap())) }
    }

    @Test
    fun `an index revokt built is consistent with its filters' coverage`() {
        val index = C2spIndex.read(built())
        assertEquals(emptyList(), C2spIndex.inconsistencies(index, filters.toMap()))
    }

    @Test
    fun `split entries that chain without a gap cover a window exactly`() {
        val split =
            IndexFile(
                listOf("f"),
                linkedMapOf(a to listOf(IndexEntry(0, Window(10u, 14u)), IndexEntry(0, Window(15u, 20u)))),
            )
        assertEquals(emptyList(), C2spIndex.inconsistencies(split, mapOf("f" to mapOf(a to Window(10u, 20u)))))
    }

    @Test
    fun `each kind of mismatch is reported`() {
        val coverage = mapOf("f" to mapOf(a to Window(10u, 20u)))

        fun index(
            vararg entries: IndexEntry,
            names: List<String> = listOf("f"),
        ) = IndexFile(
            names,
            linkedMapOf(a to entries.toList()),
        )
        assertTrue(
            C2spIndex.inconsistencies(index(IndexEntry(0, Window(10u, 21u))), coverage).any { "not inside" in it },
        )
        assertTrue(
            C2spIndex.inconsistencies(index(IndexEntry(0, Window(10u, 19u))), coverage).any {
                "without a gap" in
                    it
            },
        )
        assertTrue(
            C2spIndex
                .inconsistencies(
                    index(IndexEntry(0, Window(10u, 12u)), IndexEntry(0, Window(14u, 20u))),
                    coverage,
                ).any {
                    "without a gap" in
                        it
                },
        )
        assertTrue(
            C2spIndex.inconsistencies(IndexFile(listOf("f"), emptyMap()), coverage).any { "no entry for it" in it },
        )
        val extraLog =
            IndexFile(
                listOf("f"),
                linkedMapOf(
                    a to listOf(IndexEntry(0, Window(10u, 20u))),
                    b to listOf(IndexEntry(0, Window(1u, 2u))),
                ),
            )
        assertTrue(C2spIndex.inconsistencies(extraLog, coverage).any { "does not cover" in it })
        assertTrue(
            C2spIndex.inconsistencies(index(IndexEntry(0, Window(10u, 20u)), names = listOf("f", "g")), coverage).any {
                "not one of the generation's filters" in
                    it
            },
        )
        assertTrue(
            C2spIndex.inconsistencies(index(IndexEntry(0, Window(10u, 20u))), coverage + ("g" to emptyMap())).any {
                "not named" in
                    it
            },
        )
    }
}
