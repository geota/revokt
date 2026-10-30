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

    /** One directory row of [raw]: the log, where its section starts and how many entries it declares. */
    private class Row(
        val logId: ByteString,
        val offset: Long,
        val count: Int,
    )

    /** An index laid out by hand: [names], the directory [rows], and [entries] placed at their offsets, [size] bytes long. */
    private fun raw(
        names: List<String>,
        rows: List<Row>,
        size: Int,
        entries: Map<Int, List<IndexEntry>> = emptyMap(),
    ): ByteArray {
        val out = ByteArray(size)
        "upkiidx1".encodeToByteArray().copyInto(out)
        out[8] = (names.size ushr 8).toByte()
        out[9] = names.size.toByte()
        for (i in 0 until 4) out[10 + i] = (rows.size ushr (8 * (3 - i))).toByte()
        names.forEachIndexed { i, n -> n.encodeToByteArray().copyInto(out, 14 + 32 * i) }
        rows.forEachIndexed { i, r ->
            val at = 14 + 32 * names.size + 42 * i
            r.logId.toByteArray().copyInto(out, at)
            for (k in 0 until 8) out[at + 32 + k] = (r.offset ushr (8 * (7 - k))).toByte()
            out[at + 40] = (r.count ushr 8).toByte()
            out[at + 41] = r.count.toByte()
        }
        for ((offset, list) in entries) {
            list.forEachIndexed { k, e ->
                val at = offset + 18 * k
                out[at] = (e.filterIndex ushr 8).toByte()
                out[at + 1] = e.filterIndex.toByte()
                for (j in 0 until 8) out[at + 2 + j] = (e.window.low shr (8 * (7 - j))).toByte()
                for (j in 0 until 8) out[at + 10 + j] = (e.window.high shr (8 * (7 - j))).toByte()
            }
        }
        return out
    }

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
    fun `the header and the cap are checked`() {
        assertMalformed(ByteArray(13), "shorter than its 14-byte header")
        assertMalformed(built().also { it[7] = '0'.code.toByte() }, "magic upkiidx1")
        assertMalformed(built().copyOf(14 + 32), "more than its")
        assertMalformed("upkiidx1".encodeToByteArray() + ByteArray(C2spIndex.MAX_BYTES), "over the")
    }

    @Test
    fun `filenames are checked one by one, and a name may repeat as upki writes it`() {
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
        assertMalformed(built().also { it[14 + 10] = 'x'.code.toByte() }, "zero-padded")
        assertEquals("A".repeat(32), C2spIndex.read(withName("A".repeat(32).encodeToByteArray())).filenames[0])
        assertEquals(listOf("delta", "delta"), C2spIndex.read(withName("delta".encodeToByteArray())).filenames)
    }

    @Test
    fun `the log directory must be sorted without duplicates`() {
        val dir = 14 + 32 * 2
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
        assertMalformed(built().also { it.copyInto(it, dir + 42, dir, dir + 32) }, "not sorted")
    }

    @Test
    fun `a section must lie inside the file, after the tables`() {
        val tables = 14 + 32 + 42
        val e = listOf(IndexEntry(0, Window(1u, 2u)))
        assertMalformed(raw(listOf("f"), listOf(Row(a, 20, 1)), tables + 18, mapOf(tables to e)), "not inside the file")
        assertMalformed(raw(listOf("f"), listOf(Row(a, tables.toLong() + 1, 1)), tables + 18), "not inside the file")
        assertMalformed(raw(listOf("f"), listOf(Row(a, Long.MAX_VALUE, 1)), tables + 18), "not inside the file")
        assertMalformed(raw(listOf("f"), listOf(Row(a, -1, 1)), tables + 18), "not inside the file")
        assertMalformed(
            raw(listOf("f"), listOf(Row(a, tables.toLong() + 19, 0)), tables + 18),
            "past the end of the file",
        )
    }

    @Test
    fun `overlapping sections are rejected before any entry is read`() {
        // Many logs pointing at one section of many entries: rejected from the directory alone, so it allocates no entries.
        val logs = 2000
        val tables = 14 + 32 + 42 * logs
        val count = 20000 // under the cap, so the overlap, not the size, is what rejects it
        val rows =
            (0 until logs).map {
                Row(
                    ByteArray(32) { k ->
                        if (k <
                            2
                        ) {
                            (it ushr (8 * (1 - k))).toByte()
                        } else {
                            0
                        }
                    }.toByteString(),
                    tables.toLong(),
                    count,
                )
            }
        assertMalformed(raw(listOf("f"), rows, tables + 18 * count), "overlap")
        assertMalformed(
            built().also {
                val dir =
                    14 + 64
                it.copyInto(it, dir + 42 + 32, dir + 32, dir + 40)
            },
            "overlap",
        )
    }

    @Test
    fun `sections out of directory order, with gaps, empty sections and trailing bytes are accepted`() {
        val tables = 14 + 32 * 2 + 42 * 3
        val e0 = listOf(IndexEntry(0, Window(1u, 2u)))
        val e1 = listOf(IndexEntry(1, Window(3u, 4u)), IndexEntry(0, Window(5u, 6u)))
        val bytes =
            raw(
                listOf("f", "g"),
                listOf(Row(a, tables.toLong() + 100, 1), Row(b, tables.toLong(), 0), Row(c, tables.toLong() + 10, 2)),
                tables + 300,
                mapOf(tables + 100 to e0, tables + 10 to e1),
            )
        val index = C2spIndex.read(bytes)
        assertEquals(mapOf(a to e0, b to emptyList(), c to e1), index.logs)
        assertEquals(index, C2spIndex.read(C2spIndex.write(index)))
    }

    @Test
    fun `an empty section may sit at any offset in the file, even inside the tables`() {
        val tables = 14 + 32 + 42
        for (offset in listOf(0L, 20L, tables.toLong(), tables.toLong() + 18)) {
            assertEquals(
                mapOf(a to emptyList()),
                C2spIndex.read(raw(listOf("f"), listOf(Row(a, offset, 0)), tables + 18)).logs,
                "offset $offset",
            )
        }
    }

    @Test
    fun `an entry reaching past its window is outside it, not a gap`() {
        val w = Window(10u, 20u)
        val index = IndexFile(listOf("f"), linkedMapOf(a to listOf(IndexEntry(0, Window(5u, 25u)))))
        assertEquals(
            listOf(IndexMismatch.OutsideWindow("f", a, Window(5u, 25u), w)),
            C2spIndex.inconsistencies(
                index,
                mapOf("f" to mapOf(a to w)),
            ),
        )
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
    fun `the writer refuses names a reader would reject, and a name twice`() {
        assertFailsWith<IllegalArgumentException> { C2spIndex.index(listOf("x".repeat(33) to emptyMap())) }
        assertFailsWith<IllegalArgumentException> { C2spIndex.index(listOf("a" to emptyMap(), "a" to emptyMap())) }
    }

    @Test
    fun `an index revokt built is consistent with its filters' coverage`() {
        assertEquals(emptyList(), C2spIndex.inconsistencies(C2spIndex.read(built()), filters.toMap()))
    }

    @Test
    fun `split, duplicated and nested entries that cover a window exactly are consistent`() {
        val cover = mapOf("f" to mapOf(a to Window(10u, ULong.MAX_VALUE)))

        fun index(vararg w: Window) = IndexFile(listOf("f"), linkedMapOf(a to w.map { IndexEntry(0, it) }))
        assertEquals(
            emptyList(),
            C2spIndex.inconsistencies(index(Window(10u, 14u), Window(15u, ULong.MAX_VALUE)), cover),
        )
        assertEquals(
            emptyList(),
            C2spIndex.inconsistencies(index(Window(10u, ULong.MAX_VALUE), Window(10u, ULong.MAX_VALUE)), cover),
        )
        assertEquals(
            emptyList(),
            C2spIndex.inconsistencies(index(Window(10u, ULong.MAX_VALUE), Window(20u, 30u)), cover),
        )
    }

    @Test
    fun `empty windows cover nothing, on either side`() {
        val inverted = Window(20u, 10u)
        val cover = mapOf("f" to mapOf(a to inverted))
        assertEquals(
            emptyList(),
            C2spIndex.inconsistencies(
                IndexFile(
                    listOf("f"),
                    linkedMapOf(a to listOf(IndexEntry(0, inverted))),
                ),
                cover,
            ),
        )
        assertEquals(emptyList(), C2spIndex.inconsistencies(IndexFile(listOf("f"), emptyMap()), cover))
        assertEquals(
            listOf(IndexMismatch.OutsideWindow("f", a, Window(1u, 2u), inverted)),
            C2spIndex.inconsistencies(
                IndexFile(listOf("f"), linkedMapOf(a to listOf(IndexEntry(0, Window(1u, 2u))))),
                cover,
            ),
        )
    }

    @Test
    fun `each kind of mismatch is reported exactly`() {
        val w = Window(10u, 20u)
        val cover = mapOf("f" to mapOf(a to w))

        fun index(
            vararg entries: IndexEntry,
            names: List<String> = listOf("f"),
        ) = IndexFile(
            names,
            linkedMapOf(a to entries.toList()),
        )
        assertEquals(
            listOf(IndexMismatch.OutsideWindow("f", a, Window(10u, 21u), w)),
            C2spIndex.inconsistencies(index(IndexEntry(0, Window(10u, 21u))), cover),
        )
        assertEquals(
            listOf(IndexMismatch.Gap("f", a, w)),
            C2spIndex.inconsistencies(index(IndexEntry(0, Window(10u, 19u))), cover),
        )
        assertEquals(
            listOf(IndexMismatch.Gap("f", a, w)),
            C2spIndex.inconsistencies(index(IndexEntry(0, Window(10u, 12u)), IndexEntry(0, Window(14u, 20u))), cover),
        )
        assertEquals(
            listOf(IndexMismatch.MissingEntry("f", a)),
            C2spIndex.inconsistencies(IndexFile(listOf("f"), emptyMap()), cover),
        )
        val extraLog =
            IndexFile(
                listOf("f"),
                linkedMapOf(
                    a to listOf(IndexEntry(0, w)),
                    b to listOf(IndexEntry(0, Window(1u, 2u))),
                ),
            )
        assertEquals(listOf(IndexMismatch.UncoveredLog("f", b)), C2spIndex.inconsistencies(extraLog, cover))
        assertEquals(
            listOf(IndexMismatch.UnknownName("g")),
            C2spIndex.inconsistencies(index(IndexEntry(0, w), names = listOf("f", "g")), cover),
        )
        assertEquals(
            listOf(IndexMismatch.NotNamed("g")),
            C2spIndex.inconsistencies(
                index(IndexEntry(0, w)),
                cover + ("g" to emptyMap()),
            ),
        )
        // A filter whose coverage is empty but which has entries.
        val emptyCoverage = IndexFile(listOf("f"), linkedMapOf(a to listOf(IndexEntry(0, w))))
        assertEquals(
            listOf(IndexMismatch.UncoveredLog("f", a)),
            C2spIndex.inconsistencies(
                emptyCoverage,
                mapOf("f" to emptyMap()),
            ),
        )
    }
}
