// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.ClubcardCorpus
import dev.revokt.CrliteChannel
import dev.revokt.DiagnosticCode
import dev.revokt.SyncStage
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.update.UpdateFixtures.deltaRecord
import dev.revokt.engine.update.UpdateFixtures.fullRecord
import dev.revokt.engine.update.UpdateFixtures.log
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/** `buildIndex(records, channel)` (#130, spec §3.2, §6.5 seed archive and file names). */
class BuildIndexTest {
    private fun refused(build: IndexBuild): IndexBuild.Refused = assertIs<IndexBuild.Refused>(build)

    private fun v4(
        vararg logs: Int,
        low: Long = 1_000,
        high: Long = 2_000,
    ): ByteArray = UpdateFixtures.v4(logs.map { log(it) to (low to high) })

    @Test
    fun `the compat records build an index, full first, that C2SP reads and the consistency check passes`() {
        val built = UpdateFixtures.built(listOf(deltaRecord, fullRecord))
        assertEquals(listOf(fullRecord.id, deltaRecord.id), built.filters.map { it.record.id })
        assertEquals(listOf(true, false), built.filters.map { it.full })
        val index = C2spIndex.read(built.index)
        assertEquals(listOf(fullRecord.filename, deltaRecord.filename), index.filenames)
        val coverage =
            mapOf(
                fullRecord.filename to ClubcardCorpus.coverage(UpdateFixtures.bodies.getValue(fullRecord.filename)),
                deltaRecord.filename to ClubcardCorpus.coverage(UpdateFixtures.bodies.getValue(deltaRecord.filename)),
            )
        assertEquals(emptyList(), C2spIndex.inconsistencies(index, coverage))
    }

    @Test
    fun `the compat index bytes are the committed seedFormat 1 golden`() {
        // §6.5: buildIndex's output bytes are frozen per seedFormat; a change to them bumps seedFormat.
        val golden =
            assertNotNull(javaClass.getResourceAsStream("seed-format-1-compat.index.bin")).use { it.readBytes() }
        assertContentEquals(golden, UpdateFixtures.built(listOf(fullRecord, deltaRecord)).index)
        assertContentEquals(golden, UpdateFixtures.built(listOf(deltaRecord, fullRecord)).index)
    }

    @Test
    fun `deltas are ordered by effective timestamp, then record id, after the full`() {
        val records =
            listOf(
                FilterRecord("d-b", "compat", true, 30, "b.delta"),
                FilterRecord("d-a", "compat", true, 30, "a2.delta"),
                FilterRecord("d-c", "compat", true, 20, "c.delta"),
                FilterRecord("f", "compat", false, 40, "full.filter"),
            )
        val bodies = records.mapIndexed { i, r -> r.filename to v4(i) }.toMap()
        val built = UpdateFixtures.built(records, bodies)
        assertEquals(listOf("f", "d-c", "d-a", "d-b"), built.filters.map { it.record.id })
        assertEquals(
            listOf("full.filter", "c.delta", "a2.delta", "b.delta"),
            C2spIndex.read(built.index).filenames,
        )
    }

    @Test
    fun `only the channel's records are placed`() {
        val other = FilterRecord("x", "default", false, 1, "default.filter")
        val otherDelta = FilterRecord("y", "default", true, 2, "default.delta")
        val bodies = UpdateFixtures.bodies + mapOf(other.filename to v4(1), otherDelta.filename to v4(2))
        val read = mutableListOf<String>()
        val built =
            assertIs<IndexBuild.Built>(
                buildIndex(listOf(other, fullRecord, otherDelta, deltaRecord), CrliteChannel.COMPAT) {
                    read += it.id
                    bodies.getValue(it.filename)
                },
            )
        assertEquals(listOf(fullRecord.id, deltaRecord.id), built.filters.map { it.record.id })
        assertEquals(listOf(fullRecord.id, deltaRecord.id), read)
        val defaults = UpdateFixtures.build(listOf(other, fullRecord, otherDelta), bodies, CrliteChannel.DEFAULT)
        assertEquals(listOf("x", "y"), assertIs<IndexBuild.Built>(defaults).filters.map { it.record.id })
    }

    @Test
    fun `a channel with no full filter, or two, builds nothing and reads no body`() {
        val second = FilterRecord("f2", "compat", false, 2, "second.filter")
        for (records in listOf(listOf(deltaRecord), listOf(fullRecord, second, deltaRecord), emptyList())) {
            val r = refused(buildIndex(records, CrliteChannel.COMPAT) { error("read ${it.id}") })
            assertEquals(IndexRefusal.FULL_COUNT, r.reason, "$records")
            assertEquals(SyncStage.INDEX, r.stage)
            assertEquals(DiagnosticCode.INDEX_INCONSISTENT, r.code)
        }
        assertEquals(
            IndexRefusal.FULL_COUNT,
            refused(UpdateFixtures.build(listOf(fullRecord), channel = CrliteChannel.DEFAULT)).reason,
        )
    }

    @Test
    fun `33- and 64-character attachment filenames are placed under their 32-character derived names`() {
        val long33 = "20261021-123-compat.filter.delta" + "x"
        val long64 = "20261017-1-compat-full-filter-with-a-very-long-name-0123456.filt"
        assertEquals(33, long33.length)
        assertEquals(64, long64.length)
        val full = FilterRecord("f", "compat", false, 1, long64)
        val delta = FilterRecord("d", "compat", true, 2, long33)
        val bodies = mapOf(long64 to v4(1), long33 to v4(2))
        val built = UpdateFixtures.built(listOf(full, delta), bodies)
        val names = listOf(GenerationNames.derive(long64), GenerationNames.derive(long33))
        assertEquals(listOf(32, 32), names.map { it.length })
        assertEquals(listOf(long64.take(15) + "-", long33.take(15) + "-"), names.map { it.take(16) })
        assertEquals(names, built.filters.map { it.name })
        assertEquals(names, C2spIndex.read(built.index).filenames)
    }

    @Test
    fun `two attachments that map to one name are INDEX_INCONSISTENT before any body is read`() {
        val long = "20261017-1-compat-full-filter-with-a-very-long-name-0123456.filt"
        val derived = GenerationNames.derive(long)
        val cases =
            listOf(
                listOf(FilterRecord("f", "compat", false, 1, long), FilterRecord("d", "compat", true, 2, derived)),
                listOf(FilterRecord("f", "compat", false, 1, "same"), FilterRecord("d", "compat", true, 2, "same")),
                listOf(FilterRecord("f", "compat", false, 1, "index.bin")),
                listOf(FilterRecord("f", "compat", false, 1, "a"), FilterRecord("d", "compat", true, 2, "meta.json")),
                listOf(FilterRecord("f", "compat", false, 1, "records.json")),
            )
        for (records in cases) {
            val r = refused(buildIndex(records, CrliteChannel.COMPAT) { error("read ${it.id}") })
            assertEquals(IndexRefusal.NAME_COLLISION, r.reason, "$records")
            assertEquals(SyncStage.INDEX, r.stage)
            assertEquals(DiagnosticCode.INDEX_INCONSISTENT, r.code)
        }
    }

    @Test
    fun `an index of exactly 1 MiB builds and the next larger one is refused before it is written`() {
        // 14 + 32 x 4 filenames + 42 x 17473 logs + 18 x (17473 + 3) entries = 1048576 bytes. Every size is even, so
        // 1 MiB + 1 cannot be built; one more log in the full adds 60 bytes.
        fun records(logs: Int): Pair<List<FilterRecord>, Map<String, ByteArray>> {
            val records =
                listOf(FilterRecord("f", "compat", false, 1, "full")) +
                    (1..3).map { FilterRecord("d$it", "compat", true, 1L + it, "delta$it") }
            val bodies =
                mapOf("full" to UpdateFixtures.v4((0 until logs).map { log(it) to (1L to 2L) })) +
                    (1..3).associate { "delta$it" to v4(0) }
            return records to bodies
        }
        val (atCap, atCapBodies) = records(17_473)
        val built = UpdateFixtures.built(atCap, atCapBodies)
        assertEquals(C2spIndex.MAX_BYTES, built.index.size)
        C2spIndex.read(built.index)
        val (over, overBodies) = records(17_474)
        val r = refused(UpdateFixtures.build(over, overBodies))
        assertEquals(IndexRefusal.OVER_CAP, r.reason)
        assertEquals(SyncStage.INDEX, r.stage)
        assertEquals(DiagnosticCode.INDEX_INCONSISTENT, r.code)
        assertEquals("index.bin would be 1048636 bytes, over 1048576", r.detail)
    }

    @Test
    fun `a filter that does not decode is refused at PREPARE, with the decoder's error`() {
        val bodies = UpdateFixtures.bodies + (deltaRecord.filename to byteArrayOf(4, 0, 0))
        val r = refused(UpdateFixtures.build(listOf(fullRecord, deltaRecord), bodies))
        assertEquals(IndexRefusal.FILTER_UNREADABLE, r.reason)
        assertEquals(SyncStage.PREPARE, r.stage)
        assertEquals(null, r.code)
        assertNotNull(r.cause)
    }

    @Test
    fun `a record's filename passes the 6_3 rule and its id is not empty`() {
        assertFailsWith<IllegalArgumentException> { FilterRecord("", "compat", false, 1, "a") }
        for (bad in listOf("", ".", "..", "a/b", "a".repeat(65), "é")) {
            assertFailsWith<IllegalArgumentException>(bad) { FilterRecord("f", "compat", false, 1, bad) }
        }
        assertEquals("FilterRecord(f, compat, full, 1, a)", FilterRecord("f", "compat", false, 1, "a").toString())
    }

    @Test
    fun `byteSize is the length write produces`() {
        val built = UpdateFixtures.built(listOf(fullRecord, deltaRecord))
        val index = C2spIndex.read(built.index)
        assertEquals(built.index.size.toLong(), C2spIndex.byteSize(index))
        assertEquals(14L, C2spIndex.byteSize(C2spIndex.index(emptyList())))
    }
}
