// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

import dev.revokt.engine.seed.parse.TestZip.Companion.DESCRIPTOR
import dev.revokt.engine.seed.parse.TestZip.Companion.STORED
import okio.Buffer
import okio.EOFException
import okio.Source
import java.util.zip.CRC32
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The seed archive reader (spec §6.5 "Seed archive", "Entry names", "Entry caps"; #138), rule by rule. */
class SeedArchiveTest {
    private val seedJson = """{"seedFormat":1}""".encodeToByteArray()
    private val data = ByteArray(5_000) { (it % 7).toByte() }

    /** A well-formed archive of the fixed entries and [attachments], `seed.json` first. */
    private fun fixed(vararg attachments: String): TestZip =
        TestZip().apply {
            add(SeedArchive.SEED_JSON, seedJson, STORED)
            for (name in SeedArchive.FIXED.drop(1)) add(name, "$name body".encodeToByteArray())
            for (name in attachments) add(SeedArchive.ATTACHMENTS + name, data)
        }

    /** An opener over [archives], one per open, the last repeated. */
    private class Opener(
        vararg archives: ByteArray?,
    ) {
        private val queue = archives.toMutableList()
        var opens = 0

        fun open(): Source? {
            opens++
            val next = if (queue.size > 1) queue.removeAt(0) else queue.single()
            return next?.let { Buffer().write(it) }
        }
    }

    private fun open(bytes: ByteArray): SeedArchive = assertNotNull(SeedArchive.open { Buffer().write(bytes) })

    private fun rejects(
        bytes: ByteArray,
        message: String,
    ) {
        val e = assertFailsWith<SeedFormatException> { open(bytes) }
        assertTrue(e.message.orEmpty().contains(message), "${e.message} does not say $message")
    }

    private fun rejectsRead(
        zip: TestZip,
        name: String,
        message: String,
        cap: Long = 1L shl 20,
    ) {
        val archive = open(zip.bytes())
        val e = assertFailsWith<SeedFormatException> { read(archive, name, cap) }
        assertTrue(e.message.orEmpty().contains(message), "${e.message} does not say $message")
    }

    private fun read(
        archive: SeedArchive,
        name: String,
        cap: Long = 1L shl 20,
    ): ByteArray {
        var out: ByteArray? = null
        archive.read(listOf(checkNotNull(archive.entry(name)) to cap)) { _, b -> out = b }
        return checkNotNull(out)
    }

    @Test
    fun `every entry reads back, stored or deflated, in one pass in offset order`() {
        val zip = fixed("a.filter", "b.filter")
        val archive = open(zip.bytes())
        archive.requireFixed()
        val read = LinkedHashMap<String, ByteArray>()
        archive.read(archive.entries.reversed().map { it to (1L shl 20) }) { e, b -> read[e.name] = b }
        assertEquals(zip.entries.map { it.name }, read.keys.toList())
        for (e in zip.entries) assertContentEquals(e.data, read[e.name], e.name)
        assertEquals(
            listOf(
                "attachments/a.filter",
                "attachments/b.filter",
            ),
            archive.attachments(listOf("a.filter", "b.filter")).map {
                it.name
            },
        )
    }

    @Test
    fun `a source that opens null is no archive`() {
        assertNull(SeedArchive.open { null })
    }

    @Test
    fun `the CRC-32 is the zip CRC`() {
        val random = Random(138)
        for (size in listOf(0, 1, 2, 3, 255, 4096, 70_001)) {
            val bytes = random.nextBytes(size)
            assertEquals(CRC32().also { it.update(bytes) }.value, Crc32.of(bytes), "$size bytes")
        }
    }

    @Test
    fun `an entry may carry a data descriptor`() {
        val zip =
            fixed().apply {
                entry(SeedArchive.RECORDS).apply {
                    flags = DESCRIPTOR
                    trailer = ByteArray(16)
                }
            }
        assertContentEquals("records.json body".encodeToByteArray(), read(open(zip.bytes()), SeedArchive.RECORDS))
        val declared =
            fixed().apply {
                entry(SeedArchive.RECORDS).apply {
                    flags = DESCRIPTOR
                    localSize = size ?: 17
                }
            }
        assertContentEquals("records.json body".encodeToByteArray(), read(open(declared.bytes()), SeedArchive.RECORDS))
    }

    @Test
    fun `the end record and central directory are checked`() {
        rejects(ByteArray(21), "no zip archive")
        rejects(fixed().apply { suffix = byteArrayOf(0) }.bytes(), "no end record")
        rejects(fixed().apply { endSignature = 0x06054b51 }.bytes(), "no end record")
        rejects(fixed().apply { disk = 1 }.bytes(), "multi-disk")
        rejects(fixed().apply { directoryDisk = 1 }.bytes(), "multi-disk")
        rejects(fixed().apply { diskEntries = { it - 1 } }.bytes(), "multi-disk")
        rejects(fixed().apply { endCommentLength = 1 }.bytes(), "comment")
    }

    @Test
    fun `the central directory's count, size and offset are checked`() {
        rejects(TestZip().bytes(), "0 entries")
        rejects(
            fixed()
                .apply {
                    totalEntries = { 300 }
                    diskEntries = { 300 }
                }.bytes(),
            "300 entries",
        )
        rejects(fixed().apply { directorySize = { (1L shl 20) + 1 } }.bytes(), "central directory")
        rejects(fixed().apply { directoryOffset = { it + 1 } }.bytes(), "does not end at the end record")
        rejects(
            fixed()
                .apply {
                    directoryOffset = { it + 4 }
                    directorySize = { it - 4 }
                }.bytes(),
            "malformed central",
        )
        rejects(
            fixed()
                .apply {
                    totalEntries = { it + 1 }
                    diskEntries = { it + 1 }
                }.bytes(),
            "malformed central",
        )
        rejects(
            fixed()
                .apply {
                    totalEntries = { it - 1 }
                    diskEntries = { it - 1 }
                }.bytes(),
            "after the last",
        )
        rejects(fixed().apply { entries.last().commentLength = 200 }.bytes(), "truncated central")
        // Bytes no entry covers, before the first entry or before the central directory, are never read.
        assertEquals(5, open(fixed().apply { prefix = ByteArray(9) }.bytes()).entries.size)
        assertEquals(5, open(fixed().apply { gap = ByteArray(3) }.bytes()).entries.size)
    }

    @Test
    fun `an entry is plain, stored or deflated, on disk 0, and inside the archive's data`() {
        rejects(fixed().apply { add(SeedArchive.RECORDS, data) }.bytes(), "duplicate entry")
        rejects(fixed().apply { entry(SeedArchive.RECORDS).flags = 0x0001 }.bytes(), "encrypted")
        rejects(fixed().apply { entry(SeedArchive.RECORDS).flags = 0x0040 }.bytes(), "encrypted")
        rejects(fixed().apply { entry(SeedArchive.RECORDS).flags = 0x2000 }.bytes(), "encrypted")
        rejects(
            fixed()
                .apply {
                    entry(SeedArchive.RECORDS).apply {
                        method = 12
                        compressed = data
                    }
                }.bytes(),
            "neither",
        )
        rejects(fixed().apply { entry(SeedArchive.RECORDS).disk = 1 }.bytes(), "another disk")
        rejects(fixed().apply { entry(SeedArchive.RECORDS).size = 0xFFFF_FFFFL }.bytes(), "zip64")
        rejects(fixed().apply { entry(SeedArchive.RECORDS).compressedSize = 0xFFFF_FFFFL }.bytes(), "zip64")
        rejects(fixed().apply { entry(SeedArchive.RECORDS).offset = { 0xFFFF_FFFFL } }.bytes(), "zip64")
        rejects(fixed().apply { entry(SeedArchive.SEED_JSON).size = 3 }.bytes(), "two sizes")
        rejects(fixed().apply { entry(SeedArchive.INDEX).offset = { it + 4096 } }.bytes(), "past the archive's data")
        assertEquals(
            "\"a\\x0a\\xe9\\x22\\x5c\"",
            printable("a\né\"\\"),
        )
    }

    @Test
    fun `the fixed entries come first, are all there, and nothing else lies outside attachments`() {
        open(fixed().bytes()).requireFixed()

        fun requireFixed(zip: TestZip): String =
            assertFailsWith<SeedFormatException> { open(zip.bytes()).requireFixed() }.message.orEmpty()
        assertTrue("not seed.json" in requireFixed(fixed().apply { directoryOrder = listOf(1, 0, 2, 3, 4) }))
        assertTrue("no index.bin" in requireFixed(fixed().apply { entries.removeAt(4) }))
        for (extra in listOf("/abs", "attachments\\x", "Seed.json", "RECORDS.JSON", "Attachments/a", "x/", "")) {
            assertTrue("extra entry" in requireFixed(fixed().add(extra, data)), extra)
        }
    }

    @Test
    fun `the attachments are exactly the placed filenames, by exact name`() {
        fun attachments(
            zip: TestZip,
            vararg filenames: String,
        ): String =
            assertFailsWith<SeedFormatException> { open(zip.bytes()).attachments(filenames.toList()) }.message.orEmpty()
        for (extra in listOf("../x", "a/b", "./a", "F", "a.filter/", "")) {
            assertTrue(
                "extra entry" in attachments(fixed("a.filter").add("attachments/$extra", data), "a.filter"),
                extra,
            )
        }
        assertTrue("extra entry" in attachments(fixed("F"), "f"))
        assertTrue("no attachments/b" in attachments(fixed("a"), "a", "b"))
    }

    @Test
    fun `a read checks the local header against the central directory`() {
        rejectsRead(
            fixed().apply { entry(SeedArchive.INDEX).offset = { it + 1 } },
            SeedArchive.INDEX,
            "no local header",
        )
        rejectsRead(fixed().apply { entry(SeedArchive.INDEX).localName = "index.bim" }, SeedArchive.INDEX, "differs")
        rejectsRead(fixed().apply { entry(SeedArchive.INDEX).localFlags = DESCRIPTOR }, SeedArchive.INDEX, "differs")
        rejectsRead(fixed().apply { entry(SeedArchive.INDEX).localMethod = STORED }, SeedArchive.INDEX, "differs")
        rejectsRead(fixed().apply { entry(SeedArchive.INDEX).localCrc = 1 }, SeedArchive.INDEX, "other sizes")
        rejectsRead(fixed().apply { entry(SeedArchive.INDEX).localSize = 1 }, SeedArchive.INDEX, "other sizes")
        rejectsRead(
            fixed().apply { entry(SeedArchive.INDEX).localCompressedSize = 1 },
            SeedArchive.INDEX,
            "other sizes",
        )
        val descriptor =
            fixed().apply {
                entry(SeedArchive.INDEX).apply {
                    flags = DESCRIPTOR
                    localSize = 1
                }
            }
        rejectsRead(descriptor, SeedArchive.INDEX, "other sizes")
        // A local extra field is skipped.
        assertContentEquals(
            "index.bin body".encodeToByteArray(),
            read(open(fixed().apply { entry(SeedArchive.INDEX).localExtra = ByteArray(7) }.bytes()), SeedArchive.INDEX),
        )
    }

    @Test
    fun `no two entries overlap, across passes or within one, and none runs into the central directory`() {
        // Across the whole archive, at open: two entries at one offset, read in different passes or not at all.
        val shared = fixed().apply { entry(SeedArchive.INDEX).offset = { 0 } }.bytes()
        assertTrue("overlaps" in assertFailsWith<SeedFormatException> { open(shared) }.message.orEmpty())
        // One byte is enough: index.bin starting one byte before x5u.pem's end (the entries sit back to back).
        val oneByte = fixed().apply { entry(SeedArchive.INDEX).offset = { it - 1 } }.bytes()
        assertTrue("overlaps" in assertFailsWith<SeedFormatException> { open(oneByte) }.message.orEmpty())
        // A stored attachment whose data range holds the whole records.json entry.
        val covering = fixed()
        covering.entries.add(1, TestZip.Entry("attachments/x", ByteArray(400), TestZip.STORED))
        covering.entry(SeedArchive.RECORDS).offset = { it - 300 }
        assertTrue("overlaps" in assertFailsWith<SeedFormatException> { open(covering.bytes()) }.message.orEmpty())
        // Within one pass, the exact end: a local extra field the central directory does not show.
        val extra =
            fixed().apply {
                entry(SeedArchive.X5U).localExtra = ByteArray(12)
                entry(SeedArchive.INDEX).offset = { it - 12 }
            }
        val archive = open(extra.bytes())
        val e =
            assertFailsWith<SeedFormatException> {
                archive.read(listOf(archive.entries[3] to (1L shl 20), archive.entries[4] to (1L shl 20))) { _, _ -> }
            }
        assertTrue("overlaps the entry before it" in e.message.orEmpty(), e.message)
        val long =
            fixed().apply {
                entry(SeedArchive.INDEX).apply {
                    compressedSize = 4096
                    localCompressedSize = 4096
                }
            }
        rejectsRead(long, SeedArchive.INDEX, "runs into the central directory")
    }

    @Test
    fun `an entry inflates under its cap to exactly its declared size and CRC`() {
        val big = ByteArray(100_000)
        // A lying header: a small declared size, a body over the cap.
        rejectsRead(
            fixed().add("attachments/x", big) {
                size = 10
                localSize = 10
            },
            "attachments/x",
            "past its cap",
            cap = 50_000,
        )
        rejectsRead(
            fixed().add("attachments/x", big) {
                size = 10
                localSize = 10
            },
            "attachments/x",
            "holds 100000 bytes",
        )
        rejectsRead(fixed().add("attachments/x", big), "attachments/x", "over its cap", cap = 99_999)
        rejectsRead(fixed().add("attachments/x", big, STORED), "attachments/x", "over its cap", cap = 99_999)
        rejectsRead(
            fixed().add("attachments/x", big) {
                crc = 7
                localCrc = 7
            },
            "attachments/x",
            "CRC-32",
        )
        assertContentEquals(big, read(open(fixed().add("attachments/x", big).bytes()), "attachments/x", cap = 100_000))
        val stream = TestZip.deflate(data)
        rejectsRead(
            fixed().add("attachments/x", data) {
                compressed = stream.copyOf(stream.size - 2)
            },
            "attachments/x",
            "ends early",
        )
        rejectsRead(
            fixed().add("attachments/x", data) {
                compressed = stream + byteArrayOf(1, 2)
            },
            "attachments/x",
            "after the deflate",
        )
        rejectsRead(
            fixed().add("attachments/x", data) {
                compressed = byteArrayOf(-1, -1, -1, -1)
            },
            "attachments/x",
            "malformed deflate",
        )
    }

    @Test
    fun `a second open must give the same archive`() {
        val bytes = fixed().bytes()
        val gone = Opener(bytes, null)
        val archive = assertNotNull(SeedArchive.open(gone::open))
        assertTrue(
            "gone" in assertFailsWith<SeedFormatException> { read(archive, SeedArchive.RECORDS) }.message.orEmpty(),
        )
        val changed = bytes.copyOf().also { it[it.size - 30] = (it[it.size - 30] + 1).toByte() }
        val swapped = assertNotNull(SeedArchive.open(Opener(bytes, changed)::open))
        assertTrue(
            "changed" in assertFailsWith<SeedFormatException> { read(swapped, SeedArchive.RECORDS) }.message.orEmpty(),
        )
        val longer = assertNotNull(SeedArchive.open(Opener(bytes, bytes + byteArrayOf(0))::open))
        assertTrue(
            "grew" in assertFailsWith<SeedFormatException> { read(longer, SeedArchive.RECORDS) }.message.orEmpty(),
        )
        val truncated = assertNotNull(SeedArchive.open(Opener(bytes, bytes.copyOf(40))::open))
        assertFailsWith<EOFException> { read(truncated, SeedArchive.INDEX) }
    }

    @Test
    fun `an archive over its total cap, or one that grows between reads, is too large`() {
        val bytes = fixed().bytes()
        assertNotNull(SeedArchive.open({ Buffer().write(bytes) }, maxBytes = bytes.size.toLong()))
        val e =
            assertFailsWith<SeedTooLargeException> {
                SeedArchive.open(
                    { Buffer().write(bytes) },
                    maxBytes =
                        bytes.size - 1L,
                )
            }
        assertTrue("over its cap" in e.message.orEmpty(), e.message)
        val grown = assertNotNull(SeedArchive.open(Opener(bytes, bytes + ByteArray(100_000))::open))
        assertTrue(
            "grew" in assertFailsWith<SeedTooLargeException> { read(grown, SeedArchive.RECORDS) }.message.orEmpty(),
        )
        assertEquals(256L shl 20, SeedArchive.MAX_BYTES)
    }

    /** The central directory size the end record of [bytes] declares. */
    private fun directorySize(bytes: ByteArray): Long =
        Buffer().write(bytes, bytes.size - 22 + 12, 4).readIntLe().toLong() and 0xFFFF_FFFFL

    /** [zip] with comments added until its central directory is exactly [size] bytes. */
    private fun withDirectory(
        zip: TestZip,
        size: Long,
    ): ByteArray {
        var need = size - directorySize(zip.bytes())
        for (e in zip.entries) {
            val n = minOf(need, 65_535L).toInt()
            e.comment = ByteArray(n)
            need -= n
        }
        check(need == 0L) { "not enough entries" }
        return zip.bytes().also { check(directorySize(it) == size) }
    }

    @Test
    fun `a central directory of 1 MiB opens, and one of 1 MiB + 1 byte is rejected`() {
        val zip = { fixed(*Array(12) { "p$it" }) }
        assertEquals(17, open(withDirectory(zip(), SeedArchive.MAX_DIRECTORY_BYTES)).entries.size)
        rejects(withDirectory(zip(), SeedArchive.MAX_DIRECTORY_BYTES + 1), "central directory")
    }

    @Test
    fun `a read takes only this archive's entries`() {
        val archive = open(fixed().bytes())
        val other = open(fixed().bytes())
        assertFailsWith<IllegalArgumentException> { archive.read(listOf(other.entries[0] to 1L)) { _, _ -> } }
        assertFailsWith<IllegalArgumentException> { archive.read(listOf(archive.entries[0] to -1L)) { _, _ -> } }
    }
}
