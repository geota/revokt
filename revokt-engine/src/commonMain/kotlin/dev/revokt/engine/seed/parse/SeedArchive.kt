// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

import dev.revokt.RevoktLimits
import okio.Buffer
import okio.BufferedSource
import okio.ByteString
import okio.Source
import okio.buffer
import okio.use

/** A seed archive that is not one this reader accepts: `SEED_UNREADABLE` (spec §6.5). */
internal open class SeedFormatException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/** An archive over its total cap ([SeedArchive.MAX_BYTES]), or one that grew between reads: a source that may not end. */
internal class SeedTooLargeException(
    message: String,
) : SeedFormatException(message)

/**
 * One central-directory entry of a seed archive, as declared: [name] is its bytes read as ISO-8859-1, so only a byte-equal
 * ASCII name equals an expected one; the sizes and [crc32] are unsigned and untrusted until the entry is read.
 */
internal class ZipEntry(
    val name: String,
    val method: Int,
    val flags: Int,
    val crc32: Long,
    val compressedSize: Long,
    val size: Long,
    val localOffset: Long,
) {
    override fun toString(): String = "ZipEntry(${printable(name)}, method $method, $size bytes at $localOffset)"
}

/**
 * A seed archive (spec §6.5 "Seed archive", "Entry names", "Entry caps") read over an [opener] that gives a fresh
 * stream on every call ([dev.revokt.SeedSource.open]). The reader never derives a name or a path from an entry and never
 * writes an entry anywhere: it looks entries up by exact name and returns their bytes, each capped while it is inflated.
 *
 * **One pass per read.** The stream is not seekable, so [open] reads it once to its end for the end record and the
 * central directory (the last [MAX_DIRECTORY_BYTES] and the end record kept, nothing else), and each [read] streams it
 * again, skipping to each wanted entry in offset order and reading the rest to the end, where the archive's size and
 * central directory must equal [open]'s, or the archive changed between reads. Memory stays one entry, whatever the
 * archive's size.
 *
 * **What it accepts**, narrower than zip and failing closed (each a [SeedFormatException]): one disk, no zip64, an end
 * record with no comment as the archive's last bytes, right after the central directory; at most [maxEntries] entries,
 * no duplicate name, none encrypted, each stored or deflated (a stored one's sizes equal), its local header naming the
 * same file with the same method and flags (and, without a data descriptor, the same CRC and sizes), its data ending
 * before the central directory, and no two entries overlapping anywhere in the archive; an entry inflates to exactly its declared size and
 * CRC-32. The caps are enforced while inflating: a declared size is never trusted to bound one.
 */
internal class SeedArchive private constructor(
    private val opener: () -> Source?,
    private val archiveSize: Long,
    private val directoryOffset: Long,
    private val directory: ByteString,
    val entries: List<ZipEntry>,
) {
    private val byName: Map<String, ZipEntry> = entries.associateBy { it.name }

    /** The entry named exactly [name], or null. */
    fun entry(name: String): ZipEntry? = byName[name]

    /**
     * Spec §6.5's check before any entry but `seed.json` is read: the first entry is `seed.json`, every fixed entry is
     * present, and every other name is under `attachments/` (any other, a case variant or a directory entry included, is
     * extra).
     */
    fun requireFixed() {
        val first = entries.first()
        if (first.name != SEED_JSON) fail("the first entry is ${printable(first.name)}, not $SEED_JSON")
        for (name in FIXED) if (name !in byName) fail("no $name entry")
        entries.firstOrNull { it.name !in FIXED && !it.name.startsWith(ATTACHMENTS) }?.let {
            fail("an extra entry ${printable(it.name)}")
        }
    }

    /**
     * The `attachments/<f>` entry of each of [filenames], in their order: spec §6.5's check once `records.json` is
     * verified and before any attachment is inflated. Every entry under `attachments/` must be one of them, and each
     * of them must be present.
     */
    fun attachments(filenames: List<String>): List<ZipEntry> {
        val expected = filenames.mapTo(LinkedHashSet()) { ATTACHMENTS + it }
        entries.firstOrNull { it.name.startsWith(ATTACHMENTS) && it.name !in expected }?.let {
            fail("an extra entry ${printable(it.name)}")
        }
        return expected.map { byName[it] ?: fail("no $it entry") }
    }

    /**
     * Streams the archive once and gives [consume] the bytes of each of [wanted] (an entry of this archive and its cap),
     * in offset order, each inflated under its cap; then reads to the end and checks the archive is the one [open]
     * read. A null stream, a truncated one ([okio.EOFException]) and any rejected structure throw.
     */
    fun read(
        wanted: List<Pair<ZipEntry, Long>>,
        consume: (ZipEntry, ByteArray) -> Unit,
    ) {
        for ((entry, cap) in wanted) require(byName[entry.name] === entry && cap >= 0) { "not this archive's: $entry" }
        val source = opener() ?: fail("the archive is gone on a second open")
        source.buffer().use { s ->
            val pass = Pass(s)
            for ((entry, cap) in wanted.sortedBy { it.first.localOffset }) consume(entry, pass.entry(entry, cap))
            pass.finish()
        }
    }

    /** One streaming read of the archive, at [position]. */
    private inner class Pass(
        private val s: BufferedSource,
    ) {
        private var position = 0L

        fun entry(
            entry: ZipEntry,
            cap: Long,
        ): ByteArray {
            if (entry.localOffset < position) fail("${printable(entry.name)} overlaps the entry before it")
            skip(entry.localOffset - position)
            if (u32() != LOCAL_SIGNATURE) fail("no local header for ${printable(entry.name)}")
            u16() // version needed to extract
            val flags = u16()
            val method = u16()
            u32() // time and date
            val crc = u32()
            val compressed = u32()
            val size = u32()
            val nameLength = u16()
            val extraLength = u16()
            val name = latin1(bytes(nameLength.toLong()))
            if (name != entry.name || flags != entry.flags || method != entry.method) {
                fail("the local header of ${printable(entry.name)} differs from its central-directory entry")
            }
            val declared = listOf(crc to entry.crc32, compressed to entry.compressedSize, size to entry.size)
            // With a data descriptor (bit 3) the local header may leave the CRC and sizes zero.
            if (declared.any { (local, central) -> local != central && ((flags and DESCRIPTOR) == 0 || local != 0L) }) {
                fail("the local header of ${printable(entry.name)} declares other sizes")
            }
            skip(extraLength.toLong())
            if (position + entry.compressedSize > directoryOffset) {
                fail("${printable(entry.name)} runs into the central directory")
            }
            if (entry.size > cap) fail("${printable(entry.name)} declares ${entry.size} bytes, over its cap of $cap")
            val bytes = if (method == STORED) bytes(entry.compressedSize) else inflate(entry, cap)
            if (bytes.size.toLong() != entry.size) {
                fail("${printable(entry.name)} holds ${bytes.size} bytes, not the ${entry.size} it declares")
            }
            if (Crc32.of(bytes) != entry.crc32) fail("${printable(entry.name)} fails its CRC-32")
            return bytes
        }

        /** [entry]'s deflate stream, exactly its compressed size, inflated under [cap] (spec §6.5 "Entry caps"). */
        private fun inflate(
            entry: ZipEntry,
            cap: Long,
        ): ByteArray {
            val inflater = rawInflater()
            try {
                return inflate(inflater, entry, cap)
            } finally {
                inflater.end()
            }
        }

        private fun inflate(
            inflater: RawInflater,
            entry: ZipEntry,
            cap: Long,
        ): ByteArray {
            val out = Buffer()
            val chunk = ByteArray(CHUNK.toInt())
            var left = entry.compressedSize
            // An inflater may hold output it has not given out yet with its input all consumed, so input is fed only
            // once it gives nothing.
            var n = inflater.inflate(chunk, 0, chunk.size)
            while (n > 0 || !inflater.finished) {
                if (n > 0) {
                    if (out.size + n > cap) fail("${printable(entry.name)} inflates past its cap of $cap bytes")
                    out.write(chunk, 0, n)
                } else {
                    if (!inflater.needsInput) fail("the deflate stream of ${printable(entry.name)} stalls")
                    if (left == 0L) fail("the deflate stream of ${printable(entry.name)} ends early")
                    val input = bytes(minOf(left, CHUNK))
                    left -= input.size
                    inflater.setInput(input, 0, input.size)
                }
                n = inflater.inflate(chunk, 0, chunk.size)
            }
            val trailing = left != 0L || inflater.remaining != 0
            if (trailing) fail("bytes after the deflate stream of ${printable(entry.name)}")
            return out.readByteArray()
        }

        /** Reads to the end: the archive must be [open]'s, its size and central directory unchanged. */
        fun finish() {
            val tail = Buffer()
            while (true) {
                val n = s.read(tail, CHUNK)
                if (n == -1L) break
                position += n
                // A source that grew may not end: stop at the first byte past the size the first pass read.
                if (position > archiveSize) throw SeedTooLargeException("the archive grew between reads")
                if (tail.size > directory.size) tail.skip(tail.size - directory.size)
            }
            if (position != archiveSize || tail.readByteString() != directory) fail("the archive changed between reads")
        }

        private fun skip(n: Long) {
            s.skip(n)
            position += n
        }

        private fun bytes(n: Long): ByteArray = s.readByteArray(n).also { position += n }

        private fun u16(): Int = (s.readShortLe().toInt() and 0xFFFF).also { position += 2 }

        private fun u32(): Long = (s.readIntLe().toLong() and 0xFFFF_FFFFL).also { position += 4 }
    }

    companion object {
        const val SEED_JSON: String = "seed.json"
        const val RECORDS: String = "records.json"
        const val SIGNATURE: String = "signature"
        const val X5U: String = "x5u.pem"
        const val INDEX: String = "index.bin"
        const val ATTACHMENTS: String = "attachments/"

        /** Spec §6.5's fixed entries. */
        val FIXED: Set<String> = linkedSetOf(SEED_JSON, RECORDS, SIGNATURE, X5U, INDEX)

        /**
         * The most entries an archive may hold: the fixed ones and one attachment per record the channel may hold
         * (`MAX_CHANGESET_RECORDS`, after channel filtering); any more is necessarily an extra entry.
         */
        val maxEntries: Int get() = FIXED.size + RevoktLimits.MAX_CHANGESET_RECORDS

        /**
         * The most bytes an archive may hold (the coordinator's decision on #138): about 3.7 times the most a channel
         * holds today (a 6 MB full and 255 deltas of about 242 KB, §6.4), so a source that never ends fails closed.
         */
        const val MAX_BYTES: Long = 256L shl 20

        /** The most bytes the central directory may take: a real seed's takes about 40 KiB. */
        const val MAX_DIRECTORY_BYTES: Long = 1L shl 20

        private const val END_BYTES = 22L
        private const val CENTRAL_BYTES = 46L
        private const val LOCAL_BYTES = 30L
        private const val END_SIGNATURE = 0x06054b50L
        private const val CENTRAL_SIGNATURE = 0x02014b50L
        private const val LOCAL_SIGNATURE = 0x04034b50L
        private const val STORED = 0
        private const val DEFLATED = 8
        private const val DESCRIPTOR = 0x0008

        /** Traditional encryption (bit 0), strong encryption (bit 6) and a masked central directory (bit 13). */
        private const val ENCRYPTED = 0x0001 or 0x0040 or 0x2000
        private const val ZIP64 = 0xFFFF_FFFFL
        private const val CHUNK = 8192L

        /**
         * The archive [opener] opens, its end record and central directory read and checked, or null when [opener]
         * opens none. The stream is read to its end, once; an I/O failure is the caller's (an unreadable seed).
         */
        fun open(opener: () -> Source?): SeedArchive? = open(opener, MAX_BYTES)

        /** [open] with the total cap [maxBytes] in place of [MAX_BYTES]. */
        fun open(
            opener: () -> Source?,
            maxBytes: Long,
        ): SeedArchive? {
            val source = opener() ?: return null
            val (size, tail) = source.use { readToEnd(it, maxBytes) }
            val end = End.read(tail, size)
            val directory = Buffer().also { tail.copyTo(it, tail.size - END_BYTES - end.size, end.size) }
            val bytes = directory.snapshot()
            val entries = ArrayList<ZipEntry>(end.count)
            val names = HashSet<String>()
            repeat(end.count) {
                val entry = central(directory, end.offset)
                if (!names.add(entry.name)) fail("a duplicate entry ${printable(entry.name)}")
                entries += entry
            }
            if (!directory.exhausted()) fail("bytes after the last central-directory entry")
            requireDisjoint(entries)
            val whole = Buffer().write(bytes)
            tail.copyTo(whole, tail.size - END_BYTES, END_BYTES)
            return SeedArchive(opener, size, end.offset, whole.readByteString(), entries)
        }

        /** [source] read to its end: its size, and its last [MAX_DIRECTORY_BYTES] and end record. */
        private fun readToEnd(
            source: Source,
            maxBytes: Long,
        ): Pair<Long, Buffer> {
            var size = 0L
            val tail = Buffer()
            while (true) {
                val n = source.read(tail, CHUNK)
                if (n == -1L) break
                size += n
                if (size > maxBytes) throw SeedTooLargeException("the archive is over its cap of $maxBytes bytes")
                val keep = MAX_DIRECTORY_BYTES + END_BYTES
                if (tail.size > keep) tail.skip(tail.size - keep)
            }
            return size to tail
        }

        /** The end record: the central directory's entry [count], [size] and [offset], checked against the archive. */
        private class End(
            val count: Int,
            val size: Long,
            val offset: Long,
        ) {
            companion object {
                /** The end record in the last bytes of [tail], an archive of [archiveSize] bytes. */
                fun read(
                    tail: Buffer,
                    archiveSize: Long,
                ): End {
                    if (archiveSize < END_BYTES) fail("$archiveSize bytes is no zip archive")
                    val end = Buffer().also { tail.copyTo(it, tail.size - END_BYTES, END_BYTES) }
                    if (end.u32() !=
                        END_SIGNATURE
                    ) {
                        fail("no end record in the last $END_BYTES bytes (a comment, or not a zip)")
                    }
                    val disk = end.u16()
                    val directoryDisk = end.u16()
                    val diskEntries = end.u16()
                    val count = end.u16()
                    val size = end.u32()
                    val offset = end.u32()
                    val comment = end.u16()
                    if (disk != 0 || directoryDisk != 0 || diskEntries != count) fail("a multi-disk archive")
                    if (comment != 0) fail("an end record with a comment")
                    if (count == 0 || count > maxEntries) fail("$count entries, not 1 to $maxEntries")
                    if (size > MAX_DIRECTORY_BYTES) fail("a $size-byte central directory")
                    if (offset + size != archiveSize - END_BYTES) {
                        fail("the central directory does not end at the end record (zip64, or bytes between them)")
                    }
                    return End(count, size, offset)
                }
            }
        }

        /**
         * No two entries overlap, across the whole archive and not only within one pass: in offset order each starts at
         * or after the end of the one before, its local header with the central directory's name, then its data (a
         * lower bound of the end, since a local extra field and a data descriptor are known only once read; within a
         * pass the reader checks the exact end).
         */
        private fun requireDisjoint(entries: List<ZipEntry>) {
            var end = 0L
            var before: ZipEntry? = null
            for (e in entries.sortedBy { it.localOffset }) {
                if (e.localOffset < end) fail("${printable(e.name)} overlaps ${before?.let { printable(it.name) }}")
                end = e.localOffset + LOCAL_BYTES + e.name.length + e.compressedSize
                before = e
            }
        }

        /** The next central-directory entry of [directory], which starts at [directoryOffset] in the archive. */
        private fun central(
            directory: Buffer,
            directoryOffset: Long,
        ): ZipEntry {
            if (directory.size < CENTRAL_BYTES || directory.u32() != CENTRAL_SIGNATURE) {
                fail("a malformed central-directory entry")
            }
            directory.skip(4) // version made by, version needed
            val flags = directory.u16()
            val method = directory.u16()
            directory.skip(4) // time and date
            val crc = directory.u32()
            val compressed = directory.u32()
            val size = directory.u32()
            val nameLength = directory.u16().toLong()
            val extraLength = directory.u16().toLong()
            val commentLength = directory.u16().toLong()
            val disk = directory.u16()
            directory.skip(6) // internal and external attributes
            val offset = directory.u32()
            if (directory.size < nameLength + extraLength + commentLength) fail("a truncated central-directory entry")
            val name = latin1(directory.readByteArray(nameLength))
            directory.skip(extraLength + commentLength)
            val entry = ZipEntry(name, method, flags, crc, compressed, size, offset)
            when {
                (flags and ENCRYPTED) != 0 -> fail("$entry is encrypted")
                method != STORED && method != DEFLATED -> fail("$entry is neither stored nor deflated")
                disk != 0 -> fail("$entry starts on another disk")
                compressed == ZIP64 || size == ZIP64 || offset == ZIP64 -> fail("$entry is zip64")
                method == STORED && compressed != size -> fail("$entry is stored with two sizes")
                offset + LOCAL_BYTES > directoryOffset -> fail("$entry starts past the archive's data")
            }
            return entry
        }

        private fun Buffer.u16(): Int = readShortLe().toInt() and 0xFFFF

        private fun Buffer.u32(): Long = readIntLe().toLong() and 0xFFFF_FFFFL
    }
}

private fun fail(message: String): Nothing = throw SeedFormatException(message)

/** [bytes] read as ISO-8859-1: one char per byte, so a name equals an ASCII one only when its bytes do. */
private fun latin1(bytes: ByteArray): String =
    buildString(bytes.size) { for (b in bytes) append((b.toInt() and 0xFF).toChar()) }

/** [name] with every character outside printable ASCII escaped, for a message. */
internal fun printable(name: String): String =
    buildString {
        append('"')
        for (c in name) {
            val plain = c in ' '..'~' && c != '"' && c != '\\'
            if (plain) append(c) else append("\\x" + c.code.toString(16).padStart(2, '0'))
        }
        append('"')
    }

/** CRC-32 (ISO 3309, the zip CRC), table-driven. */
internal object Crc32 {
    private val TABLE =
        IntArray(256) { n ->
            var c = n
            repeat(8) { c = if ((c and 1) != 0) (c ushr 1) xor 0xEDB88320.toInt() else c ushr 1 }
            c
        }

    fun of(bytes: ByteArray): Long {
        var c = -1
        for (b in bytes) c = TABLE[(c xor b.toInt()) and 0xFF] xor (c ushr 8)
        return c.inv().toLong() and 0xFFFF_FFFFL
    }
}
