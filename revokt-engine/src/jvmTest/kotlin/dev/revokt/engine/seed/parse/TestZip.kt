// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

import okio.Buffer
import java.util.zip.CRC32
import java.util.zip.Deflater

/**
 * A test-local zip writer for the seed tests (#138; #145's writer comes later and round-trips against the loader): every
 * field of every header can be set or made to lie, so each rule of [SeedArchive] has an archive that breaks it alone.
 * The CRC is the JDK's ([CRC32]) and the deflate stream the JDK's raw [Deflater], independent of the reader's own.
 */
internal class TestZip {
    /** One entry: its [data], how it is stored, and every header field a test may override. */
    class Entry(
        val name: String,
        val data: ByteArray,
        var method: Int = DEFLATED,
    ) {
        var flags: Int = 0
        var crc: Long? = null
        var compressedSize: Long? = null
        var size: Long? = null
        var disk: Int = 0
        var extra: ByteArray = ByteArray(0)
        var comment: ByteArray = ByteArray(0)

        /** The central directory entry's comment length instead of [comment]'s. */
        var commentLength: Int? = null

        /** The bytes written as the entry's data instead of [data] stored or deflated. */
        var compressed: ByteArray? = null

        /** The central directory's local header offset instead of the real one. */
        var offset: ((Long) -> Long)? = null

        /** The local header's overrides; null writes the central directory's value (zero sizes with a descriptor). */
        var localName: String? = null
        var localFlags: Int? = null
        var localMethod: Int? = null
        var localCrc: Long? = null
        var localCompressedSize: Long? = null
        var localSize: Long? = null
        var localExtra: ByteArray = ByteArray(0)

        /** Bytes written after the data, before the next local header (a data descriptor, or junk). */
        var trailer: ByteArray = ByteArray(0)

        /** Whether the central directory lists this entry; an unlisted one is written locally only. */
        var listed: Boolean = true

        internal val body: ByteArray by lazy {
            compressed ?: if (method == STORED) data else deflate(data)
        }
        internal val realCrc: Long get() = CRC32().also { it.update(data) }.value
    }

    val entries: MutableList<Entry> = mutableListOf()

    /** Bytes before the first local header. */
    var prefix: ByteArray = ByteArray(0)

    /** Bytes between the last entry's data and the central directory. */
    var gap: ByteArray = ByteArray(0)

    var endComment: ByteArray = ByteArray(0)

    /** The end record's comment length instead of [endComment]'s. */
    var endCommentLength: Int? = null
    var endSignature: Long = END_SIGNATURE
    var disk: Int = 0
    var directoryDisk: Int = 0

    /** Overrides of the end record's entry counts, directory size and offset, from the real ones. */
    var diskEntries: ((Int) -> Int)? = null
    var totalEntries: ((Int) -> Int)? = null
    var directorySize: ((Long) -> Long)? = null
    var directoryOffset: ((Long) -> Long)? = null

    /** Bytes after the end record. */
    var suffix: ByteArray = ByteArray(0)

    /** The central directory's entries in this order of [entries] indices, when set. */
    var directoryOrder: List<Int>? = null

    fun add(
        name: String,
        data: ByteArray,
        method: Int = DEFLATED,
        configure: Entry.() -> Unit = {},
    ): TestZip = apply { entries += Entry(name, data, method).apply(configure) }

    fun entry(name: String): Entry = entries.single { it.name == name }

    fun bytes(): ByteArray {
        val out = Buffer().write(prefix)
        val offsets = entries.map { e -> out.size.also { local(out, e) } }
        out.write(gap)
        val start = out.size
        val listed = (directoryOrder ?: entries.indices.toList()).filter { entries[it].listed }
        for (i in listed) central(out, entries[i], offsets[i])
        end(out, listed.size, out.size - start, start)
        return out.readByteArray()
    }

    private fun local(
        out: Buffer,
        e: Entry,
    ) {
        val descriptor = (e.flags and DESCRIPTOR) != 0
        out.writeIntLe(LOCAL_SIGNATURE)
        out.writeShortLe(20)
        out.writeShortLe(e.localFlags ?: e.flags)
        out.writeShortLe(e.localMethod ?: e.method)
        out.writeIntLe(0)
        out.writeIntLe((e.localCrc ?: if (descriptor) 0 else crcOf(e)).toInt())
        out.writeIntLe((e.localCompressedSize ?: if (descriptor) 0 else compressedOf(e)).toInt())
        out.writeIntLe((e.localSize ?: if (descriptor) 0 else sizeOf(e)).toInt())
        val name = (e.localName ?: e.name).toByteArray(Charsets.ISO_8859_1)
        out.writeShortLe(name.size)
        out.writeShortLe(e.localExtra.size)
        out.write(name)
        out.write(e.localExtra)
        out.write(e.body)
        out.write(e.trailer)
    }

    private fun central(
        out: Buffer,
        e: Entry,
        offset: Long,
    ) {
        out.writeIntLe(CENTRAL_SIGNATURE)
        out.writeShortLe(20)
        out.writeShortLe(20)
        out.writeShortLe(e.flags)
        out.writeShortLe(e.method)
        out.writeIntLe(0)
        out.writeIntLe(crcOf(e).toInt())
        out.writeIntLe(compressedOf(e).toInt())
        out.writeIntLe(sizeOf(e).toInt())
        val name = e.name.toByteArray(Charsets.ISO_8859_1)
        out.writeShortLe(name.size)
        out.writeShortLe(e.extra.size)
        out.writeShortLe(e.commentLength ?: e.comment.size)
        out.writeShortLe(e.disk)
        out.writeShortLe(0)
        out.writeIntLe(0)
        out.writeIntLe((e.offset?.invoke(offset) ?: offset).toInt())
        out.write(name)
        out.write(e.extra)
        out.write(e.comment)
    }

    private fun end(
        out: Buffer,
        listed: Int,
        size: Long,
        start: Long,
    ) {
        out.writeIntLe(endSignature.toInt())
        out.writeShortLe(disk)
        out.writeShortLe(directoryDisk)
        out.writeShortLe(diskEntries?.invoke(listed) ?: listed)
        out.writeShortLe(totalEntries?.invoke(listed) ?: listed)
        out.writeIntLe((directorySize?.invoke(size) ?: size).toInt())
        out.writeIntLe((directoryOffset?.invoke(start) ?: start).toInt())
        out.writeShortLe(endCommentLength ?: endComment.size)
        out.write(endComment)
        out.write(suffix)
    }

    private fun crcOf(e: Entry): Long = e.crc ?: e.realCrc

    private fun compressedOf(e: Entry): Long = e.compressedSize ?: e.body.size.toLong()

    private fun sizeOf(e: Entry): Long = e.size ?: e.data.size.toLong()

    companion object {
        const val STORED = 0
        const val DEFLATED = 8
        const val DESCRIPTOR = 0x0008
        const val END_SIGNATURE = 0x06054b50L
        const val CENTRAL_SIGNATURE = 0x02014b50
        const val LOCAL_SIGNATURE = 0x04034b50

        /** [data] as one raw deflate stream (no zlib wrapper), as a zip entry holds it. */
        fun deflate(
            data: ByteArray,
            level: Int = Deflater.DEFAULT_COMPRESSION,
        ): ByteArray {
            val deflater = Deflater(level, true)
            try {
                deflater.setInput(data)
                deflater.finish()
                val out = Buffer()
                val chunk = ByteArray(8192)
                while (!deflater.finished()) out.write(chunk, 0, deflater.deflate(chunk))
                return out.readByteArray()
            } finally {
                deflater.end()
            }
        }
    }
}
