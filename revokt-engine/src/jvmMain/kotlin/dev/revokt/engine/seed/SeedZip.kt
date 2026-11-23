// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import okio.Buffer
import java.util.zip.CRC32
import java.util.zip.Deflater

/** One entry [SeedZip.write] writes: [name] (ASCII), its [data], and whether it is [stored] rather than deflated. */
internal class SeedZipEntry(
    val name: String,
    val data: ByteArray,
    val stored: Boolean = false,
)

/**
 * The seed archive's zip writer (#145; spec §6.5 "The zip the loader reads"): the strict subset `SeedArchive` reads and
 * nothing more, with fixed bytes for fixed input, so a rebuild of one changeset on one JDK gives one archive.
 *
 * Entries are written in the given order, each a local header, its data and no data descriptor, then the central
 * directory and an end record with no comment as the archive's last bytes. Every entry is dated 1980-02-01 00:00, as
 * Gradle's reproducible archives are (`isPreserveFileTimestamps = false`), written as DOS fields so no time zone enters;
 * it has flags 0, no extra field and no comment, and external attributes 0. A deflated entry is raw deflate at level 9,
 * as Firefox's omni.ja writer (`mozjar.py`) deflates. Not `java.util.zip.ZipOutputStream`: it writes a data descriptor
 * after every deflated entry and dates entries through the default time zone.
 *
 * One disk and no zip64: a name that is not non-empty printable ASCII, a duplicate name, more than [MAX_ENTRIES]
 * entries, or an archive whose offsets would need zip64 throws [IllegalArgumentException]. The deflate output is the
 * JDK's zlib's, so byte equality across rebuilds holds for one JDK build (the job pins it, data/seed/README.md).
 */
internal object SeedZip {
    /** The most entries one end record counts without zip64. */
    const val MAX_ENTRIES: Int = 0xFFFF

    /** The DOS date of 1980-02-01: `(year - 1980) << 9 | month << 5 | day`. */
    const val DOS_DATE: Int = (0 shl 9) or (2 shl 5) or 1

    /** The DOS time 00:00:00. */
    const val DOS_TIME: Int = 0

    private const val LOCAL_SIGNATURE = 0x04034b50
    private const val CENTRAL_SIGNATURE = 0x02014b50
    private const val END_SIGNATURE = 0x06054b50
    private const val STORED = 0
    private const val DEFLATED = 8
    private const val VERSION_STORED = 10
    private const val VERSION_DEFLATED = 20
    private const val VERSION_MADE_BY = 20
    private const val MAX_U32 = 0xFFFF_FFFFL
    private const val MAX_U16 = 0xFFFF
    private const val LEVEL = 9
    private const val PRINTABLE_LOW = 0x21
    private const val PRINTABLE_HIGH = 0x7E

    /** The archive of [entries], in their order. */
    fun write(entries: List<SeedZipEntry>): ByteArray {
        require(entries.size <= MAX_ENTRIES) { "${entries.size} entries, over $MAX_ENTRIES" }
        val names = HashSet<String>()
        for (e in entries) {
            require(e.name.isNotEmpty() && e.name.all { it.code in PRINTABLE_LOW..PRINTABLE_HIGH }) {
                "the entry name is not printable ASCII: ${e.name.length} characters"
            }
            require(e.name.length <= MAX_U16) { "the entry name is over $MAX_U16 bytes" }
            require(names.add(e.name)) { "a duplicate entry ${e.name}" }
        }
        val out = Buffer()
        val central = Buffer()
        for (e in entries) {
            val body = if (e.stored) e.data else deflate(e.data)
            val crc = CRC32().apply { update(e.data) }.value
            val offset = out.size
            require(offset + LOCAL_FIXED + e.name.length + body.size < MAX_U32) { "the archive would need zip64" }
            val name = e.name.encodeToByteArray()
            val method = if (e.stored) STORED else DEFLATED
            val version = if (e.stored) VERSION_STORED else VERSION_DEFLATED
            out
                .writeIntLe(LOCAL_SIGNATURE)
                .writeShortLe(version)
                .writeShortLe(0)
                .writeShortLe(method)
                .writeShortLe(DOS_TIME)
                .writeShortLe(DOS_DATE)
                .writeIntLe(crc.toInt())
                .writeIntLe(body.size)
                .writeIntLe(e.data.size)
                .writeShortLe(name.size)
                .writeShortLe(0)
                .write(name)
                .write(body)
            central
                .writeIntLe(CENTRAL_SIGNATURE)
                .writeShortLe(VERSION_MADE_BY)
                .writeShortLe(version)
                .writeShortLe(0)
                .writeShortLe(method)
                .writeShortLe(DOS_TIME)
                .writeShortLe(DOS_DATE)
                .writeIntLe(crc.toInt())
                .writeIntLe(body.size)
                .writeIntLe(e.data.size)
                .writeShortLe(name.size)
                .writeShortLe(0)
                .writeShortLe(0)
                .writeShortLe(0)
                .writeShortLe(0)
                .writeIntLe(0)
                .writeIntLe(offset.toInt())
                .write(name)
        }
        val directoryOffset = out.size
        val directorySize = central.size
        require(directoryOffset + directorySize < MAX_U32) { "the archive would need zip64" }
        out.writeAll(central)
        out
            .writeIntLe(END_SIGNATURE)
            .writeShortLe(0)
            .writeShortLe(0)
            .writeShortLe(entries.size)
            .writeShortLe(entries.size)
            .writeIntLe(directorySize.toInt())
            .writeIntLe(directoryOffset.toInt())
            .writeShortLe(0)
        return out.readByteArray()
    }

    /** [data] as raw deflate (no zlib header or trailer) at level [LEVEL]. */
    private fun deflate(data: ByteArray): ByteArray {
        val deflater = Deflater(LEVEL, true)
        try {
            deflater.setInput(data)
            deflater.finish()
            val out = Buffer()
            val chunk = ByteArray(CHUNK)
            while (!deflater.finished()) {
                val n = deflater.deflate(chunk)
                out.write(chunk, 0, n)
            }
            return out.readByteArray()
        } finally {
            deflater.end()
        }
    }

    private const val LOCAL_FIXED = 30
    private const val CHUNK = 8192
}
