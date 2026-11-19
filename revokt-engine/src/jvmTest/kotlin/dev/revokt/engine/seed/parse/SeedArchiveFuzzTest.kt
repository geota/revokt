// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import okio.Buffer
import okio.EOFException
import java.util.zip.CRC32

/**
 * Spec §9.1 target "seed archive and x5u PEM", the archive half (#138): over any bytes, [SeedArchive] either rejects
 * them with a [SeedFormatException] (or a truncated read's [EOFException]) or reads a directory of at most
 * [SeedArchive.maxEntries] distinct names, each of whose entries reads to exactly its declared size and the JDK's CRC-32,
 * the same on a second read, never past its cap. Then an archive written from the input's bytes ([TestZip], stored and
 * deflated entries) reads back exactly. With `JAZZER_FUZZ` unset JUnit replays `SeedArchiveFuzzTestInputs/`; the nightly
 * job runs it with `-max_len=1048599`, `MAX_DIRECTORY_BYTES` + the end record + 1, so the directory cap is reached.
 */
class SeedArchiveFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun read(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private const val CAP = 1L shl 20

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            asArchive(data)
            roundTrip(data)
        }

        private fun asArchive(data: ByteArray) {
            val archive =
                try {
                    SeedArchive.open { Buffer().write(data) }
                } catch (_: SeedFormatException) {
                    return
                } ?: error("a source that opens bytes opened no archive")
            check(archive.entries.size in 1..SeedArchive.maxEntries) { "${archive.entries.size} entries" }
            check(
                archive.entries
                    .map { it.name }
                    .toSet()
                    .size == archive.entries.size,
            ) { "a duplicate name" }
            try {
                archive.requireFixed()
            } catch (_: SeedFormatException) {
                // Most inputs have no seed's entries; the directory is still read below.
            }
            for (entry in archive.entries) {
                val first = readOrNull(archive, entry) ?: continue
                check(first.size.toLong() == entry.size && first.size <= CAP) { "$entry read ${first.size} bytes" }
                check(CRC32().also { it.update(first) }.value == entry.crc32) { "$entry fails the JDK's CRC-32" }
                check(readOrNull(archive, entry)?.contentEquals(first) == true) { "a second read of $entry differs" }
            }
        }

        private fun readOrNull(
            archive: SeedArchive,
            entry: ZipEntry,
        ): ByteArray? {
            var out: ByteArray? = null
            try {
                archive.read(listOf(entry to CAP)) { _, b -> out = b }
            } catch (_: SeedFormatException) {
                return null
            } catch (_: EOFException) {
                return null
            }
            return checkNotNull(out) { "a read gave nothing" }
        }

        /** The input split at each zero byte into at most 16 entries, alternately deflated and stored, read back. */
        private fun roundTrip(data: ByteArray) {
            val parts = ArrayList<ByteArray>()
            var start = 0
            for (i in data.indices) {
                if (data[i] == 0.toByte() && parts.size < 15) {
                    parts += data.copyOfRange(start, i)
                    start = i + 1
                }
            }
            parts += data.copyOfRange(start, data.size)
            val zip = TestZip()
            for ((i, part) in parts.withIndex()) {
                zip.add("attachments/e$i", part, if (i % 2 == 0) TestZip.DEFLATED else TestZip.STORED)
            }
            val archive = checkNotNull(SeedArchive.open { Buffer().write(zip.bytes()) })
            val read = LinkedHashMap<String, ByteArray>()
            archive.read(archive.entries.map { it to data.size.toLong() }) { e, b -> read[e.name] = b }
            check(read.keys.toList() == zip.entries.map { it.name }) { "the entries read back otherwise" }
            for (e in zip.entries) {
                check(
                    read.getValue(e.name).contentEquals(e.data),
                ) { "${e.name} reads back otherwise" }
            }
            check(archive.attachments(parts.indices.map { "e$it" }).size == parts.size)
        }
    }
}
