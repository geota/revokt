// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.c2sp

import okio.ByteString
import okio.ByteString.Companion.toByteString

/** A malformed `index.bin`: a violated MUST (or the overlap SHOULD) of the C2SP index file format. */
internal class IndexFormatException(
    message: String,
) : Exception(message)

/** An inclusive window of SCT timestamps, in milliseconds since the epoch, compared as unsigned 64-bit values. */
internal data class Window(
    val low: ULong,
    val high: ULong,
) {
    operator fun contains(t: ULong): Boolean = t in low..high
}

/** One `Entry` of a log's entry section: the filter at [filterIndex] covers the log over [window]. */
internal data class IndexEntry(
    val filterIndex: Int,
    val window: Window,
)

/**
 * A parsed `index.bin` (C2SP `upki-revocation@v1.0.0`, "Index file format"): the filename table in file order, and per
 * log ID the entries of its section, in file order. [logs] iterates in log-ID order, which the reader enforces.
 */
internal class IndexFile(
    val filenames: List<String>,
    val logs: Map<ByteString, List<IndexEntry>>,
) {
    override fun equals(other: Any?): Boolean = other is IndexFile && filenames == other.filenames && logs == other.logs

    override fun hashCode(): Int = 31 * filenames.hashCode() + logs.hashCode()
}

/**
 * The C2SP revocation index (`index.bin`) at `upki-revocation/v1.0.0` (spec §2 goal 1, §3.2): big-endian integers, a
 * 14-byte header (`upkiidx1`, `uint16` filename count, `uint32` log count), 32-byte zero-padded filenames, 42-byte log
 * directory entries (log ID, `uint64` offset, `uint16` entry count) sorted by raw log ID, and 18-byte entries
 * (`uint16` filter index, `uint64` minimum and maximum timestamps, inclusive).
 */
internal object C2spIndex {
    private val MAGIC = "upkiidx1".encodeToByteArray()
    private const val HEADER = 14
    private const val NAME = 32
    private const val LOG_ENTRY = 42
    private const val ENTRY = 18
    private const val LOG_ID = 32
    private val NAME_CHARS = ('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('-', '.', '_')

    /** Whether [name] is a filter filename the C2SP cache directory layout allows. */
    fun isFilename(name: String): Boolean =
        name.encodeToByteArray().size in 1..NAME && name != "." && name != ".." && name.all { it in NAME_CHARS }

    /** Parses [bytes], enforcing every MUST of the index file format and the SHOULD against overlapping sections. */
    fun read(bytes: ByteArray): IndexFile {
        if (bytes.size < HEADER) fail("index.bin is ${bytes.size} bytes, shorter than its 14-byte header")
        if (!bytes
                .copyOfRange(
                    0,
                    MAGIC.size,
                ).contentEquals(MAGIC)
        ) {
            fail("index.bin does not start with the magic upkiidx1")
        }
        val numFilenames = u16(bytes, 8)
        val numLogs = u32(bytes, 10)
        val tablesEnd = HEADER.toLong() + NAME.toLong() * numFilenames + LOG_ENTRY.toLong() * numLogs
        if (tablesEnd > bytes.size) {
            fail("index.bin declares $numFilenames filenames and $numLogs logs, more than its ${bytes.size} bytes hold")
        }
        val filenames = readFilenames(bytes, numFilenames)
        val logs = readLogs(bytes, HEADER + NAME * numFilenames, numLogs.toInt(), tablesEnd.toULong(), numFilenames)
        return IndexFile(filenames, logs)
    }

    private fun fail(message: String): Nothing = throw IndexFormatException(message)

    private fun readFilenames(
        bytes: ByteArray,
        count: Int,
    ): List<String> {
        val filenames =
            (0 until count).map { i ->
                val slot = bytes.copyOfRange(HEADER + NAME * i, HEADER + NAME * (i + 1))
                val end = slot.indexOf(0).let { if (it < 0) NAME else it }
                if ((end until NAME).any { slot[it] != 0.toByte() }) {
                    fail(
                        "filename $i is not zero-padded after its first zero byte",
                    )
                }
                val name = slot.copyOfRange(0, end).decodeToString()
                if (!isFilename(
                        name,
                    )
                ) {
                    fail(
                        "filename $i ('$name') is not 1 to 32 bytes of A-Z, a-z, 0-9, '-', '.', '_', nor '.' or '..'",
                    )
                }
                name
            }
        if (filenames.toSet().size != filenames.size) fail("the filename table names a file twice")
        return filenames
    }

    private fun readLogs(
        bytes: ByteArray,
        dirStart: Int,
        count: Int,
        tablesEnd: ULong,
        numFilenames: Int,
    ): Map<ByteString, List<IndexEntry>> {
        val logs = LinkedHashMap<ByteString, List<IndexEntry>>()
        val sections = ArrayList<LongRange>()
        var previous: ByteString? = null
        for (i in 0 until count) {
            val at = dirStart + LOG_ENTRY * i
            val logId = bytes.copyOfRange(at, at + LOG_ID).toByteString()
            if (previous != null &&
                previous >= logId
            ) {
                fail("the log directory is not sorted by log ID, or lists ${logId.hex()} twice")
            }
            previous = logId
            val offset = u64(bytes, at + LOG_ID)
            val entries = u16(bytes, at + LOG_ID + 8)
            // offset is checked against the file size before the sum, so the end cannot overflow.
            if (offset < tablesEnd || offset > bytes.size.toULong() ||
                offset + ENTRY.toULong() * entries.toULong() > bytes.size.toULong()
            ) {
                fail(
                    "log ${logId.hex()}'s entry section ($entries entries at offset $offset) is not inside the file after the tables",
                )
            }
            val start = offset.toInt()
            if (entries > 0) sections += start.toLong() until start.toLong() + ENTRY * entries
            logs[logId] = readEntries(bytes, start, entries, logId, numFilenames)
        }
        sections.sortBy { it.first }
        for ((a, b) in sections.zipWithNext()) {
            if (b.first <=
                a.last
            ) {
                fail("two logs' entry sections overlap at offset ${b.first}")
            }
        }
        return logs
    }

    private fun readEntries(
        bytes: ByteArray,
        start: Int,
        count: Int,
        logId: ByteString,
        numFilenames: Int,
    ): List<IndexEntry> =
        (0 until count).map { k ->
            val e = start + ENTRY * k
            val filter = u16(bytes, e)
            if (filter >= numFilenames) fail("log ${logId.hex()} entry $k names filter $filter of $numFilenames")
            IndexEntry(filter, Window(u64(bytes, e + 2), u64(bytes, e + 10)))
        }

    /**
     * The index for filters [filters] in order, each a name and its coverage (log ID to window), laid out exactly as
     * upki 1.0.1's `Index::write`: filenames in the given order, logs in log-ID order, each log's entries in filter order,
     * entry sections contiguous after the log directory.
     */
    fun index(filters: List<Pair<String, Map<ByteString, Window>>>): IndexFile {
        filters.forEach { (name, _) -> require(isFilename(name)) { "'$name' is not a C2SP filter filename" } }
        require(filters.map { it.first }.toSet().size == filters.size) { "a filter name appears twice" }
        require(filters.size <= 0xFFFF) { "${filters.size} filters; an index addresses at most 65535" }
        val logs = HashMap<ByteString, MutableList<IndexEntry>>()
        filters.forEachIndexed { i, (_, coverage) ->
            for ((logId, window) in coverage) {
                require(logId.size == LOG_ID) { "a log ID is 32 bytes, got ${logId.size}" }
                logs.getOrPut(logId) { mutableListOf() } += IndexEntry(i, window)
            }
        }
        // Okio's ByteString compares byte by byte as unsigned values: the raw-bytes order the format requires.
        return IndexFile(
            filters.map { it.first },
            logs.keys.sorted().associateWithTo(LinkedHashMap()) { logs.getValue(it) },
        )
    }

    /** The bytes of [index], its tables and sections in the order [index] holds them. */
    fun write(index: IndexFile): ByteArray {
        val tablesEnd = HEADER + NAME * index.filenames.size + LOG_ENTRY * index.logs.size
        val out = ByteArray(tablesEnd + ENTRY * index.logs.values.sumOf { it.size })
        MAGIC.copyInto(out, 0)
        putU16(out, 8, index.filenames.size)
        putU32(out, 10, index.logs.size.toLong())
        index.filenames.forEachIndexed { i, name -> name.encodeToByteArray().copyInto(out, HEADER + NAME * i) }
        var dir = HEADER + NAME * index.filenames.size
        var section = tablesEnd
        for ((logId, entries) in index.logs) {
            logId.toByteArray().copyInto(out, dir)
            putU64(out, dir + LOG_ID, section.toULong())
            putU16(out, dir + LOG_ID + 8, entries.size)
            dir += LOG_ENTRY
            for (e in entries) {
                putU16(out, section, e.filterIndex)
                putU64(out, section + 2, e.window.low)
                putU64(out, section + 10, e.window.high)
                section += ENTRY
            }
        }
        return out
    }

    /**
     * Step 1 of the C2SP check procedure: the covering filters for the (log ID, timestamp) pairs in [scts], in the
     * order they are first matched. Every matching entry counts, not only the first.
     */
    fun covering(
        index: IndexFile,
        scts: List<Pair<ByteString, ULong>>,
    ): Set<String> {
        val out = LinkedHashSet<String>()
        for ((logId, t) in scts) {
            for (e in index.logs[logId].orEmpty()) {
                if (t in
                    e.window
                ) {
                    out += index.filenames[e.filterIndex]
                }
            }
        }
        return out
    }

    /**
     * Spec §3.2 selection equivalence for an index revokt did not build: for every log ID and timestamp, the filters the
     * index names must be exactly the filters whose own coverage contains it. Here that is: the index names exactly the
     * filters in [coverage], and for each filter and log, the union of its entries equals the filter's own window
     * (every entry inside it, no gap, nothing for a log the filter does not cover). Returns every mismatch; empty when
     * the index is consistent.
     */
    fun inconsistencies(
        index: IndexFile,
        coverage: Map<String, Map<ByteString, Window>>,
    ): List<String> {
        val out = mutableListOf<String>()
        val named = index.filenames.toSet()
        (coverage.keys - named).forEach { out += "filter $it is not named by the index" }
        (named - coverage.keys).forEach { out += "the index names $it, which is not one of the generation's filters" }
        val byFilterLog = HashMap<Pair<String, ByteString>, MutableList<Window>>()
        for ((logId, entries) in index.logs) {
            for (e in entries) {
                byFilterLog.getOrPut(index.filenames[e.filterIndex] to logId) { mutableListOf() } +=
                    e.window
            }
        }
        for ((name, logs) in coverage.filterKeys { it in named }) {
            for ((logId, window) in logs) out += mismatches(name, logId, window, byFilterLog.remove(name to logId))
        }
        for ((key, _) in byFilterLog) {
            out +=
                "the index has an entry for filter ${key.first}, log ${key.second.hex()}, which the filter does not cover"
        }
        return out
    }

    /** How one filter's entries for one log depart from its own [window]; [windows] is null when it has none. */
    private fun mismatches(
        name: String,
        logId: ByteString,
        window: Window,
        windows: List<Window>?,
    ): List<String> {
        val where = "filter $name, log ${logId.hex()}"
        if (windows == null) return listOf("$where: the filter covers the log but the index has no entry for it")
        val out = mutableListOf<String>()
        windows.filter { it.low < window.low || it.high > window.high || it.low > it.high }.forEach {
            out +=
                "$where: entry [${it.low}, ${it.high}] is not inside the filter's window [${window.low}, ${window.high}]"
        }
        if (!coversExactly(windows, window)) {
            out += "$where: the entries do not cover the filter's window [${window.low}, ${window.high}] without a gap"
        }
        return out
    }

    /** Whether the union of [windows] is exactly [target]: sorted, they start at its low, chain with no gap, and reach its high. */
    private fun coversExactly(
        windows: List<Window>,
        target: Window,
    ): Boolean {
        val sorted = windows.filter { it.low <= it.high }.sortedBy { it.low }
        if (sorted.isEmpty() || sorted.first().low != target.low) return false
        var reach = sorted.first().high
        for (w in sorted.drop(1)) {
            if (reach != ULong.MAX_VALUE && w.low > reach + 1u) return false
            if (w.high > reach) reach = w.high
        }
        return reach == target.high
    }

    private fun u16(
        b: ByteArray,
        at: Int,
    ): Int = ((b[at].toInt() and 0xFF) shl 8) or (b[at + 1].toInt() and 0xFF)

    private fun u32(
        b: ByteArray,
        at: Int,
    ): Long =
        (0 until 4).fold(0L) { acc, i ->
            (acc shl 8) or
                (b[at + i].toLong() and 0xFF)
        }

    private fun u64(
        b: ByteArray,
        at: Int,
    ): ULong =
        (0 until 8).fold(0uL) { acc, i ->
            (acc shl 8) or
                (b[at + i].toULong() and 0xFFu)
        }

    private fun putU16(
        b: ByteArray,
        at: Int,
        v: Int,
    ) {
        b[at] = (v ushr 8).toByte()
        b[at + 1] = v.toByte()
    }

    private fun putU32(
        b: ByteArray,
        at: Int,
        v: Long,
    ) {
        for (i in 0 until 4) b[at + i] = (v ushr (8 * (3 - i))).toByte()
    }

    private fun putU64(
        b: ByteArray,
        at: Int,
        v: ULong,
    ) {
        for (i in 0 until 8) b[at + i] = (v shr (8 * (7 - i))).toByte()
    }
}
