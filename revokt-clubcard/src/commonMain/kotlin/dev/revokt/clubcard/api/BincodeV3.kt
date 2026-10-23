// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.port.ByteReader
import dev.revokt.clubcard.port.Clubcard
import dev.revokt.clubcard.port.ClubcardIndexEntry
import dev.revokt.clubcard.port.CrliteCoverage
import dev.revokt.clubcard.port.LogId
import dev.revokt.clubcard.port.Timestamp
import dev.revokt.clubcard.port.TimestampInterval
import okio.ByteString

/**
 * The v3 filter body: `bincode` 1.x with its default options (little-endian, fixed-width integers, `u64` lengths,
 * trailing bytes allowed) over `clubcard-crlite`'s `Clubcard<4, CRLiteCoverage, ()>` as serde derives it (spec §6.3):
 *
 * ```
 * universe:      u64 n × { [u8; 32] log_id, u64 low, u64 high }      // HashMap<LogId, TimestampInterval>
 * partition:     ()                                                   // 0 bytes
 * index:         u64 n × { u64 len, u8 key[len],                      // BTreeMap<Vec<u8>, ClubcardIndexEntry>
 *                          u64 approx_filter_m, u64 exact_filter_m, u64 approx_filter_rank,
 *                          u64 approx_filter_offset, u64 exact_filter_offset, u8 inverted,
 *                          u64 n × { u64 len, u8 serial[len] } }
 * approx_filter: u64 n × { u64 len, u64 words[len] }                  // Vec<Vec<u64>>
 * exact_filter:  u64 len, u64 words[len]                              // Vec<u64>
 * ```
 *
 * Original code, not a translation: upstream decodes this through serde. The spec §6.3 strictness rules are the
 * same as the v4 reader's; in addition every `usize` must fit the v4 range (`u32`; rank and column count `u8`), so a
 * v3 filter that revokt accepts is one it could also have accepted as a v4 transcode. `BTreeMap` serializes its keys
 * in order, so the sorted-index rule holds for every producer-written v3 filter.
 */
@OptIn(RevoktInternalApi::class)
internal object BincodeV3 {
    private const val COVERAGE_ENTRY_BYTES = 32L + 8 + 8
    private const val INDEX_ENTRY_MIN_BYTES = 8L + 5 * 8 + 1 + 8
    private const val U32_MAX = 0xFFFF_FFFFL
    private const val U8_MAX = 0xFFL

    fun readClubcard(buf: ByteReader): Clubcard<CrliteCoverage> {
        val universe = readCoverage(buf)
        val index = readIndex(buf)
        val columnCount = readCount(buf, "approx_filter columns", perItemBytes = 8)
        if (columnCount > U8_MAX) {
            throw ClubcardFormatException("v3 approx_filter has $columnCount columns, more than the v4 range (255)")
        }
        val approxFilter = Array(columnCount.toInt()) { readWords(buf) }
        val exactFilter = readWords(buf)
        for ((blockId, entry) in index) {
            if (entry.approxFilterRank > columnCount) {
                throw ClubcardFormatException(
                    "index entry ${blockId.hex()} has rank ${entry.approxFilterRank} but the filter has $columnCount columns",
                )
            }
        }
        // Trailing bytes are accepted: bincode 1.x's `deserialize` does not check for them.
        return Clubcard(universe, index, approxFilter, exactFilter)
    }

    private fun readCoverage(buf: ByteReader): CrliteCoverage {
        val count = readCount(buf, "coverage", perItemBytes = COVERAGE_ENTRY_BYTES)
        val map = LinkedHashMap<LogId, TimestampInterval>(count.toInt())
        for (i in 0 until count) {
            val logId = LogId(buf.bytes(32, "LogId"))
            val low = Timestamp(u64le(buf))
            val high = Timestamp(u64le(buf))
            if (map.put(logId, TimestampInterval(low, high)) != null) {
                throw ClubcardFormatException("coverage lists log ${logId.bytes.hex()} twice")
            }
        }
        return CrliteCoverage(map)
    }

    private fun readIndex(buf: ByteReader): Map<ByteString, ClubcardIndexEntry> {
        val count = readCount(buf, "index", perItemBytes = INDEX_ENTRY_MIN_BYTES)
        val index = LinkedHashMap<ByteString, ClubcardIndexEntry>()
        var previous: ByteString? = null
        for (i in 0 until count) {
            val blockId = readBytes(buf, "block id")
            if (previous != null && previous >= blockId) {
                throw ClubcardFormatException("index is not sorted by block id at entry $i")
            }
            previous = blockId
            index[blockId] = readIndexEntry(buf)
        }
        return index
    }

    private fun readIndexEntry(buf: ByteReader): ClubcardIndexEntry {
        val approxFilterM = u32Range(buf, "approx_filter_m")
        val exactFilterM = u32Range(buf, "exact_filter_m")
        val approxFilterRank = u64le(buf)
        if (approxFilterRank.toULong() > U8_MAX.toULong()) {
            throw ClubcardFormatException("v3 approx_filter_rank $approxFilterRank exceeds the v4 range (255)")
        }
        val approxFilterOffset = u32Range(buf, "approx_filter_offset")
        val exactFilterOffset = u32Range(buf, "exact_filter_offset")
        val inverted = buf.u8()
        if (inverted > 1) throw ClubcardFormatException("inverted byte is $inverted, expected 0 or 1")
        val exceptionCount = readCount(buf, "exceptions", perItemBytes = 8)
        val exceptions = ArrayList<ByteString>(exceptionCount.toInt())
        for (i in 0 until exceptionCount) exceptions.add(readBytes(buf, "exception serial"))
        return ClubcardIndexEntry(
            approxFilterM = approxFilterM,
            exactFilterM = exactFilterM,
            approxFilterRank = approxFilterRank.toInt(),
            approxFilterOffset = approxFilterOffset,
            exactFilterOffset = exactFilterOffset,
            inverted = inverted != 0,
            exceptions = exceptions,
        )
    }

    /** `Vec<u64>`: a `u64` length, checked against the remaining input, then little-endian words plus one pad word (spec §6.4). */
    private fun readWords(buf: ByteReader): LongArray {
        val count = readCount(buf, "u64 sequence", perItemBytes = 8)
        val words = LongArray(count.toInt() + 1)
        for (i in 0 until count.toInt()) words[i] = u64le(buf)
        return words
    }

    /** A `u64` length prefix such that `count * perItemBytes` fits the remaining input, so nothing is allocated for a lying length. */
    private fun readCount(
        buf: ByteReader,
        what: String,
        perItemBytes: Long,
    ): Long {
        val count = u64le(buf)
        if (count.toULong() > (buf.remaining / perItemBytes).toULong()) {
            throw ClubcardFormatException(
                "not enough bytes for $what: $count items declared, ${buf.remaining} bytes remain",
            )
        }
        return count
    }

    private fun readBytes(
        buf: ByteReader,
        what: String,
    ): ByteString {
        val len = readCount(buf, what, perItemBytes = 1)
        return buf.bytes(len.toInt(), what)
    }

    private fun u32Range(
        buf: ByteReader,
        name: String,
    ): Long {
        val value = u64le(buf)
        if (value.toULong() > U32_MAX.toULong()) {
            throw ClubcardFormatException("v3 $name $value exceeds the v4 range (u32)")
        }
        return value
    }

    /** `u64`, little-endian (bincode's default), read through the port's big-endian reader. */
    private fun u64le(buf: ByteReader): Long {
        val be = buf.u64()
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or ((be ushr (8 * i)) and 0xff)
        return v
    }
}
