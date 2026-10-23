// SPDX-FileCopyrightText: Mozilla Foundation and clubcard contributors; translation 2026 revokt contributors
// SPDX-License-Identifier: MPL-2.0
// Translation of clubcard-crlite 0.6.2 src/codec.rs (git b8ca6961975d51518097dd4eb99d0fdeabee7845), spec §3.1.
// Decoding only: the `encode` halves are not translated. Lines marked `revokt:` are the spec §6.3 decode-strictness
// and §6.4 pad-word additions; everything else follows upstream statement by statement.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dev.revokt.clubcard.port

import dev.revokt.clubcard.RevoktInternalApi
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * A cursor over the bytes being decoded: upstream passes `&[u8]` slices and returns the unconsumed rest; the cursor
 * is the same thing with one position instead of many slices. Every read checks the remaining length first.
 */
@RevoktInternalApi
public class ByteReader(
    private val buf: ByteArray,
    position: Int = 0,
) {
    init {
        require(position in 0..buf.size) { "position $position is outside 0..${buf.size}" }
    }

    /** Index of the next unread byte. */
    public var position: Int = position
        private set

    public val remaining: Int get() = buf.size - position

    public fun isEmpty(): Boolean = remaining == 0

    private fun need(
        n: Long,
        what: String,
    ) {
        if (n < 0 || n > remaining) throw ClubcardError.Deserialize("not enough bytes for $what")
    }

    /** `n` bytes as an unsigned big-endian integer, `n` in 1..8. Every multi-byte read goes through here. */
    private fun readBigEndian(
        n: Int,
        what: String,
    ): Long {
        need(n.toLong(), what)
        var v = 0L
        repeat(n) { v = (v shl 8) or (buf[position++].toLong() and 0xff) }
        return v
    }

    /** `uint8`. */
    public fun readU8(): Int = readBigEndian(1, "u8").toInt()

    /** `uint32`, big-endian. */
    public fun readU32(): Long = readBigEndian(4, "u32")

    /** `uint64`, big-endian. */
    public fun readU64(): Long = readBigEndian(8, "u64")

    /** `uint64`, little-endian (the v3 bincode body; not part of the upstream codec). */
    public fun readU64Le(): Long = readU64().reverseBytes()

    /** `opaque x[n]`: `n` fixed-width bytes. */
    public fun bytes(
        n: Int,
        what: String,
    ): ByteString {
        need(n.toLong(), what)
        // A zero-length read shares one instance: 65535 empty serials must not cost 65535 objects (spec §6.3 budget).
        val out = if (n == 0) ByteString.EMPTY else buf.toByteString(position, n)
        position += n
        return out
    }

    /** Read an `n`-byte big-endian length (or item count) prefix, `n` in 1..4. */
    public fun readLen(n: Int): Long = readBigEndian(n, "length")

    /** `opaque content<0..2^(8*n)-1>`: an `n`-byte byte-length prefix followed by the bytes. */
    public fun readVec(n: Int): ByteString {
        val len = readLen(n)
        need(len, "vector content") // checked as a Long first, so the toInt() below cannot truncate
        return bytes(len.toInt(), "vector content")
    }

    /**
     * `u64 items<count>`: a `u32` item count followed by that many big-endian `u64`s. The data length is checked
     * against the remaining bytes before anything is allocated (the per-decoder allocation budget of spec §6.3 is
     * the input itself).
     */
    public fun readU64Seq(): LongArray {
        val count = readLen(4)
        need(count * 8, "u64 sequence data") // a Long product: a count up to 2^32 - 1 cannot wrap
        // revokt: one zero pad word per column (spec §6.4); `Equation.eval` reads the same with or without it.
        val n = count.toInt()
        val items = LongArray(n + 1)
        for (i in 0 until n) items[i] = readU64()
        return items
    }
}

/**
 * The v4 (C2SP) wire format readers, `impl Codec for …` upstream (decoding only). They live in an object rather than
 * in companions because upstream implements them in `clubcard-crlite` for types that belong to `clubcard`; the readers
 * for `clubcard-crlite`'s own types (`LogId`, `Timestamp`, `CrliteCoverage`, …) are companions in CrliteQuery.kt.
 */
@RevoktInternalApi
public object Codec {
    /**
     * ```
     * struct {
     *     CRLiteCoverage universe;
     *     ClubcardIndex  index;
     *     FilterColumn   approx_filter<count>;   // uint8 count, then `count` columns
     *     FilterColumn   exact_filter;
     * } Clubcard;
     * ```
     * where `FilterColumn` is `uint64 words<count>` (a uint32 count followed by that many big-endian words).
     */
    public fun readClubcard(buf: ByteReader): Clubcard<CrliteCoverage> {
        val universe = CrliteCoverage.read(buf)
        val index = readIndex(buf)
        val columnCount = buf.readLen(1).toInt()
        val approxFilter = Array(columnCount) { buf.readU64Seq() }
        val exactFilter = buf.readU64Seq()
        checkRanks(index, columnCount)
        return Clubcard(universe, index, approxFilter, exactFilter)
    }

    /**
     * revokt: spec §6.3, a rank past the last column is rejected at decode (upstream indexes out of bounds at query
     * time). Shared with the v3 reader.
     */
    public fun checkRanks(
        index: ClubcardIndex,
        columnCount: Int,
    ) {
        for ((blockId, entry) in index) {
            if (entry.approxFilterRank > columnCount) {
                throw ClubcardError.Deserialize(
                    "index entry ${blockId.hex()} has rank ${entry.approxFilterRank} but the filter has $columnCount columns",
                )
            }
        }
    }

    /**
     * ```
     * struct {
     *     uint8  len;
     *     opaque serial[len];
     * } Exception;                        // serial as opaque<0..2^8-1>
     *
     * struct {
     *     uint32    approx_filter_m;
     *     uint8     approx_filter_rank;
     *     uint32    approx_filter_offset;
     *     uint32    exact_filter_m;
     *     uint32    exact_filter_offset;
     *     uint8     inverted;
     *     Exception exceptions<count>;     // uint16 count, then `count` serials
     * } ClubcardIndexEntry;
     * ```
     */
    public fun readIndexEntry(buf: ByteReader): ClubcardIndexEntry {
        val approxFilterM = buf.readU32()
        val approxFilterRank = buf.readU8()
        val approxFilterOffset = buf.readU32()
        val exactFilterM = buf.readU32()
        val exactFilterOffset = buf.readU32()
        val inverted = buf.readU8()
        // revokt: spec §6.3, `inverted` is 0 or 1 (a C2SP MUST; upstream's v4 reader takes `!= 0`; bincode rejects it on v3).
        if (inverted > 1) throw ClubcardError.Deserialize("inverted byte is $inverted, expected 0 or 1")

        val count = buf.readLen(2).toInt()
        val exceptions = List(count) { buf.readVec(1) }

        return ClubcardIndexEntry(
            approxFilterM = approxFilterM,
            exactFilterM = exactFilterM,
            approxFilterRank = approxFilterRank,
            approxFilterOffset = approxFilterOffset,
            exactFilterOffset = exactFilterOffset,
            inverted = inverted != 0,
            exceptions = exceptions,
        )
    }

    /**
     * ```
     * struct {
     *     opaque             block_id[32];
     *     ClubcardIndexEntry entry;
     * } IndexEntry;
     *
     * IndexEntry index<count>;   // uint32 count, then `count` entries
     * ```
     * (`impl Codec for ClubcardIndex` lives in query.rs upstream; it is here because it reads the entry above.)
     */
    public fun readIndex(buf: ByteReader): ClubcardIndex {
        val count = buf.readLen(4)
        // Insertion order is the verified sorted order, so iteration reproduces upstream's BTreeMap: keep it linked.
        val index = LinkedHashMap<ByteString, ClubcardIndexEntry>()
        var previous: ByteString? = null
        for (i in 0 until count) {
            val blockId = buf.bytes(32, "ClubcardIndexEntry")
            val entry = readIndexEntry(buf)
            // revokt: spec §6.3, block ids strictly increasing (a C2SP MUST; also rejects duplicates, which upstream overwrites).
            if (previous != null && previous >= blockId) {
                throw ClubcardError.Deserialize("index is not sorted by block id at entry $i")
            }
            previous = blockId
            index[blockId] = entry
        }
        return index
    }
}

/** Byte order reversal of a 64-bit word. */
private fun Long.reverseBytes(): Long {
    var v = 0L
    var x = this
    repeat(8) {
        v = (v shl 8) or (x and 0xff)
        x = x ushr 8
    }
    return v
}
