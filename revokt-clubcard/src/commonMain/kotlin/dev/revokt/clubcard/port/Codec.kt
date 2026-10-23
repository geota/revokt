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
    position: Int,
) {
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

    /** `uint8`. */
    public fun u8(): Int {
        need(1, "u8")
        return buf[position++].toInt() and 0xff
    }

    /** `uint32`, big-endian. */
    public fun u32(): Long {
        need(4, "u32")
        var v = 0L
        for (i in 0 until 4) v = (v shl 8) or (buf[position + i].toLong() and 0xff)
        position += 4
        return v
    }

    /** `uint64`, big-endian. */
    public fun u64(): Long {
        need(8, "u64")
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (buf[position + i].toLong() and 0xff)
        position += 8
        return v
    }

    /** `opaque x[n]`: `n` fixed-width bytes. */
    public fun bytes(
        n: Int,
        what: String,
    ): ByteString {
        need(n.toLong(), what)
        val out = buf.toByteString(position, n)
        position += n
        return out
    }

    /** Read an `n`-byte big-endian length (or item count) prefix, `n` in 1..4. */
    public fun readLen(n: Int): Long {
        need(n.toLong(), "length")
        var v = 0L
        for (i in 0 until n) v = (v shl 8) or (buf[position + i].toLong() and 0xff)
        position += n
        return v
    }

    /** `opaque content<0..2^(8*n)-1>`: an `n`-byte byte-length prefix followed by the bytes. */
    public fun readVec(n: Int): ByteString {
        val len = readLen(n)
        need(len, "vector content")
        return bytes(len.toInt(), "vector content")
    }

    /**
     * `u64 items<count>`: a `u32` item count followed by that many big-endian `u64`s. The data length is checked
     * against the remaining bytes before anything is allocated (the per-decoder allocation budget of spec §6.3 is
     * the input itself).
     */
    public fun readU64Seq(): LongArray {
        val count = readLen(4)
        val byteLen = count * 8
        if (byteLen > remaining) throw ClubcardError.Deserialize("not enough bytes for u64 sequence data")
        // revokt: one zero pad word per column (spec §6.4); `Equation.eval` reads the same with or without it.
        val items = LongArray(count.toInt() + 1)
        for (i in 0 until count.toInt()) items[i] = u64()
        return items
    }
}

/** The v4 (C2SP) wire format readers, `impl Codec for …` upstream (decoding only). */
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
        // revokt: spec §6.3, a rank past the last column is rejected at decode (upstream indexes out of bounds at query).
        for ((blockId, entry) in index) {
            if (entry.approxFilterRank > columnCount) {
                throw ClubcardError.Deserialize(
                    "index entry ${blockId.hex()} has rank ${entry.approxFilterRank} but the filter has $columnCount columns",
                )
            }
        }
        return Clubcard(universe, index, approxFilter, exactFilter)
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
        val approxFilterM = buf.u32()
        val approxFilterRank = buf.u8()
        val approxFilterOffset = buf.u32()
        val exactFilterM = buf.u32()
        val exactFilterOffset = buf.u32()
        val inverted = buf.u8()
        // revokt: spec §6.3, `inverted` is 0 or 1 (a C2SP MUST; upstream reads `!= 0`).
        if (inverted > 1) throw ClubcardError.Deserialize("inverted byte is $inverted, expected 0 or 1")

        val count = buf.readLen(2).toInt()
        val exceptions = ArrayList<ByteString>(count)
        for (i in 0 until count) exceptions.add(buf.readVec(1))

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
