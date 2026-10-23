// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * Test-only encoders for both wire formats (spec §6.3), written from the format description so a malformed filter
 * can be produced field by field. The structure is a plain description, not a port type, so the tests can write
 * values the decoders must reject (an `inverted` of 2, an unsorted index, a lying length).
 */
internal class TestCoverage(
    val logId: ByteString,
    val low: Long,
    val high: Long,
)

internal class TestIndexEntry(
    val blockId: ByteString,
    val approxM: Long = 0,
    val rank: Long = 0,
    val approxOffset: Long = 0,
    val exactM: Long = 0,
    val exactOffset: Long = 0,
    val inverted: Int = 0,
    val exceptions: List<ByteString> = emptyList(),
)

internal class TestFilter(
    val coverage: List<TestCoverage> = emptyList(),
    val index: List<TestIndexEntry> = emptyList(),
    val approx: List<LongArray> = emptyList(),
    val exact: LongArray = LongArray(0),
)

internal fun bytesOf(
    value: Int,
    size: Int = 32,
): ByteString = ByteArray(size) { value.toByte() }.toByteString()

internal object TestFilterWriter {
    /** v4: the 2-byte prefix, then the C2SP body, big-endian. */
    fun v4(
        filter: TestFilter,
        trailing: ByteArray = ByteArray(0),
    ): ByteArray {
        val b = Buffer().writeByte(4).writeByte(0)
        b.writeShort(filter.coverage.size)
        for (c in filter.coverage) b.write(c.logId).writeLong(c.low).writeLong(c.high)
        b.writeInt(filter.index.size)
        for (e in filter.index) {
            b.write(e.blockId)
            b.writeInt(e.approxM.toInt()).writeByte(e.rank.toInt()).writeInt(e.approxOffset.toInt())
            b.writeInt(e.exactM.toInt()).writeInt(e.exactOffset.toInt()).writeByte(e.inverted)
            b.writeShort(e.exceptions.size)
            for (x in e.exceptions) b.writeByte(x.size).write(x)
        }
        b.writeByte(filter.approx.size)
        for (column in filter.approx) {
            b.writeInt(column.size)
            for (w in column) b.writeLong(w)
        }
        b.writeInt(filter.exact.size)
        for (w in filter.exact) b.writeLong(w)
        b.write(trailing)
        return b.readByteArray()
    }

    /** v3: the 2-byte prefix, then the bincode 1.x body, little-endian with `u64` lengths. */
    fun v3(
        filter: TestFilter,
        trailing: ByteArray = ByteArray(0),
    ): ByteArray {
        val b = Buffer().writeByte(3).writeByte(0)
        b.writeLongLe(filter.coverage.size.toLong())
        for (c in filter.coverage) b.write(c.logId).writeLongLe(c.low).writeLongLe(c.high)
        b.writeLongLe(filter.index.size.toLong())
        for (e in filter.index) {
            b.writeLongLe(e.blockId.size.toLong()).write(e.blockId)
            b.writeLongLe(e.approxM).writeLongLe(e.exactM).writeLongLe(e.rank)
            b.writeLongLe(e.approxOffset).writeLongLe(e.exactOffset).writeByte(e.inverted)
            b.writeLongLe(e.exceptions.size.toLong())
            for (x in e.exceptions) b.writeLongLe(x.size.toLong()).write(x)
        }
        b.writeLongLe(filter.approx.size.toLong())
        for (column in filter.approx) {
            b.writeLongLe(column.size.toLong())
            for (w in column) b.writeLongLe(w)
        }
        b.writeLongLe(filter.exact.size.toLong())
        for (w in filter.exact) b.writeLongLe(w)
        b.write(trailing)
        return b.readByteArray()
    }
}
