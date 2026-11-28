// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.clubcard.api

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.port.ByteReader
import dev.revokt.clubcard.port.ClubcardError
import dev.revokt.clubcard.port.CrliteClubcard
import dev.revokt.clubcard.port.CrliteCoverage
import dev.revokt.clubcard.port.Encoding
import dev.revokt.clubcard.port.WORD_WIDTH

/**
 * Apache-licensed glue over the MPL-2.0 port in `dev.revokt.clubcard.port` (spec §3.1 item 2): the one entry point
 * that turns filter bytes into a [CrliteClubcard] ([decode]), and the coverage-only read beside it ([coverage]). The
 * 2-byte prefix selects the decoder (spec §6.3): v4 is the port's own C2SP reader; v3 (bincode 1.x) has no upstream
 * reader to translate and is [BincodeV3], written here.
 */
@RevoktInternalApi
public object ClubcardFilters {
    /** Word width of the ribbon filter, the `W = 4` of spec §6.2. */
    public val wordWidth: Int get() = WORD_WIDTH

    /** The encoding named by the 2-byte prefix, or a [ClubcardFormatException] for an unknown or malformed prefix. */
    public fun encodingOf(bytes: ByteArray): Encoding = translating { Encoding.read(ByteReader(bytes)) }

    /**
     * Decodes a complete filter (a full filter or a delta: each is a clubcard with its own coverage and index).
     * Every rule of spec §6.3 applies: v4 trailing bytes are rejected and v3 trailing bytes accepted; `inverted` is
     * 0 or 1 (a deviation from upstream on v4 only; bincode already enforces it on v3); the index is sorted and log ids are distinct; a rank past the last column is rejected; every length
     * is checked against the remaining input before anything is allocated.
     */
    public fun decode(bytes: ByteArray): CrliteClubcard =
        translating {
            val buf = ByteReader(bytes)
            when (Encoding.read(buf)) {
                Encoding.V3 -> CrliteClubcard(BincodeV3.readClubcard(buf))
                Encoding.V4 -> CrliteClubcard.fromBytes(bytes)
            }
        }

    /**
     * Reads only a filter's coverage (spec §6.5 Load): the 2-byte prefix, then the coverage, the first field of the body
     * in both encodings, through the readers [decode] uses, so its rules hold (log ids distinct; the count bounded, by
     * the remaining input on v3 and by its `u16` on v4, before anything is allocated). Nothing after the coverage is
     * read: whenever [decode] returns a filter this returns its [CrliteClubcard.universe], equal entry for entry and in
     * the same order, but a filter whose coverage reads and whose rest does not decode returns its coverage here and
     * fails [decode].
     */
    public fun coverage(bytes: ByteArray): CrliteCoverage =
        translating {
            val buf = ByteReader(bytes)
            when (Encoding.read(buf)) {
                Encoding.V3 -> BincodeV3.readCoverage(buf)
                Encoding.V4 -> CrliteCoverage.read(buf)
            }
        }

    private inline fun <T> translating(block: () -> T): T =
        try {
            block()
        } catch (e: ClubcardError) {
            throw ClubcardFormatException(e.message ?: "malformed clubcard", e)
        }
}
