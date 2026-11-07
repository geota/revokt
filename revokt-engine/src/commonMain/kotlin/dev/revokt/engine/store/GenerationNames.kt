// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.engine.c2sp.C2spIndex
import okio.ByteString.Companion.encodeUtf8

/**
 * The names spec §6.5 derives: a file's name in a generation (revision 48) and a generation's directory name. Both are
 * store key segments.
 */
internal object GenerationNames {
    /** §6.3's longest source filename. */
    const val MAX_SOURCE_FILENAME: Int = 64

    /** A derived name's length: [PREFIX] characters, `-` and [HASH_HEX] hex characters. */
    const val DERIVED_LENGTH: Int = 32

    private const val PREFIX = 15
    private const val HASH_HEX = 16
    private const val TIMESTAMP_DIGITS = 13
    private const val MAX_TIMESTAMP = 9_999_999_999_999L
    private const val DIRECTORY_LENGTH = 4 + TIMESTAMP_DIGITS + 1 + HASH_HEX
    private const val SHA256_HEX = 64

    /**
     * Whether [name] passes §6.3's filename rule, `^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$`, over the whole string. The
     * reserved names are the caller's check, where the name enters.
     */
    fun isSourceFilename(name: String): Boolean =
        name.length in 1..MAX_SOURCE_FILENAME && name != "." && name != ".." && name.all(StoreKeys::isNameChar)

    /**
     * The file's name in a generation for a §6.3-checked attachment or §7.3-checked manifest [filename]: [filename]
     * itself when it is a C2SP filename (at most 32 bytes), otherwise its first 15 characters, `-` and the first 16
     * lowercase hex characters of the SHA-256 of its ASCII bytes, 32 characters in all. Never the attachment's hash.
     */
    fun derive(filename: String): String {
        require(isSourceFilename(filename)) { "'$filename' is not a source filename" }
        if (C2spIndex.isFilename(filename)) return filename
        return filename.substring(0, PREFIX) + "-" + hash16(filename)
    }

    /**
     * A generation's directory name: `gen-`, [sourceTimestampMillis] zero-padded to 13 digits (so lexical order is
     * chronological), `-` and the first 16 lowercase hex characters of the SHA-256 of [generationId]'s UTF-8 bytes.
     */
    fun directory(
        sourceTimestampMillis: Long,
        generationId: String,
    ): String {
        require(sourceTimestampMillis in 0..MAX_TIMESTAMP) { "the timestamp $sourceTimestampMillis is not 13 digits" }
        require(generationId.isNotEmpty()) { "generationId is empty" }
        return "gen-" + sourceTimestampMillis.toString().padStart(TIMESTAMP_DIGITS, '0') + "-" + hash16(generationId)
    }

    /** Whether [name] has the shape [directory] produces. */
    fun isDirectory(name: String): Boolean =
        name.length == DIRECTORY_LENGTH &&
            name.startsWith("gen-") &&
            name[4 + TIMESTAMP_DIGITS] == '-' &&
            (4 until 4 + TIMESTAMP_DIGITS).all { name[it] in '0'..'9' } &&
            (DIRECTORY_LENGTH - HASH_HEX until DIRECTORY_LENGTH).all { isLowerHex(name[it]) }

    /** Whether [hex] is exactly 64 lowercase hex characters, a SHA-256 as a blob key segment. */
    fun isSha256Hex(hex: String): Boolean = hex.length == SHA256_HEX && hex.all(::isLowerHex)

    /** The first 16 lowercase hex characters of the SHA-256 of [s]'s UTF-8 bytes (ASCII for a source filename). */
    private fun hash16(s: String): String =
        s
            .encodeUtf8()
            .sha256()
            .hex()
            .substring(0, HASH_HEX)

    private fun isLowerHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f'
}
