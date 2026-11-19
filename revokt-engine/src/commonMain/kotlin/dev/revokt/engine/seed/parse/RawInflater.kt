// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

/**
 * One raw deflate stream's inflater (RFC 1951, no zlib wrapper), for a seed archive's deflated entries (spec §6.5). Common
 * Okio has no inflater (`InflaterSource` is JVM-only), so the archive reader is common code over this seam: the JVM's is
 * `java.util.zip.Inflater`, and the linuxX64 purity gate only compiles (spec §3).
 */
internal interface RawInflater {
    /** Whether the end of the deflate stream was reached. */
    val finished: Boolean

    /** Whether every input byte given so far was consumed. */
    val needsInput: Boolean

    /** The input bytes given and not consumed: after [finished], the bytes past the end of the stream. */
    val remaining: Int

    fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    )

    /**
     * Inflates into [output] from [offset], at most [length] bytes, and returns the count. A malformed stream, and one
     * that needs a preset dictionary, throws [SeedFormatException].
     */
    fun inflate(
        output: ByteArray,
        offset: Int,
        length: Int,
    ): Int

    /** Releases the inflater's native state. */
    fun end()
}

/** A fresh [RawInflater]. */
internal expect fun rawInflater(): RawInflater
