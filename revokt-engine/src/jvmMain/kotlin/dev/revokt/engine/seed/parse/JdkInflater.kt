// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

import java.util.zip.DataFormatException
import java.util.zip.Inflater

/** A fresh [RawInflater]. */
internal fun rawInflater(): RawInflater = JdkInflater()

/** [RawInflater] over `java.util.zip.Inflater` with `nowrap`, as `java.util.zip.ZipFile` reads a deflated entry. */
private class JdkInflater : RawInflater {
    private val inflater = Inflater(true)

    override val finished: Boolean get() = inflater.finished()

    override val needsInput: Boolean get() = inflater.needsInput()

    override val remaining: Int get() = inflater.remaining

    override fun setInput(
        input: ByteArray,
        offset: Int,
        length: Int,
    ) {
        inflater.setInput(input, offset, length)
    }

    override fun inflate(
        output: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        val n =
            try {
                inflater.inflate(output, offset, length)
            } catch (e: DataFormatException) {
                throw SeedFormatException("a malformed deflate stream: ${e.message}", e)
            }
        if (inflater.needsDictionary()) throw SeedFormatException("a deflate stream that needs a preset dictionary")
        return n
    }

    override fun end() {
        inflater.end()
    }
}
