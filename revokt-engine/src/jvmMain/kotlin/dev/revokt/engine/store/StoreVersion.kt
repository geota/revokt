// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

/**
 * `store.version` (spec §6.5): the store layout's version, read before anything else at `start()`. The file holds ASCII
 * decimal `[1-9][0-9]{0,8}` and nothing else: no sign, no leading zero, no space and no newline. The writer writes
 * [CURRENT].
 */
internal object StoreVersion {
    /** The key of the file. */
    const val KEY: String = StoreKeys.VERSION

    /** This engine's layout. */
    const val CURRENT: Int = 1

    private const val MAX_DIGITS = 9
    private const val RADIX = 10

    /** The version [bytes] hold, or null when they are not exactly `[1-9][0-9]{0,8}`; never throws. */
    fun parse(bytes: ByteArray): Int? {
        if (bytes.isEmpty() || bytes.size > MAX_DIGITS || bytes[0] == '0'.code.toByte()) return null
        var version = 0
        for (b in bytes) {
            val digit = b - '0'.code.toByte()
            if (digit !in 0 until RADIX) return null
            version = version * RADIX + digit
        }
        return version
    }

    /** [version]'s bytes, which [parse] reads back to it; [version] must be one [parse] can return. */
    fun encode(version: Int): ByteArray {
        require(version >= 1) { "a store version is positive: $version" }
        return version.toString().encodeToByteArray().also { check(it.size <= MAX_DIGITS) { "too many digits" } }
    }
}
