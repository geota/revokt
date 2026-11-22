// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

/**
 * The key rule of `RevoktStorage` (spec §3): segments of `[A-Za-z0-9._-]{1,96}` joined by `/`, never `.` or `..`, and
 * never the reserved key `.lock`. The whole string is checked character by character, so no trailing newline, empty
 * segment or leading `/` passes, and no key resolves outside the store's root.
 */
internal object StoreKeys {
    const val MAX_SEGMENT: Int = 96

    /** The lock's key; no path but `lock()` ever opens, lists or deletes it. */
    const val LOCK: String = ".lock"

    fun isKey(name: String): Boolean {
        if (name == LOCK) return false
        var start = 0
        while (true) {
            val slash = name.indexOf('/', start)
            val end = if (slash < 0) name.length else slash
            if (!isSegment(name, start, end)) return false
            if (slash < 0) return true
            start = slash + 1
        }
    }

    fun requireKey(name: String) {
        require(isKey(name)) { "'$name' is not a store key" }
    }

    /** Whether [c] is one of `[A-Za-z0-9._-]`, the characters of a key segment and of a source filename (§6.3). */
    fun isNameChar(c: Char): Boolean =
        c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '.' || c == '_' || c == '-'

    private fun isSegment(
        name: String,
        start: Int,
        end: Int,
    ): Boolean {
        val length = end - start
        if (length !in 1..MAX_SEGMENT) return false
        // A segment of one or two characters that starts and ends with a dot is `.` or `..`.
        if (length <= 2 && name[start] == '.' && name[end - 1] == '.') return false
        for (i in start until end) if (!isNameChar(name[i])) return false
        return true
    }
}
