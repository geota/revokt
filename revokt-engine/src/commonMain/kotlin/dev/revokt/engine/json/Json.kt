// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import dev.revokt.RevoktLimits

/** Why a JSON text was rejected. */
internal enum class JsonError {
    /** Longer than the cap the caller passed (`RevoktLimits.MAX_JSON_BYTES` by default); checked before reading. */
    TOO_LARGE,

    /** More than [Json.MAX_DEPTH] nested arrays and objects; checked before the container is allocated. */
    TOO_DEEP,

    /** The text ends inside a value, or holds none. */
    END_OF_INPUT,

    /** A byte that cannot start or continue a value here. */
    UNEXPECTED_BYTE,

    /** Bytes other than whitespace after the value. */
    TRAILING_BYTES,

    /** Not RFC 8259 number syntax (a leading zero, a bare `-`, `1.`, `1e`). */
    INVALID_NUMBER,

    /** A number whose magnitude rounds to infinity as a double. */
    NUMBER_OUT_OF_RANGE,

    /** A backslash not followed by one of `"\/bfnrt` or by `u` and four hex digits. */
    INVALID_ESCAPE,

    /** A `\u` escape of a surrogate that is not a high surrogate immediately followed by a `\u` low one (spec §7.1). */
    LONE_SURROGATE,

    /** An unescaped byte below 0x20 inside a string. */
    CONTROL_CHARACTER,

    /** A string byte sequence that is not well-formed UTF-8 (RFC 3629: no overlong forms, surrogates or values above U+10FFFF). */
    INVALID_UTF8,

    /** An object with two members of the same key after unescaping (spec §7.1). */
    DUPLICATE_KEY,
}

/** A rejected JSON text: [error] at byte [offset]. The only exception [Json.parse] throws. */
internal class JsonParseException(
    val error: JsonError,
    val offset: Int,
) : Exception("$error at byte $offset")

/**
 * The engine's JSON tokenizer and parser (spec §7.1 "JSON"): RFC 8259 over UTF-8 bytes, rejecting duplicate keys and
 * unpaired surrogates. The size cap is checked before anything is read and the depth before each container is
 * allocated; every string, array and object is bounded by the bytes it was read from. Numbers follow serde_json, the
 * parser `canonical_json` 0.7.0 is used with: an integer literal is a [JsonInteger] within `u64` (non-negative) or
 * `i64` (negative, not `-0`), every other number the correctly rounded [JsonDouble].
 */
internal object Json {
    /** serde_json's recursion limit: it rejects the 128th nested container, so the oracle and revokt agree on depth. */
    const val MAX_DEPTH: Int = 127

    fun parse(
        bytes: ByteArray,
        maxBytes: Long = RevoktLimits.MAX_JSON_BYTES,
    ): JsonValue {
        if (bytes.size > maxBytes) throw JsonParseException(JsonError.TOO_LARGE, 0)
        return Parser(bytes).document()
    }
}

private class Parser(
    private val b: ByteArray,
) {
    private var pos = 0

    fun document(): JsonValue {
        val value = value(0)
        skipWhitespace()
        if (pos < b.size) fail(JsonError.TRAILING_BYTES)
        return value
    }

    private fun fail(
        error: JsonError,
        at: Int = pos,
    ): Nothing = throw JsonParseException(error, at)

    private fun peek(): Int = if (pos < b.size) b[pos].toInt() and 0xFF else fail(JsonError.END_OF_INPUT)

    private fun skipWhitespace() {
        while (pos < b.size) {
            when (b[pos].toInt()) {
                0x20, 0x09, 0x0A, 0x0D -> pos++
                else -> return
            }
        }
    }

    private fun value(depth: Int): JsonValue {
        skipWhitespace()
        return when (peek().toChar()) {
            '{' -> obj(depth + 1)
            '[' -> array(depth + 1)
            '"' -> JsonString(string())
            't' -> literal("true", JsonBoolean.TRUE)
            'f' -> literal("false", JsonBoolean.FALSE)
            'n' -> literal("null", JsonNull)
            '-', in '0'..'9' -> number()
            else -> fail(JsonError.UNEXPECTED_BYTE)
        }
    }

    private fun literal(
        text: String,
        value: JsonValue,
    ): JsonValue {
        for (c in text) {
            if (peek() != c.code) fail(JsonError.UNEXPECTED_BYTE)
            pos++
        }
        return value
    }

    /** Skips whitespace and consumes [close] or a comma, failing on anything else; true when [close] ended it. */
    private fun closes(close: Char): Boolean {
        skipWhitespace()
        val c = peek()
        pos++
        return when (c) {
            close.code -> true
            ','.code -> false
            else -> fail(JsonError.UNEXPECTED_BYTE, pos - 1)
        }
    }

    private fun array(depth: Int): JsonValue {
        if (depth > Json.MAX_DEPTH) fail(JsonError.TOO_DEEP)
        pos++
        skipWhitespace()
        if (peek() == ']'.code) {
            pos++
            return JsonArray.EMPTY
        }
        val items = ArrayList<JsonValue>()
        do {
            items.add(value(depth))
        } while (!closes(']'))
        return JsonArray(items)
    }

    private fun obj(depth: Int): JsonValue {
        if (depth > Json.MAX_DEPTH) fail(JsonError.TOO_DEEP)
        val start = pos
        pos++
        skipWhitespace()
        if (peek() == '}'.code) {
            pos++
            return JsonObject.EMPTY
        }
        val members = ArrayList<Pair<String, JsonValue>>()
        do {
            skipWhitespace()
            if (peek() != '"'.code) fail(JsonError.UNEXPECTED_BYTE)
            val key = string()
            skipWhitespace()
            if (peek() != ':'.code) fail(JsonError.UNEXPECTED_BYTE)
            pos++
            members.add(key to value(depth))
        } while (!closes('}'))
        return JsonObject.ofOrNull(members) ?: fail(JsonError.DUPLICATE_KEY, start)
    }

    /** A string from its opening quote: ASCII without escapes is decoded in one step, anything else unit by unit. */
    private fun string(): String {
        val start = ++pos
        while (pos < b.size) {
            val c = b[pos].toInt()
            if (c == '"'.code) return b.decodeToString(start, pos++)
            if (c == '\\'.code || c < 0x20 || c >= 0x7F) break
            pos++
        }
        val out = StringBuilder(pos - start + 16)
        for (i in start until pos) out.append(b[i].toInt().toChar())
        while (true) {
            val c = peek()
            when {
                c == '"'.code -> {
                    pos++
                    return out.toString()
                }

                c == '\\'.code -> {
                    escape(out)
                }

                c < 0x20 -> {
                    fail(JsonError.CONTROL_CHARACTER)
                }

                c < 0x80 -> {
                    out.append(c.toChar())
                    pos++
                }

                else -> {
                    utf8(c, out)
                }
            }
        }
    }

    private fun escape(out: StringBuilder) {
        val at = pos
        pos++
        val c = peek()
        pos++
        when (c.toChar()) {
            '"', '\\', '/' -> out.append(c.toChar())
            'b' -> out.append('\b')
            'f' -> out.append('\u000C')
            'n' -> out.append('\n')
            'r' -> out.append('\r')
            't' -> out.append('\t')
            'u' -> unicodeEscape(at, out)
            else -> fail(JsonError.INVALID_ESCAPE, at)
        }
    }

    /** After `\u`: a non-surrogate, or a high surrogate whose `\u` low surrogate follows at once. */
    private fun unicodeEscape(
        at: Int,
        out: StringBuilder,
    ) {
        val unit = hex4(at)
        if (unit in 0xDC00..0xDFFF) fail(JsonError.LONE_SURROGATE, at)
        if (unit in 0xD800..0xDBFF) {
            val low = pos
            if (pos + 1 >= b.size || b[pos] != '\\'.code.toByte() || b[pos + 1] != 'u'.code.toByte()) {
                fail(JsonError.LONE_SURROGATE, at)
            }
            pos += 2
            val second = hex4(low)
            if (second !in 0xDC00..0xDFFF) fail(JsonError.LONE_SURROGATE, at)
            out.append(unit.toChar()).append(second.toChar())
            return
        }
        out.append(unit.toChar())
    }

    private fun hex4(at: Int): Int {
        var unit = 0
        repeat(4) {
            val digit =
                when (val c = peek()) {
                    in '0'.code..'9'.code -> c - '0'.code
                    in 'a'.code..'f'.code -> c - 'a'.code + 10
                    in 'A'.code..'F'.code -> c - 'A'.code + 10
                    else -> fail(JsonError.INVALID_ESCAPE, at)
                }
            unit = unit * 16 + digit
            pos++
        }
        return unit
    }

    /** One multi-byte UTF-8 sequence from its lead byte [lead], appended as UTF-16. */
    private fun utf8(
        lead: Int,
        out: StringBuilder,
    ) {
        val at = pos
        val (count, low, high) = utf8Lead(lead) ?: fail(JsonError.INVALID_UTF8)
        var cp = lead and (0x3F shr count)
        for (i in 1..count) {
            if (at + i >= b.size) fail(JsonError.INVALID_UTF8, at)
            val c = b[at + i].toInt() and 0xFF
            if (c !in (if (i == 1) low else 0x80)..(if (i == 1) high else 0xBF)) fail(JsonError.INVALID_UTF8, at)
            cp = (cp shl 6) or (c and 0x3F)
        }
        pos = at + count + 1
        if (cp < 0x10000) {
            out.append(cp.toChar())
        } else {
            out.append((0xD800 + ((cp - 0x10000) shr 10)).toChar()).append((0xDC00 + (cp and 0x3FF)).toChar())
        }
    }

    /** RFC 8259 number syntax, then serde_json's classification: an integer literal in range, else a double. */
    private fun number(): JsonValue {
        val start = pos
        val negative = skip('-')
        val intStart = pos
        if (peek() == '0'.code) {
            pos++
            if (pos < b.size && isDigit(b[pos])) fail(JsonError.INVALID_NUMBER)
        } else {
            digits()
        }
        val intEnd = pos
        val fraction = skip('.')
        if (fraction) digits()
        val exponent = skip('e') || skip('E')
        if (exponent) {
            if (!skip('+')) skip('-')
            digits()
        }
        if (!fraction && !exponent) integer(negative, intStart, intEnd)?.let { return it }
        val value = b.decodeToString(start, pos).toDouble()
        if (!value.isFinite()) fail(JsonError.NUMBER_OUT_OF_RANGE, start)
        return JsonDouble(value)
    }

    /** Consumes [c] when it is next. */
    private fun skip(c: Char): Boolean = (pos < b.size && b[pos] == c.code.toByte()).also { if (it) pos++ }

    /** One or more digits. */
    private fun digits() {
        if (pos >= b.size) fail(JsonError.END_OF_INPUT)
        if (!isDigit(b[pos])) fail(JsonError.INVALID_NUMBER)
        while (pos < b.size && isDigit(b[pos])) pos++
    }

    /** The integer of digits `[from, to)`, or null when serde_json reads it as a double (overflow, or `-0`). */
    private fun integer(
        negative: Boolean,
        from: Int,
        to: Int,
    ): JsonInteger? {
        if (to - from > 20) return null
        var magnitude = 0uL
        for (i in from until to) {
            val digit = (b[i] - '0'.code.toByte()).toULong()
            if (magnitude > (ULong.MAX_VALUE - digit) / 10uL) return null
            magnitude = magnitude * 10uL + digit
        }
        return when {
            !negative -> JsonInteger(false, magnitude)
            magnitude in 1uL..(1uL shl 63) -> JsonInteger(true, magnitude)
            else -> null
        }
    }

    private fun isDigit(c: Byte): Boolean = c in '0'.code.toByte()..'9'.code.toByte()
}

/**
 * The continuation bytes after a UTF-8 lead byte and the range of the first (RFC 3629 table 3-7: no overlong form, no
 * surrogate, nothing above U+10FFFF), every later one being 0x80 to 0xBF; null for a byte that cannot lead.
 */
private fun utf8Lead(lead: Int): Triple<Int, Int, Int>? =
    when (lead) {
        in 0xC2..0xDF -> Triple(1, 0x80, 0xBF)
        0xE0 -> Triple(2, 0xA0, 0xBF)
        in 0xE1..0xEC, 0xEE, 0xEF -> Triple(2, 0x80, 0xBF)
        0xED -> Triple(2, 0x80, 0x9F)
        0xF0 -> Triple(3, 0x90, 0xBF)
        in 0xF1..0xF3 -> Triple(3, 0x80, 0xBF)
        0xF4 -> Triple(3, 0x80, 0x8F)
        else -> null
    }
