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
 * `i64` (negative, not `-0`), every other number the nearest [JsonDouble] (ties to even), computed exactly by
 * [DecimalDouble], never by the platform's `String.toDouble()`.
 *
 * Allocation (spec §6.5, #99): at most 4·len + 64 KiB on Remote Settings–shaped input (a changeset or `records.json`)
 * and 20·len + 64 KiB on any input, measured after one warm-up decode of `{}` on the same thread. Nothing is retained
 * across calls but constants (the empty values, `true`, `false`, `null`): every buffer and table belongs to one parse
 * and counts toward that parse. So containers collect their members on one scratch stack per parse and are
 * copied out at exact size, objects are sorted parallel arrays, a one-item array holds its item, the integers 0 to 1023
 * and short escape-free strings are shared within a parse, and decimals are converted without a `String`, in buffers
 * reused across the parse.
 */
internal object Json {
    /** serde_json's recursion limit: it rejects the 128th nested container, so the oracle and revokt agree on depth. */
    const val MAX_DEPTH: Int = 127

    /** One document through every path of the parser, and one rejection: see the `init` block. */
    private val PRELOAD =
        "{\"a\":[1,-1,18446744073709551615,0.5,1.5e300,4.9e-324,\"\u00e9\\n\\u00e9\",true,false,null,{}]," +
            "\"b\":{\"c\":[[]]}}"

    init {
        // Spec §6.5 measures a parse's allocation after one warm-up decode of `{}`. Loading and initialising the
        // classes a document reaches is a one-time cost of the process, not of a parse, so it is done here, when the
        // first decode (that warm-up) initialises this object.
        Parser(PRELOAD.encodeToByteArray()).document()
        try {
            Parser(byteArrayOf('['.code.toByte())).document()
        } catch (_: JsonParseException) {
            // The rejection path's classes are loaded too.
        }
    }

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
    private val strings = Strings(b)
    private var decimal: DecimalDouble? = null
    private var smallIntegers: Array<JsonInteger?>? = null

    /** The members of every open container, innermost last; [keys] holds the open objects' keys. */
    private var values = Array<JsonValue>(16) { JsonNull }
    private var top = 0
    private var keys = Array(16) { "" }
    private var keyTop = 0

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
            '"' -> string()
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

    private fun push(value: JsonValue) {
        if (top == values.size) values = values.let { old -> Array(top * 2) { if (it < top) old[it] else JsonNull } }
        values[top++] = value
    }

    private fun pushKey(key: String) {
        if (keyTop == keys.size) keys = keys.let { old -> Array(keyTop * 2) { if (it < keyTop) old[it] else "" } }
        keys[keyTop++] = key
    }

    private fun array(depth: Int): JsonValue {
        if (depth > Json.MAX_DEPTH) fail(JsonError.TOO_DEEP)
        pos++
        skipWhitespace()
        if (peek() == ']'.code) {
            pos++
            return JsonArray.EMPTY
        }
        val first = value(depth)
        if (closes(']')) return JsonArray.of(first)
        val mark = top
        push(first)
        do {
            push(value(depth))
        } while (!closes(']'))
        val items = Array(top - mark) { values[mark + it] }
        top = mark
        return JsonArray.owning(items)
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
        val mark = top
        val keyMark = keyTop
        do {
            skipWhitespace()
            if (peek() != '"'.code) fail(JsonError.UNEXPECTED_BYTE)
            pushKey(string().value)
            skipWhitespace()
            if (peek() != ':'.code) fail(JsonError.UNEXPECTED_BYTE)
            pos++
            push(value(depth))
        } while (!closes('}'))
        val memberKeys = Array(keyTop - keyMark) { keys[keyMark + it] }
        val memberValues = Array(top - mark) { values[mark + it] }
        top = mark
        keyTop = keyMark
        return JsonObject.owningOrNull(memberKeys, memberValues) ?: fail(JsonError.DUPLICATE_KEY, start)
    }

    /** A string from its opening quote. */
    private fun string(): JsonString {
        val start = pos + 1
        val end = strings.scan(start)
        pos = end + 1
        return strings.read(start, end)
    }

    /** The parse's one instance of [value], below [SMALL_INTEGERS]; the table is the parse's own, not static. */
    private fun small(value: Int): JsonInteger {
        val table = smallIntegers ?: arrayOfNulls<JsonInteger>(SMALL_INTEGERS).also { smallIntegers = it }
        return table[value] ?: JsonInteger(false, value.toULong()).also { table[value] = it }
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
        return double(start, intStart, negative)
    }

    /** The double of the number lexeme from [start], its digits from [digitsStart]. */
    private fun double(
        start: Int,
        digitsStart: Int,
        negative: Boolean,
    ): JsonDouble {
        val magnitude = (decimal ?: DecimalDouble().also { decimal = it }).parse(b, digitsStart, pos)
        if (magnitude.isInfinite()) fail(JsonError.NUMBER_OUT_OF_RANGE, start)
        return JsonDouble(if (negative) -magnitude else magnitude)
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
            !negative && magnitude < SMALL_INTEGERS.toULong() -> small(magnitude.toInt())
            !negative -> JsonInteger(false, magnitude)
            magnitude in 1uL..(1uL shl 63) -> JsonInteger(true, magnitude)
            else -> null
        }
    }
}

/** Integers below this are shared within a parse. */
private const val SMALL_INTEGERS = 1024

private fun isDigit(c: Byte): Boolean = c in '0'.code.toByte()..'9'.code.toByte()

/**
 * The strings of one parse: each is validated in one pass and decoded once. Escape-free strings of at most
 * [SHARED_BYTES] bytes are shared within the parse ([SharedValues]), so repeated keys and values cost one copy.
 */
private class Strings(
    private val b: ByteArray,
) {
    private val table = SharedValues(b)
    private var escaped = false

    private fun fail(
        error: JsonError,
        at: Int,
    ): Nothing = throw JsonParseException(error, at)

    /** Validates the string whose content starts at [start] and returns the index of its closing quote. */
    fun scan(start: Int): Int {
        escaped = false
        var i = start
        while (true) {
            if (i >= b.size) fail(JsonError.END_OF_INPUT, i)
            val c = b[i].toInt() and 0xFF
            i =
                when {
                    c == '"'.code -> return i
                    c == '\\'.code -> escape(i)
                    c < 0x20 -> fail(JsonError.CONTROL_CHARACTER, i)
                    c < 0x80 -> i + 1
                    else -> utf8(c, i)
                }
        }
    }

    /** The string [scan] just validated, content `[start, end)`. */
    fun read(
        start: Int,
        end: Int,
    ): JsonString =
        when {
            escaped -> JsonString(unescape(start, end))
            end == start -> EMPTY
            end - start > SHARED_BYTES -> JsonString(b.decodeToString(start, end))
            else -> share(start, end - start)
        }

    private fun share(
        start: Int,
        length: Int,
    ): JsonString {
        val slot = table.slot(start, length)
        return table[slot] as JsonString?
            ?: JsonString(b.decodeToString(start, start + length)).also { table.put(slot, start, length, it) }
    }

    /** Validates the escape whose backslash is at [at]; returns the index after it. */
    private fun escape(at: Int): Int {
        if (at + 1 >= b.size) fail(JsonError.END_OF_INPUT, b.size)
        return when (b[at + 1].toInt().toChar()) {
            '"', '\\', '/', 'b', 'f', 'n', 'r', 't' -> at + 2
            'u' -> unicodeEscape(at)
            else -> fail(JsonError.INVALID_ESCAPE, at)
        }.also { escaped = true }
    }

    /** `\u` at [at]: a non-surrogate, or a high surrogate whose `\u` low surrogate follows at once. */
    private fun unicodeEscape(at: Int): Int {
        val unit = hex4(at + 2, at)
        if (unit in 0xDC00..0xDFFF) fail(JsonError.LONE_SURROGATE, at)
        if (unit !in 0xD800..0xDBFF) return at + 6
        val low = at + 6
        if (low + 1 >= b.size || b[low] != '\\'.code.toByte() || b[low + 1] != 'u'.code.toByte()) {
            fail(JsonError.LONE_SURROGATE, at)
        }
        if (hex4(low + 2, low) !in 0xDC00..0xDFFF) fail(JsonError.LONE_SURROGATE, at)
        return low + 6
    }

    /** The four hex digits at [from], of the escape at [at]. */
    private fun hex4(
        from: Int,
        at: Int,
    ): Int {
        var unit = 0
        for (i in from until from + 4) {
            if (i >= b.size) fail(JsonError.END_OF_INPUT, b.size)
            val digit = hexDigit(b[i].toInt())
            if (digit < 0) fail(JsonError.INVALID_ESCAPE, at)
            unit = unit * 16 + digit
        }
        return unit
    }

    /** Validates the multi-byte UTF-8 sequence led by [lead] at [at] (RFC 3629 table 3-7); returns the index after it. */
    private fun utf8(
        lead: Int,
        at: Int,
    ): Int {
        val bounds = utf8Lead(lead)
        if (bounds < 0) fail(JsonError.INVALID_UTF8, at)
        val count = bounds and 0xFF
        for (i in 1..count) {
            if (at + i >= b.size) fail(JsonError.INVALID_UTF8, at)
            val c = b[at + i].toInt() and 0xFF
            val low = if (i == 1) (bounds ushr 8) and 0xFF else 0x80
            val high = if (i == 1) bounds ushr 16 else 0xBF
            if (c !in low..high) fail(JsonError.INVALID_UTF8, at)
        }
        return at + count + 1
    }

    /** Decodes the validated content `[start, end)`, which holds an escape, into at most one UTF-16 unit per byte. */
    private fun unescape(
        start: Int,
        end: Int,
    ): String {
        val out = CharArray(end - start)
        var n = 0
        var i = start
        while (i < end) {
            val c = b[i].toInt() and 0xFF
            when {
                c == '\\'.code -> {
                    val e = b[i + 1].toInt().toChar()
                    out[n++] = if (e == 'u') hex4(i + 2, i).toChar() else unescaped(e)
                    i += if (e == 'u') 6 else 2
                }

                c < 0x80 -> {
                    out[n++] = c.toChar()
                    i++
                }

                else -> {
                    val count = utf8Lead(c) and 0xFF
                    var cp = c and (0x3F shr count)
                    for (j in 1..count) cp = (cp shl 6) or (b[i + j].toInt() and 0x3F)
                    if (cp < 0x10000) {
                        out[n++] = cp.toChar()
                    } else {
                        out[n++] = (0xD800 + ((cp - 0x10000) shr 10)).toChar()
                        out[n++] = (0xDC00 + (cp and 0x3FF)).toChar()
                    }
                    i += count + 1
                }
            }
        }
        return out.concatToString(0, n)
    }

    companion object {
        const val SHARED_BYTES = 64
        val EMPTY = JsonString("")
    }
}

/** The character a validated one-letter escape stands for. */
private fun unescaped(e: Char): Char =
    when (e) {
        'b' -> '\b'
        'f' -> '\u000C'
        'n' -> '\n'
        'r' -> '\r'
        't' -> '\t'
        else -> e
    }

/**
 * Values shared within one parse, keyed by their bytes in the input: a fixed open-addressing table of [SLOTS] slots,
 * allocated on first use and filled to three quarters, so its cost is constant (about 12 KiB).
 */
private class SharedValues(
    private val b: ByteArray,
) {
    private var starts = IntArray(0)
    private var lengths = IntArray(0)
    private var values = arrayOfNulls<JsonValue>(0)
    private var count = 0

    /** The slot holding the bytes `[start, start + length)`, or the free slot where they belong. */
    fun slot(
        start: Int,
        length: Int,
    ): Int {
        if (values.isEmpty()) {
            starts = IntArray(SLOTS)
            lengths = IntArray(SLOTS)
            values = arrayOfNulls(SLOTS)
        }
        var h = -0x7ee3623b
        for (i in start until start + length) h = (h xor b[i].toInt()) * 0x01000193
        var slot = (h xor (h ushr 16)) and (SLOTS - 1)
        while (values[slot] != null && !(lengths[slot] == length && sameBytes(starts[slot], start, length))) {
            slot = (slot + 1) and (SLOTS - 1)
        }
        return slot
    }

    operator fun get(slot: Int): JsonValue? = values[slot]

    /** Stores [value] in the free [slot] while the table is under three quarters full. */
    fun put(
        slot: Int,
        start: Int,
        length: Int,
        value: JsonValue,
    ) {
        if (count >= SLOTS * 3 / 4) return
        starts[slot] = start
        lengths[slot] = length
        values[slot] = value
        count++
    }

    private fun sameBytes(
        a: Int,
        c: Int,
        length: Int,
    ): Boolean {
        for (i in 0 until length) if (b[a + i] != b[c + i]) return false
        return true
    }

    companion object {
        const val SLOTS = 1024
    }
}

private fun hexDigit(c: Int): Int =
    when (c) {
        in '0'.code..'9'.code -> c - '0'.code
        in 'a'.code..'f'.code -> c - 'a'.code + 10
        in 'A'.code..'F'.code -> c - 'A'.code + 10
        else -> -1
    }

/**
 * A UTF-8 lead byte's continuation count (bits 0–7) and the first continuation byte's range, low (bits 8–15) and high
 * (bits 16–23), per RFC 3629 table 3-7: no overlong form, no surrogate, nothing above U+10FFFF; every later continuation
 * byte is 0x80 to 0xBF. -1 for a byte that cannot lead.
 */
private fun utf8Lead(lead: Int): Int =
    when (lead) {
        in 0xC2..0xDF -> 1 or (0x80 shl 8) or (0xBF shl 16)
        0xE0 -> 2 or (0xA0 shl 8) or (0xBF shl 16)
        in 0xE1..0xEC, 0xEE, 0xEF -> 2 or (0x80 shl 8) or (0xBF shl 16)
        0xED -> 2 or (0x80 shl 8) or (0x9F shl 16)
        0xF0 -> 3 or (0x90 shl 8) or (0xBF shl 16)
        in 0xF1..0xF3 -> 3 or (0x80 shl 8) or (0xBF shl 16)
        0xF4 -> 3 or (0x80 shl 8) or (0x8F shl 16)
        else -> -1
    }
