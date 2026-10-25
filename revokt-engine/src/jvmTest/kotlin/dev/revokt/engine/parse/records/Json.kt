// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

/**
 * The JSON the corpus records use (spec §9.2 "Corpus record schema"): objects, arrays, strings, booleans and null, no
 * numbers. Written with keys in insertion order, one record per line, so a regenerated file diffs cleanly. The parser
 * also reads numbers, as their text, for the inputs of other corpora (`x509-limbo`'s `limbo.json`).
 */
internal sealed class Json {
    class Obj(
        val fields: Map<String, Json>,
    ) : Json() {
        operator fun get(key: String): Json? = fields[key]

        fun string(key: String): String = stringOrNull(key) ?: error("missing string $key")

        /** The string at [key], null when absent; a value of another type fails. */
        fun stringOrNull(key: String): String? = typed<Str>(key)?.value

        fun strings(key: String): List<String> =
            array(key).map { (it as? Str ?: error("$key holds a non-string")).value }

        fun boolOrNull(key: String): Boolean? = typed<Bool>(key)?.value

        fun array(key: String): List<Json> = typed<Arr>(key)?.items ?: error("missing array $key")

        fun child(key: String): Obj = childOrNull(key) ?: error("missing object $key")

        fun childOrNull(key: String): Obj? = typed<Obj>(key)

        /** This object, after checking it has no key outside [keys]. */
        fun only(keys: Set<String>): Obj =
            also { check(keys.containsAll(fields.keys)) { "unknown keys ${fields.keys - keys}" } }

        private inline fun <reified T : Json> typed(key: String): T? =
            when (val v = fields[key]) {
                null -> null
                is T -> v
                else -> error("$key is not a ${T::class.simpleName}")
            }
    }

    class Arr(
        val items: List<Json>,
    ) : Json()

    class Str(
        val value: String,
    ) : Json()

    class Bool(
        val value: Boolean,
    ) : Json()

    object Null : Json()

    /** A number as its JSON text; read only, never written in a record. */
    class Num(
        val text: String,
    ) : Json()

    fun write(): String = StringBuilder().also { write(it) }.toString()

    private fun write(out: StringBuilder) {
        when (this) {
            is Obj -> {
                out.append('{')
                fields.entries.forEachIndexed { i, (k, v) ->
                    if (i > 0) out.append(',')
                    quote(k, out)
                    out.append(':')
                    v.write(out)
                }
                out.append('}')
            }

            is Arr -> {
                out.append('[')
                items.forEachIndexed { i, v ->
                    if (i > 0) out.append(',')
                    v.write(out)
                }
                out.append(']')
            }

            is Str -> {
                quote(value, out)
            }

            is Bool -> {
                out.append(value)
            }

            Null -> {
                out.append("null")
            }

            is Num -> {
                error("a record holds no numbers")
            }
        }
    }

    companion object {
        fun obj(vararg fields: Pair<String, Json?>): Obj =
            Obj(
                fields.filter { it.second != null }.associate {
                    it.first to
                        it.second!!
                },
            )

        fun str(value: String?): Str? = value?.let(::Str)

        fun strings(values: List<String>): Arr = Arr(values.map(::Str))

        fun parse(text: String): Json =
            Parser(text).run {
                value().also {
                    skipSpace()
                    check(pos == text.length) { "trailing text at $pos" }
                }
            }

        private fun quote(
            s: String,
            out: StringBuilder,
        ) {
            out.append('"')
            for (c in s) {
                when {
                    c == '"' -> out.append("\\\"")
                    c == '\\' -> out.append("\\\\")
                    c == '\n' -> out.append("\\n")
                    c < ' ' -> out.append("\\u%04x".format(c.code))
                    else -> out.append(c)
                }
            }
            out.append('"')
        }
    }

    private class Parser(
        val s: String,
    ) {
        var pos = 0

        fun skipSpace() {
            while (pos < s.length && s[pos].isWhitespace()) pos++
        }

        fun value(): Json {
            skipSpace()
            check(pos < s.length) { "unexpected end" }
            return when (s[pos]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> Str(string())
                '-', in '0'..'9' -> number()
                else -> literal()
            }
        }

        private fun obj(): Obj {
            pos++
            val fields = LinkedHashMap<String, Json>()
            skipSpace()
            if (s[pos] == '}') return Obj(fields).also { pos++ }
            while (true) {
                skipSpace()
                val key = string()
                skipSpace()
                expect(':')
                check(fields.put(key, value()) == null) { "duplicate key $key" }
                skipSpace()
                if (s[pos] == '}') return Obj(fields).also { pos++ }
                expect(',')
            }
        }

        private fun arr(): Arr {
            pos++
            val items = ArrayList<Json>()
            skipSpace()
            if (s[pos] == ']') return Arr(items).also { pos++ }
            while (true) {
                items += value()
                skipSpace()
                if (s[pos] == ']') return Arr(items).also { pos++ }
                expect(',')
            }
        }

        private fun string(): String {
            expect('"')
            val out = StringBuilder()
            check(pos < s.length) { "unterminated string" }
            while (s[pos] != '"') {
                val c = s[pos++]
                out.append(if (c == '\\') escape() else c)
                check(pos < s.length) { "unterminated string" }
            }
            pos++
            return out.toString()
        }

        private fun escape(): Char {
            check(pos < s.length) { "unterminated escape" }
            return when (val e = s[pos++]) {
                '"', '\\', '/' -> e
                'n' -> '\n'
                't' -> '\t'
                'r' -> '\r'
                'b' -> '\b'
                'f' -> '\u000c'
                'u' -> hex4()
                else -> error("escape \\$e at $pos")
            }
        }

        /** Four hex digits after `\u`, exactly. */
        private fun hex4(): Char {
            check(pos + 4 <= s.length) { "short \\u escape" }
            val digits = s.substring(pos, pos + 4)
            check(digits.all { it in '0'..'9' || it.lowercaseChar() in 'a'..'f' }) { "bad \\u escape $digits" }
            pos += 4
            return digits.toInt(16).toChar()
        }

        /** RFC 8259's `number`: `-`? (`0` | `[1-9][0-9]*`) (`.` digits)? ([eE] [+-]? digits)?. */
        private fun number(): Num {
            val start = pos
            if (s[pos] == '-') pos++
            check(pos < s.length && s[pos].isAsciiDigit()) { "bad number at $start" }
            if (s[pos] == '0') pos++ else digits()
            if (pos < s.length && s[pos] == '.') {
                pos++
                check(digits() > 0) { "bad fraction at $start" }
            }
            if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) {
                pos++
                if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++
                check(digits() > 0) { "bad exponent at $start" }
            }
            return Num(s.substring(start, pos))
        }

        private fun digits(): Int {
            val start = pos
            while (pos < s.length && s[pos].isAsciiDigit()) pos++
            return pos - start
        }

        private fun Char.isAsciiDigit() = this in '0'..'9'

        private fun literal(): Json =
            when {
                s.startsWith("true", pos) -> Bool(true).also { pos += 4 }
                s.startsWith("false", pos) -> Bool(false).also { pos += 5 }
                s.startsWith("null", pos) -> Null.also { pos += 4 }
                else -> error("unexpected '${s[pos]}' at $pos")
            }

        private fun expect(c: Char) {
            check(pos < s.length && s[pos] == c) { "expected '$c' at $pos" }
            pos++
        }
    }
}
