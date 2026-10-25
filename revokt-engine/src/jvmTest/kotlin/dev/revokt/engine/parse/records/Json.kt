// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

/**
 * The JSON subset the corpus records use (spec §9.2 "Corpus record schema"): objects, arrays, strings, booleans and
 * null, no numbers. Written with keys in insertion order, one record per line, so a regenerated file diffs cleanly.
 */
internal sealed class Json {
    class Obj(
        val fields: Map<String, Json>,
    ) : Json() {
        operator fun get(key: String): Json? = fields[key]

        fun string(key: String): String = (fields[key] as? Str)?.value ?: error("missing string $key")

        fun stringOrNull(key: String): String? = (fields[key] as? Str)?.value

        fun array(key: String): List<Json> = (fields[key] as? Arr)?.items ?: error("missing array $key")

        fun child(key: String): Obj = fields[key] as? Obj ?: error("missing object $key")

        fun childOrNull(key: String): Obj? = fields[key] as? Obj
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
            while (s[pos] != '"') {
                val c = s[pos++]
                if (c != '\\') {
                    out.append(c)
                    continue
                }
                when (val e = s[pos++]) {
                    '"', '\\', '/' -> out.append(e)
                    'n' -> out.append('\n')
                    'u' -> out.append(s.substring(pos, pos + 4).toInt(16).toChar()).also { pos += 4 }
                    else -> error("escape \\$e at $pos")
                }
            }
            pos++
            return out.toString()
        }

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
