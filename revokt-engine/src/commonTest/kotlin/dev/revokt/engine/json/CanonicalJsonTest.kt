// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Canonical JSON (spec §7.1): `canonical_json` 0.7.0's own `test_to_string` cases (its `src/ser.rs`, inputs written as
 * the JSON text its `json!` literals denote) but its non-integer numbers, which revokt refuses (#227), and the corner
 * cases of its integer and escape rules. The differential
 * against the crate itself is `CanonicalJsonOracleTest`.
 */
class CanonicalJsonTest {
    private fun canonical(text: String): String =
        CanonicalJson.write(Json.parse(text.encodeToByteArray())).decodeToString()

    private fun check(
        text: String,
        expected: String,
    ) = assertEquals(expected, canonical(text), text)

    @Test
    fun `the crate's own cases`() {
        check("null", "null")
        check("true", "true")
        check("false", "false")
        check("0", "0")
        check("123", "123")
        check("-123", "-123")
        check("23", "23")
        check("2300", "2300")
        check("\"\"", "\"\"")
        check("\" Preserve single quotes'in string\"", "\" Preserve single quotes'in string\"")
        check("\" Escapes quotes \\\" \"", "\" Escapes quotes \\\" \"")
        check("\"This\\\\and this\"", "\"This\\\\and this\"")
        check("\"I ❤ testing\"", "\"I \\u2764 testing\"")
        check("\"This is a sentence.\\n\"", "\"This is a sentence.\\n\"")
        check("\"This is a \\t tab.\"", "\"This is a \\t tab.\"")
        check("\"This is a \\r carriage return char.\"", "\"This is a \\r carriage return char.\"")
        check("\"image/jpeg\"", "\"image/jpeg\"")
        check("\"image\\/\\/jpeg\"", "\"image//jpeg\"")
        check("\"frequency at 10.0e+04\"", "\"frequency at 10.0e+04\"")
        check("\"I \\\\u{} testing\"", "\"I \\\\u{} testing\"")
        check("\"I \\\\u{1234 testing\"", "\"I \\\\u{1234 testing\"")
        check("\"I \\\\u{{12345}} testing\"", "\"I \\\\u{{12345}} testing\"")
        check("\"𝄞\"", "\"\\ud834\\udd1e\"")
        check("\"𝗠𝗼𝘇\"", "\"\\ud835\\udde0\\ud835\\uddfc\\ud835\\ude07\"")
        check("\"\uD800\uDC00 \uDBFF\uDFFF\"", "\"\\ud800\\udc00 \\udbff\\udfff\"")
        check("{\"a\": {}, \"b\": \"b\"}", "{\"a\":{},\"b\":\"b\"}")
        check("{\"a\": \"a\", \"id\": \"1\", \"b\": \"b\"}", "{\"a\":\"a\",\"b\":\"b\",\"id\":\"1\"}")
        check(
            """{"a": {"b": "b", "a": "a", "c": {"b": "b", "a": "a", "c": ["b", "a", "c"], "d": {"b": "b", "a": "a"},
               "id": "1", "e": 1, "f": [2, 3, 1], "g": {"2": 2, "3": 3, "1": {"b": "b", "a": "a", "c": "c"}}}}, "id": "1"}""",
            "{\"a\":{\"a\":\"a\",\"b\":\"b\",\"c\":{\"a\":\"a\",\"b\":\"b\",\"c\":[\"b\",\"a\",\"c\"]," +
                "\"d\":{\"a\":\"a\",\"b\":\"b\"},\"e\":1,\"f\":[2,3,1]," +
                "\"g\":{\"1\":{\"a\":\"a\",\"b\":\"b\",\"c\":\"c\"},\"2\":2,\"3\":3},\"id\":\"1\"}},\"id\":\"1\"}",
        )
        check(
            "{\"b\": [\"two\", \"three\"], \"a\": [\"zero\", \"one\"]}",
            "{\"a\":[\"zero\",\"one\"],\"b\":[\"two\",\"three\"]}",
        )
        check("{\"é\": \"check\"}", "{\"\\u00e9\":\"check\"}")
        check("[]", "[]")
        check("[\"one\", \"two\", \"three\"]", "[\"one\",\"two\",\"three\"]")
        check("[{\"key\": \"✓\"}]", "[{\"key\":\"\\u2713\"}]")
        check("[{\"key\": \"ę\"}]", "[{\"key\":\"\\u0119\"}]")
        check(
            "[{\"foo\": \"bar\", \"last_modified\": \"12345\", \"id\": \"1\"}, {\"bar\": \"baz\", \"last_modified\": \"45678\", \"id\": \"2\"}]",
            "[{\"foo\":\"bar\",\"id\":\"1\",\"last_modified\":\"12345\"},{\"bar\":\"baz\",\"id\":\"2\",\"last_modified\":\"45678\"}]",
        )
        check("{\"z\": 1, \"a\": 2, \"m\": 3}", "{\"a\":2,\"m\":3,\"z\":1}")
    }

    @Test
    fun `every control character, DEL and non-ASCII are escaped, printable ASCII is not`() {
        val all =
            (0 until 0x80).joinToString("") { c ->
                if (c < 0x20 || c == '"'.code ||
                    c == '\\'.code
                ) {
                    "\\u%04x".hex(c)
                } else {
                    c.toChar().toString()
                }
            }
        val out = canonical("\"$all\"")
        val expected =
            StringBuilder("\"")
                .apply {
                    for (c in 0 until 0x80) {
                        append(
                            when (c) {
                                0x08 -> "\\b"
                                0x09 -> "\\t"
                                0x0A -> "\\n"
                                0x0C -> "\\f"
                                0x0D -> "\\r"
                                '"'.code -> "\\\""
                                '\\'.code -> "\\\\"
                                in 0x20..0x7E -> c.toChar().toString()
                                else -> "\\u%04x".hex(c)
                            },
                        )
                    }
                    append('"')
                }.toString()
        assertEquals(expected, out)
        check("\"\\u0080\\u00ff\\uABCD\\uFFFF\\uE000\"", "\"\\u0080\\u00ff\\uabcd\\uffff\\ue000\"")
    }

    private fun String.hex(c: Int): String = replace("%04x", c.toString(16).padStart(4, '0'))

    @Test
    fun `integers are exact, and every other number is refused, never printed (#227)`() {
        check("18446744073709551615", "18446744073709551615")
        check("-9223372036854775808", "-9223372036854775808")
        check("0", "0")
        check("2300", "2300")
        // canonical_json would print each of these in Rust's shortest exponential form; no signed payload holds one.
        for (text in listOf(
            "23.1",
            "1.0",
            "0.0",
            "-0",
            "1e21",
            "0.000000930258908",
            "18446744073709551616",
            "-9223372036854775809",
            "1e-400",
            "[1.0,-2,3E2]",
            "{\"def\": \"bar\", \"abc\": 0.000000930258908}",
        )) {
            assertFailsWith<NonIntegerNumberException>(text) { canonical(text) }
        }
    }

    @Test
    fun `objects built in code are written in code point order`() {
        val obj =
            JsonObject.of(
                "\uD83D\uDE00" to JsonInteger.of(1),
                "\uE000" to JsonString("x"),
                "a" to JsonArray.EMPTY,
            )
        assertEquals("{\"a\":[],\"\\ue000\":\"x\",\"\\ud83d\\ude00\":1}", CanonicalJson.write(obj).decodeToString())
    }
}
