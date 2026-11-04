// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Canonical JSON (spec §7.1): `canonical_json` 0.7.0's own `test_to_string` cases (its `src/ser.rs`, inputs written as
 * the JSON text its `json!` literals denote), and the corner cases of its number and escape rules. The differential
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
        check("23.1", "2.31E1")
        check("23", "23")
        check("1.0", "1E0")
        check("0.0", "0E0")
        check("23.0", "2.3E1")
        check("-23.0", "-2.3E1")
        check("2300", "2300")
        check("0.00099", "9.9E-4")
        check("0.000011", "1.1E-5")
        check("0.0000011", "1.1E-6")
        check("0.000001", "1E-6")
        check("5.6", "5.6E0")
        check("0.00000099", "9.9E-7")
        check("0.0000001", "1E-7")
        check("0.000000930258908", "9.30258908E-7")
        check("0.00000000000068272", "6.8272E-13")
        check("1e21", "1E21")
        check("1e20", "1E20")
        check("1000000000000000.1", "1.0000000000000001E15")
        check("11000000000000000.0", "1.1E16")
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
        check(
            "{\"def\": \"bar\", \"abc\": 0.000000930258908, \"ghi\": 1000000000000000000000.0, \"rust\": \"❤\", " +
                "\"zoo\": [\"zorilla\", \"anteater\"]}",
            "{\"abc\":9.30258908E-7,\"def\":\"bar\",\"ghi\":1E21,\"rust\":\"\\u2764\",\"zoo\":[\"zorilla\",\"anteater\"]}",
        )
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
    fun `integers are exact, every other number is Rust's shortest exponential form`() {
        check("18446744073709551615", "18446744073709551615")
        check("-9223372036854775808", "-9223372036854775808")
        check("18446744073709551616", "1.8446744073709552E19")
        check("-9223372036854775809", "-9.223372036854776E18")
        check("-0", "-0E0")
        check("-0.0", "-0E0")
        check("0e5", "0E0")
        check("1e-400", "0E0")
        check("100e-2", "1E0")
        check("123456789012345678901234567890", "1.2345678901234568E29")
        check("1.7976931348623157e308", "1.7976931348623157E308")
        check("2.2250738585072014e-308", "2.2250738585072014E-308")
        check("2.2250738585072009e-308", "2.225073858507201E-308")
        check("4.9e-324", "5E-324")
        check("1e23", "1E23")
        check("9007199254740993.0", "9.007199254740992E15")
        check("0.1", "1E-1")
        check("0.30000000000000004", "3.0000000000000004E-1")
        check("-1.5", "-1.5E0")
        check("12345e-1", "1.2345E3")
        check("[1.0,-2,3E2]", "[1E0,-2,3E2]")
        // A tie between two shortest candidates: Rust's Dragon rounds up, where JDK 19+ Double.toString rounds to even.
        check("1497898211722073.25", "1.4978982117220733E15")
        check("1125899906842624.75", "1.1258999068426248E15")
    }

    @Test
    fun `objects built in code are written in code point order`() {
        val obj =
            JsonObject.of(
                "\uD83D\uDE00" to JsonInteger.of(1),
                "\uE000" to JsonDouble(0.5),
                "a" to JsonArray.EMPTY,
            )
        assertEquals("{\"a\":[],\"\\ue000\":5E-1,\"\\ud83d\\ude00\":1}", CanonicalJson.write(obj).decodeToString())
        assertFailsWith<IllegalArgumentException> { ShortestDouble.exponential(Double.POSITIVE_INFINITY) }
    }
}
