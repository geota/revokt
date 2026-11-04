// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The JSON conformance set of #92 (spec §7.1 "JSON"): what the engine's parser accepts, and what it rejects and why. */
class JsonTest {
    private fun parse(text: String): JsonValue = Json.parse(text.encodeToByteArray())

    private fun bytes(vararg b: Int): ByteArray = ByteArray(b.size) { b[it].toByte() }

    private fun rejects(
        error: JsonError,
        input: ByteArray,
        maxBytes: Long = Long.MAX_VALUE,
    ): JsonParseException {
        val e = assertFailsWith<JsonParseException>(input.decodeToString()) { Json.parse(input, maxBytes) }
        assertEquals(error, e.error, input.decodeToString())
        return e
    }

    private fun rejects(
        error: JsonError,
        text: String,
    ): JsonParseException = rejects(error, text.encodeToByteArray())

    private fun str(s: String) = JsonString(s)

    private fun int(v: Long) = JsonInteger.of(v)

    @Test
    fun `scalars, containers and whitespace`() {
        assertEquals(JsonNull, parse("null"))
        assertEquals(JsonBoolean.TRUE, parse("true"))
        assertEquals(JsonBoolean.FALSE, parse(" \t\r\nfalse\n"))
        assertEquals(int(0), parse("0"))
        assertEquals(int(-12), parse("-12"))
        assertEquals(str(""), parse("\"\""))
        assertEquals(JsonArray.EMPTY, parse("[ ]"))
        assertEquals(JsonObject.EMPTY, parse("{ }"))
        assertEquals(
            JsonObject.of("a" to JsonArray(listOf(int(1), JsonNull, str("x"))), "b" to JsonObject.EMPTY),
            parse(" { \"b\" : { } , \"a\" : [ 1 , null , \"x\" ] } "),
        )
    }

    @Test
    fun `escapes and UTF-8 decode to the same string`() {
        val expected = "\"\\/\b\u000C\n\r\tAé\u2764\uD834\uDD1E\u007F"
        assertEquals(str(expected), parse("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\u00e9\\u2764\\uD834\\udd1e\u007F\""))
        assertEquals(str(expected), parse("\"\\\"\\\\/\\b\\f\\n\\r\\tAé❤\uD834\uDD1E\u007F\""))
        assertEquals(str("\u0000"), parse("\"\\u0000\""))
        assertEquals(str("\uFFFF\uE000"), parse("\"\\uffff\uE000\""))
        assertEquals(str("\uDBFF\uDFFF"), Json.parse(bytes(0x22, 0xF4, 0x8F, 0xBF, 0xBF, 0x22)))
        assertEquals(str("\u0080\u07FF\u0800"), Json.parse(bytes(0x22, 0xC2, 0x80, 0xDF, 0xBF, 0xE0, 0xA0, 0x80, 0x22)))
    }

    @Test
    fun `integers keep serde_json's u64 and i64 ranges, everything else is a double`() {
        assertEquals(JsonInteger(false, ULong.MAX_VALUE), parse("18446744073709551615"))
        assertEquals(JsonDouble(1.8446744073709552E19), parse("18446744073709551616"))
        assertEquals(int(Long.MIN_VALUE), parse("-9223372036854775808"))
        assertEquals(JsonDouble(-9.223372036854775809E18), parse("-9223372036854775809"))
        assertEquals(JsonDouble(-1.8446744073709552E19), parse("-18446744073709551615"))
        assertEquals(JsonDouble(1.2345678901234568E29), parse("123456789012345678901234567890"))
        assertEquals(JsonDouble(-0.0), parse("-0"))
        assertEquals(JsonDouble(0.0), parse("0.0"))
        assertEquals(JsonDouble(100.0), parse("1E2"))
        assertEquals(JsonDouble(1.0), parse("1.0"))
        assertEquals(JsonDouble(-0.5), parse("-5e-1"))
        assertEquals(JsonDouble(0.0), parse("1e-400"))
        assertEquals(JsonDouble(-0.0), parse("-1e-400"))
        assertEquals(JsonDouble(0.0), parse("0e99999999999999999999"))
        assertEquals(JsonDouble(Double.MAX_VALUE), parse("1.7976931348623157e308"))
        assertEquals(JsonDouble(Double.MIN_VALUE), parse("4.9e-324"))
        assertEquals(Long.MIN_VALUE, int(Long.MIN_VALUE).toLongOrNull())
        assertEquals(Long.MAX_VALUE, int(Long.MAX_VALUE).toLongOrNull())
        assertNull(JsonInteger(false, ULong.MAX_VALUE).toLongOrNull())
        rejects(JsonError.NUMBER_OUT_OF_RANGE, "1e400")
        rejects(JsonError.NUMBER_OUT_OF_RANGE, "-1.8e308")
        rejects(JsonError.NUMBER_OUT_OF_RANGE, "[1e99999999999999999999]")
    }

    @Test
    fun `number syntax is RFC 8259's`() {
        for (text in listOf("01", "-01", "00", "1.", "1.e5", "1e", "1e+", "1E-", "-", "-a", "--1", "-.5", "1ea")) {
            val e = assertFailsWith<JsonParseException>(text) { parse(text) }
            assertTrue(e.error == JsonError.INVALID_NUMBER || e.error == JsonError.END_OF_INPUT, "$text: ${e.error}")
        }
        for (text in listOf(".5", "+1", "NaN", "Infinity", "-Infinity", "0x10", "1.5.3", "1 2", "0-1")) {
            val e = assertFailsWith<JsonParseException>(text) { parse(text) }
            assertTrue(e.error != JsonError.TOO_LARGE, "$text: ${e.error}")
        }
    }

    @Test
    fun `objects reject duplicate keys, compared after unescaping`() {
        rejects(JsonError.DUPLICATE_KEY, "{\"a\":1,\"a\":1}")
        rejects(JsonError.DUPLICATE_KEY, "{\"a\":1,\"b\":2,\"\\u0061\":3}")
        rejects(JsonError.DUPLICATE_KEY, "[{\"x\":{\"\":1,\"\":2}}]")
        assertEquals(2, (parse("{\"a\":1,\"A\":1}") as JsonObject).size)
    }

    @Test
    fun `keys iterate in code point order, not UTF-16 order`() {
        val obj =
            parse(
                "{\"b\":1,\"\\uE000\":2,\"\\uD83D\\uDE00\":3,\"a\":4,\"ab\":5,\"\":6,\"\\u00e9\":7}",
            ) as JsonObject
        assertEquals(listOf("", "a", "ab", "b", "é", "\uE000", "\uD83D\uDE00"), obj.keys)
        assertTrue(JsonObject.compareCodePoints("\uFFFF", "\uD800\uDC00") < 0)
        assertTrue(JsonObject.compareCodePoints("\uD800\uDC01", "\uD800\uDC00") > 0)
        assertEquals(0, JsonObject.compareCodePoints("x", "x"))
    }

    @Test
    fun `unpaired surrogates are rejected`() {
        for (text in listOf(
            "\"\\uD800\"",
            "\"\\uDC00\"",
            "\"\\udfff\\ud800\"",
            "\"\\uD800\\u0041\"",
            "\"\\uD800\\uD800\"",
            "\"\\uD800x\"",
            "\"\\uD800\\n\"",
            "\"\\uDBFF",
        )) {
            rejects(JsonError.LONE_SURROGATE, text)
        }
    }

    @Test
    fun `strings reject control characters, bad escapes and ill-formed UTF-8`() {
        rejects(JsonError.CONTROL_CHARACTER, bytes(0x22, 0x01, 0x22))
        rejects(JsonError.CONTROL_CHARACTER, "\"a\tb\"")
        rejects(JsonError.CONTROL_CHARACTER, "\"é\n\"")
        for (text in listOf("\"\\x\"", "\"\\u12G4\"", "\"\\U0041\"", "\"\\'\"")) rejects(JsonError.INVALID_ESCAPE, text)
        rejects(JsonError.END_OF_INPUT, "\"\\u12")
        rejects(JsonError.END_OF_INPUT, "\"abc")
        rejects(JsonError.END_OF_INPUT, "\"\\")
        for (seq in listOf(
            bytes(0xC0, 0x80),
            bytes(0xC1, 0xBF),
            bytes(0xE0, 0x9F, 0xBF),
            bytes(0xED, 0xA0, 0x80),
            bytes(0xED, 0xBF, 0xBF),
            bytes(0xF0, 0x8F, 0xBF, 0xBF),
            bytes(0xF4, 0x90, 0x80, 0x80),
            bytes(0xF5, 0x80, 0x80, 0x80),
            bytes(0xFF),
            bytes(0x80),
            bytes(0xC3, 0x28),
            bytes(0xE2, 0x82),
        )) {
            rejects(JsonError.INVALID_UTF8, bytes(0x22) + seq + bytes(0x22))
        }
        rejects(JsonError.INVALID_UTF8, bytes(0x22, 0xE2, 0x82))
    }

    @Test
    fun `structure errors`() {
        rejects(JsonError.END_OF_INPUT, "")
        rejects(JsonError.END_OF_INPUT, "  ")
        rejects(JsonError.END_OF_INPUT, "[1,")
        rejects(JsonError.END_OF_INPUT, "{\"a\":")
        rejects(JsonError.END_OF_INPUT, "tru")
        rejects(JsonError.UNEXPECTED_BYTE, "[1,]")
        rejects(JsonError.UNEXPECTED_BYTE, "{\"a\":1,}")
        rejects(JsonError.UNEXPECTED_BYTE, "[1 2]")
        rejects(JsonError.UNEXPECTED_BYTE, "{\"a\" 1}")
        rejects(JsonError.UNEXPECTED_BYTE, "{1:2}")
        rejects(JsonError.UNEXPECTED_BYTE, "{'a':1}")
        rejects(JsonError.UNEXPECTED_BYTE, "True")
        rejects(JsonError.UNEXPECTED_BYTE, "nul1")
        rejects(JsonError.UNEXPECTED_BYTE, "]")
        rejects(JsonError.UNEXPECTED_BYTE, bytes(0xEF, 0xBB, 0xBF, 0x31))
        rejects(JsonError.UNEXPECTED_BYTE, "\u000C1")
        rejects(JsonError.TRAILING_BYTES, "{} x")
        rejects(JsonError.TRAILING_BYTES, "1 2")
        rejects(JsonError.TRAILING_BYTES, "null\u0000")
        assertEquals(3, rejects(JsonError.UNEXPECTED_BYTE, "[1 2]").offset)
    }

    @Test
    fun `depth is capped at serde_json's 127 before the container is allocated`() {
        val ok = "[".repeat(Json.MAX_DEPTH) + "]".repeat(Json.MAX_DEPTH)
        var v = parse(ok)
        var depth = 0
        while (v is JsonArray && v.items.isNotEmpty()) {
            v = v.items[0]
            depth++
        }
        assertEquals(Json.MAX_DEPTH - 1, depth)
        assertEquals(Json.MAX_DEPTH, rejects(JsonError.TOO_DEEP, "[".repeat(Json.MAX_DEPTH + 1)).offset)
        val mixed = "{\"a\":[".repeat(64)
        rejects(JsonError.TOO_DEEP, mixed)
        parse("{\"a\":[".repeat(63) + "{}" + "]}".repeat(63))
    }

    @Test
    fun `the size cap is checked before reading`() {
        assertEquals(0, rejects(JsonError.TOO_LARGE, "[1,2]".encodeToByteArray(), maxBytes = 4).offset)
        assertEquals(JsonArray(listOf(int(1))), Json.parse("[1]".encodeToByteArray(), maxBytes = 3))
        rejects(
            JsonError.TOO_LARGE,
            ByteArray(4 * 1024 * 1024 + 1) {
                ' '.code.toByte()
            },
            dev.revokt.RevoktLimits.MAX_JSON_BYTES,
        )
    }

    @Test
    fun `tree constructors check their invariants`() {
        assertFailsWith<IllegalArgumentException> { JsonInteger(true, 0u) }
        assertFailsWith<IllegalArgumentException> { JsonInteger(true, (1uL shl 63) + 1uL) }
        assertFailsWith<IllegalArgumentException> { JsonDouble(Double.NaN) }
        assertFailsWith<IllegalArgumentException> { JsonObject.of("a" to JsonNull, "a" to JsonNull) }
        assertEquals(JsonObject.of("b" to JsonNull, "a" to JsonNull), JsonObject.of("a" to JsonNull, "b" to JsonNull))
        assertEquals(JsonObject.EMPTY.hashCode(), JsonObject.of().hashCode())
        assertTrue(JsonObject.of("a" to JsonNull).toString().contains("a=JsonNull"))
        assertEquals(JsonNull, JsonObject.of("a" to JsonNull)["a"])
    }
}
