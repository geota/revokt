// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

/**
 * Canonical JSON exactly as `canonical_json` 0.7.0 (`mozilla-services/canonicaljson-rs`, `to_string` over serde_json
 * 1.x) writes it, the serialisation the content-signature payload is hashed in (spec §7.1, §9): no whitespace; object
 * keys in code point order; integers in decimal; a [JsonDouble] as Rust's shortest round-trip `{:e}` with a capital
 * `E` (`2.31E1`, `1E21`, `-0E0`); in strings `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, `\u00xx` for every other control
 * character, printable ASCII (0x20 to 0x7E) as itself, and every other UTF-16 unit as `\u` and four lowercase hex
 * digits, so a character above U+FFFF is its surrogate pair. The output is ASCII.
 */
internal object CanonicalJson {
    fun write(value: JsonValue): ByteArray = StringBuilder().also { write(value, it) }.toString().encodeToByteArray()

    private fun write(
        value: JsonValue,
        out: StringBuilder,
    ) {
        when (value) {
            JsonNull -> {
                out.append("null")
            }

            is JsonBoolean -> {
                out.append(value.value)
            }

            is JsonString -> {
                quote(value.value, out)
            }

            is JsonInteger -> {
                out.append(if (value.negative) "-" else "").append(value.magnitude.toString())
            }

            is JsonDouble -> {
                out.append(ShortestDouble.exponential(value.value))
            }

            is JsonArray -> {
                out.append('[')
                for (i in 0 until value.size) {
                    if (i > 0) out.append(',')
                    write(value[i], out)
                }
                out.append(']')
            }

            is JsonObject -> {
                out.append('{')
                for (i in 0 until value.size) {
                    if (i > 0) out.append(',')
                    quote(value.keyAt(i), out)
                    out.append(':')
                    write(value.valueAt(i), out)
                }
                out.append('}')
            }
        }
    }

    private const val HEX = "0123456789abcdef"

    private fun quote(
        s: String,
        out: StringBuilder,
    ) {
        out.append('"')
        for (c in s) {
            when (c) {
                '"' -> {
                    out.append("\\\"")
                }

                '\\' -> {
                    out.append("\\\\")
                }

                '\b' -> {
                    out.append("\\b")
                }

                '\t' -> {
                    out.append("\\t")
                }

                '\n' -> {
                    out.append("\\n")
                }

                '\u000C' -> {
                    out.append("\\f")
                }

                '\r' -> {
                    out.append("\\r")
                }

                in ' '..'~' -> {
                    out.append(c)
                }

                else -> {
                    out.append("\\u")
                    for (shift in 12 downTo 0 step 4) out.append(HEX[(c.code shr shift) and 0xF])
                }
            }
        }
        out.append('"')
    }
}
