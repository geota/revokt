// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

/**
 * A value of the engine's own immutable JSON tree (spec §7.1 "JSON"; no JSON library, §3). Numbers keep the three
 * kinds `canonical_json` 0.7.0 serialises differently, as serde_json reads them: [JsonInteger] for an integer literal
 * in `[-2^63, 2^64 - 1]` other than `-0`, and [JsonDouble] for every other number.
 */
internal sealed interface JsonValue

internal data object JsonNull : JsonValue

internal data class JsonBoolean(
    val value: Boolean,
) : JsonValue {
    companion object {
        val TRUE = JsonBoolean(true)
        val FALSE = JsonBoolean(false)
    }
}

internal data class JsonString(
    val value: String,
) : JsonValue

/** An integer held exactly as [magnitude] and a sign: up to `2^64 - 1` when not [negative], `1..2^63` when it is. */
internal data class JsonInteger(
    val negative: Boolean,
    val magnitude: ULong,
) : JsonValue {
    init {
        require(!negative || magnitude in 1uL..(1uL shl 63)) { "a negative integer's magnitude is 1 to 2^63" }
    }

    /** The value when it fits a [Long], else null. */
    fun toLongOrNull(): Long? =
        when {
            negative -> -magnitude.toLong()
            magnitude <= Long.MAX_VALUE.toULong() -> magnitude.toLong()
            else -> null
        }

    companion object {
        fun of(value: Long): JsonInteger =
            if (value < 0) JsonInteger(true, value.toULong().inv() + 1uL) else JsonInteger(false, value.toULong())
    }
}

/** A finite double: a number with a fraction or an exponent, `-0`, or an integer outside [JsonInteger]'s range. */
internal data class JsonDouble(
    val value: Double,
) : JsonValue {
    init {
        require(value.isFinite()) { "JSON has no NaN or infinity" }
    }
}

internal data class JsonArray(
    val items: List<JsonValue>,
) : JsonValue {
    companion object {
        val EMPTY = JsonArray(emptyList())
    }
}

/** An object, its [members] iterating in code point order of the keys (spec §7.1), keys distinct by construction. */
internal class JsonObject private constructor(
    val members: Map<String, JsonValue>,
) : JsonValue {
    operator fun get(key: String): JsonValue? = members[key]

    override fun equals(other: Any?): Boolean = other is JsonObject && members == other.members

    override fun hashCode(): Int = members.hashCode()

    override fun toString(): String = "JsonObject($members)"

    companion object {
        val EMPTY = JsonObject(emptyMap())

        /** The object of [entries] in code point order of the keys, or null when two entries share a key. */
        fun ofOrNull(entries: List<Pair<String, JsonValue>>): JsonObject? {
            if (entries.isEmpty()) return EMPTY
            val sorted = entries.sortedWith { a, b -> compareCodePoints(a.first, b.first) }
            val members = LinkedHashMap<String, JsonValue>(sorted.size * 4 / 3 + 1)
            for (i in sorted.indices) {
                if (i > 0 && sorted[i - 1].first == sorted[i].first) return null
                members[sorted[i].first] = sorted[i].second
            }
            return JsonObject(members)
        }

        fun of(vararg entries: Pair<String, JsonValue>): JsonObject =
            requireNotNull(ofOrNull(entries.asList())) { "two members share a key" }

        /**
         * Orders [a] and [b] by Unicode code point, which is UTF-8 byte order (`canonical_json` sorts Rust `String`s).
         * UTF-16 order differs only where a surrogate meets a unit at or above U+E000: the surrogate's code point is
         * above U+FFFF, so it sorts last. Strings from the parser hold only paired surrogates.
         */
        fun compareCodePoints(
            a: String,
            b: String,
        ): Int {
            for (i in 0 until minOf(a.length, b.length)) {
                val x = a[i]
                val y = b[i]
                if (x != y) return rank(x) - rank(y)
            }
            return a.length - b.length
        }

        private fun rank(c: Char): Int = if (c.isSurrogate()) c.code + 0x2800 else c.code
    }
}
