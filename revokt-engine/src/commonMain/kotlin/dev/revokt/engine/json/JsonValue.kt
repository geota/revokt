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
        require(!negative || isNegativeMagnitude(magnitude)) { "a negative integer's magnitude is 1 to 2^63" }
    }

    /** The value when it fits a [Long], else null. */
    fun toLongOrNull(): Long? =
        when {
            negative -> -magnitude.toLong()
            magnitude <= Long.MAX_VALUE.toULong() -> magnitude.toLong()
            else -> null
        }

    companion object {
        /**
         * Whether [magnitude] is 1 to 2^63, by signed comparisons: an unsigned range test would load
         * `kotlin.UnsignedKt` on the first negative number.
         */
        fun isNegativeMagnitude(magnitude: ULong): Boolean = magnitude.toLong().let { it > 0 || it == Long.MIN_VALUE }

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

/**
 * An array; [items] is a read-only view. A one-item array holds its item directly, so nesting costs one small object
 * per level (spec §6.5's allocation budget).
 */
internal class JsonArray private constructor(
    private val array: Array<JsonValue>,
    private val single: JsonValue?,
) : JsonValue {
    constructor(items: List<JsonValue>) : this(
        if (items.size ==
            1
        ) {
            NONE
        } else {
            items.toTypedArray()
        },
        items.singleOrNull(),
    )

    val items: List<JsonValue> get() = if (single != null) listOf(single) else array.asList()

    val size: Int get() = if (single != null) 1 else array.size

    operator fun get(index: Int): JsonValue = if (single != null && index == 0) single else array[index]

    override fun equals(other: Any?): Boolean = other is JsonArray && items == other.items

    override fun hashCode(): Int = items.hashCode()

    override fun toString(): String = "JsonArray($items)"

    companion object {
        private val NONE = emptyArray<JsonValue>()

        val EMPTY = JsonArray(NONE, null)

        /** Takes [array], of two or more items, as is: the parser's exact-size copy, which nothing else holds. */
        internal fun owning(array: Array<JsonValue>): JsonArray = JsonArray(array, null)

        /** The one-item array of [item]. */
        internal fun of(item: JsonValue): JsonArray = JsonArray(NONE, item)
    }
}

/**
 * An object: keys distinct and in code point order (spec §7.1), held as sorted parallel arrays, looked up by binary
 * search.
 */
internal class JsonObject private constructor(
    private val keyArray: Array<String>,
    private val valueArray: Array<JsonValue>,
) : JsonValue {
    /** The keys in code point order, a read-only view. */
    val keys: List<String> get() = keyArray.asList()

    val size: Int get() = keyArray.size

    operator fun get(key: String): JsonValue? {
        var low = 0
        var high = keyArray.size - 1
        while (low <= high) {
            val mid = (low + high) ushr 1
            val c = compareCodePoints(keyArray[mid], key)
            when {
                c < 0 -> low = mid + 1
                c > 0 -> high = mid - 1
                else -> return valueArray[mid]
            }
        }
        return null
    }

    /** The key of the [i]th member in key order. */
    fun keyAt(i: Int): String = keyArray[i]

    /** The value of the [i]th member in key order. */
    fun valueAt(i: Int): JsonValue = valueArray[i]

    override fun equals(other: Any?): Boolean =
        other is JsonObject && keyArray.contentEquals(other.keyArray) && valueArray.contentEquals(other.valueArray)

    override fun hashCode(): Int = 31 * keyArray.contentHashCode() + valueArray.contentHashCode()

    override fun toString(): String =
        keyArray.indices.joinToString(", ", "JsonObject({", "})") { "${keyArray[it]}=${valueArray[it]}" }

    companion object {
        val EMPTY = JsonObject(emptyArray(), emptyArray())

        /** The object of [entries] in code point order of the keys, or null when two entries share a key. */
        fun ofOrNull(entries: List<Pair<String, JsonValue>>): JsonObject? =
            owningOrNull(Array(entries.size) { entries[it].first }, Array(entries.size) { entries[it].second })

        fun of(vararg entries: Pair<String, JsonValue>): JsonObject =
            requireNotNull(ofOrNull(entries.asList())) { "two members share a key" }

        /**
         * Sorts [keys] and [values] together in place, a stable merge sort by code point, and takes both as is; null
         * when two keys are equal. The arrays must be the caller's own.
         */
        internal fun owningOrNull(
            keys: Array<String>,
            values: Array<JsonValue>,
        ): JsonObject? {
            if (keys.isEmpty()) return EMPTY
            sort(keys, values)
            for (i in 1 until keys.size) if (keys[i - 1] == keys[i]) return null
            return JsonObject(keys, values)
        }

        /** Insertion sort up to 16 members, else a bottom-up merge sort through one pair of scratch arrays. */
        private fun sort(
            keys: Array<String>,
            values: Array<JsonValue>,
        ) {
            val n = keys.size
            if (n <= 16) {
                for (i in 1 until n) {
                    val k = keys[i]
                    val v = values[i]
                    var j = i - 1
                    while (j >= 0 && compareCodePoints(keys[j], k) > 0) {
                        keys[j + 1] = keys[j]
                        values[j + 1] = values[j]
                        j--
                    }
                    keys[j + 1] = k
                    values[j + 1] = v
                }
                return
            }
            var srcK = keys
            var srcV = values
            var dstK = keys.copyOf()
            var dstV = values.copyOf()
            var width = 1
            while (width < n) {
                var low = 0
                while (low < n) {
                    merge(srcK, srcV, dstK, dstV, low, minOf(low + width, n), minOf(low + 2 * width, n))
                    low += 2 * width
                }
                srcK = dstK.also { dstK = srcK }
                srcV = dstV.also { dstV = srcV }
                width *= 2
            }
            if (srcK !== keys) {
                srcK.copyInto(keys)
                srcV.copyInto(values)
            }
        }

        private fun merge(
            srcK: Array<String>,
            srcV: Array<JsonValue>,
            dstK: Array<String>,
            dstV: Array<JsonValue>,
            low: Int,
            mid: Int,
            high: Int,
        ) {
            var a = low
            var b = mid
            for (o in low until high) {
                val fromA = b >= high || (a < mid && compareCodePoints(srcK[a], srcK[b]) <= 0)
                val from = if (fromA) a++ else b++
                dstK[o] = srcK[from]
                dstV[o] = srcV[from]
            }
        }

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

        // A range test on the code, not Char.isSurrogate(), so that sorting loads no further stdlib class (spec §6.5's
        // measurement counts every class a parse loads after the warm-up document).
        private fun rank(c: Char): Int = if (c.code in 0xD800..0xDFFF) c.code + 0x2800 else c.code
    }
}
