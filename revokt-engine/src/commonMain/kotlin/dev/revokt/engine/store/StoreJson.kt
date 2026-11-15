// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.engine.json.CanonicalJson
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonNull
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonParseException
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.json.JsonValue

/** A store file's content that does not have the shape its decoder reads. */
internal class MalformedStoreFileException(
    message: String,
) : Exception(message)

/**
 * Typed reads of one JSON object of a store file (spec §6.5), over the engine's JSON tree. A member that is absent or
 * `null` is absent; one of the wrong type, and an absent required member, is a [MalformedStoreFileException]. Members
 * the decoder does not ask for are ignored, so the layout can grow (the reading the issue states; §6.5 is silent).
 */
internal class StoreFields(
    private val obj: JsonObject,
) {
    fun string(key: String): String = optString(key) ?: missing(key)

    fun optString(key: String): String? =
        when (val v = obj[key]) {
            null, JsonNull -> null
            is JsonString -> v.value
            else -> wrong(key)
        }

    fun long(key: String): Long = optLong(key) ?: missing(key)

    fun optLong(key: String): Long? =
        when (val v = obj[key]) {
            null, JsonNull -> null
            is JsonInteger -> v.toLongOrNull() ?: wrong(key)
            else -> wrong(key)
        }

    fun optObject(key: String): StoreFields? =
        when (val v = obj[key]) {
            null, JsonNull -> null
            is JsonObject -> StoreFields(v)
            else -> wrong(key)
        }

    /** The object [key] holds, or null when it is absent or anything but an object. */
    fun objectOrNull(key: String): StoreFields? = (obj[key] as? JsonObject)?.let(::StoreFields)

    /** Whether [key] holds a value other than `null` that is not an object. */
    fun presentNotObject(key: String): Boolean = obj[key].let { it != null && it != JsonNull && it !is JsonObject }

    fun optArray(key: String): JsonArray? =
        when (val v = obj[key]) {
            null, JsonNull -> null
            is JsonArray -> v
            else -> wrong(key)
        }

    /** The members of this object, in key order. */
    val members: List<Pair<String, JsonValue>> get() = List(obj.size) { obj.keyAt(it) to obj.valueAt(it) }

    /** The value of the enum constant whose name is the string [key] holds. */
    inline fun <reified E : Enum<E>> enum(key: String): E {
        val name = string(key)
        return enumValues<E>().firstOrNull { it.name == name } ?: wrong(key)
    }

    fun missing(key: String): Nothing = throw MalformedStoreFileException("no '$key'")

    fun wrong(key: String): Nothing = throw MalformedStoreFileException("'$key' has the wrong type or value")

    companion object {
        /**
         * [decode] over [bytes] parsed as a JSON object, or null when they are not JSON, not an object, or not the
         * shape [decode] reads (a [MalformedStoreFileException], or an [IllegalArgumentException] from the value's own
         * checks).
         */
        fun <T> decodeOrNull(
            bytes: ByteArray,
            decode: (StoreFields) -> T,
        ): T? =
            try {
                val root = Json.parse(bytes) as? JsonObject
                root?.let { decode(StoreFields(it)) }
            } catch (ignored: JsonParseException) {
                null
            } catch (ignored: MalformedStoreFileException) {
                null
            } catch (ignored: IllegalArgumentException) {
                null
            }

        /** The canonical JSON of the object of [members], those whose value is null left out. */
        fun encode(vararg members: Pair<String, JsonValue?>): ByteArray =
            CanonicalJson.write(objectOf(members.asList()))

        /** The object of [members], those whose value is null left out. */
        fun objectOf(members: List<Pair<String, JsonValue?>>): JsonObject =
            requireNotNull(
                JsonObject.ofOrNull(
                    members.mapNotNull { (k, v) ->
                        v?.let { k to it }
                    },
                ),
            ) { "two members share a key" }

        fun string(value: String?): JsonString? = value?.let(::JsonString)

        fun long(value: Long?): JsonInteger? = value?.let(JsonInteger::of)
    }
}
