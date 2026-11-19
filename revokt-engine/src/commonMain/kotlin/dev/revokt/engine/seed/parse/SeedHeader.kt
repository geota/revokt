// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonParseException
import dev.revokt.engine.json.JsonString

/**
 * A seed's `seed.json` (spec §6.5), the archive's one unsigned entry, read for the header checks only: [seedFormat],
 * [channel], [dataset], [filterFormat], [recordsLastModified] (a hint: the seed's timestamp is the verified `<ts>` of
 * `records.json`) and [engineFloor]. The enum values are names, as `meta.json` writes them (`"COMPAT"`, `"CRLITE"`,
 * `"V3"`), kept as read for the loader to check; the integers are JSON integers. Other members are ignored.
 */
internal class SeedHeader(
    val seedFormat: Long,
    val channel: String,
    val dataset: String,
    val filterFormat: String,
    val recordsLastModified: Long,
    val engineFloor: Long,
) {
    override fun toString(): String =
        listOf(
            "seedFormat=$seedFormat",
            printable(channel),
            printable(dataset),
            printable(filterFormat),
            "recordsLastModified=$recordsLastModified",
            "engineFloor=$engineFloor",
        ).joinToString(", ", "SeedHeader(", ")")

    companion object {
        /** The most bytes `seed.json` may inflate to (spec §6.5 "Entry caps"). */
        const val MAX_BYTES: Long = 64L shl 10

        /** The header in [bytes]; anything but a JSON object with each member of its type is [SeedFormatException]. */
        fun read(bytes: ByteArray): SeedHeader {
            val root =
                try {
                    Json.parse(bytes, MAX_BYTES)
                } catch (e: JsonParseException) {
                    throw SeedFormatException("seed.json is not JSON: ${e.message}")
                }
            val obj = root as? JsonObject ?: throw SeedFormatException("seed.json is not an object")
            return SeedHeader(
                seedFormat = obj.long("seedFormat"),
                channel = obj.string("channel"),
                dataset = obj.string("dataset"),
                filterFormat = obj.string("filterFormat"),
                recordsLastModified = obj.long("recordsLastModified"),
                engineFloor = obj.long("engineFloor"),
            )
        }

        private fun JsonObject.long(key: String): Long =
            (this[key] as? JsonInteger)?.toLongOrNull()
                ?: throw SeedFormatException("seed.json's $key is not an integer in the Long range")

        private fun JsonObject.string(key: String): String =
            (this[key] as? JsonString)?.value ?: throw SeedFormatException("seed.json's $key is not a string")
    }
}
