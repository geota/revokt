// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.CrliteChannel
import dev.revokt.engine.json.JsonBoolean
import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.json.JsonValue
import okio.ByteString
import okio.ByteString.Companion.decodeHex

/** A CRLite record's `attachment`, as the signed record declares it. */
internal class CrliteAttachment(
    /** Under §6.3's rule ([AttachmentName]). */
    val filename: String,
    val sha256: ByteString,
    val size: Long,
    /** Relative to the pinned `attachmentBaseUrl`. */
    val location: String,
) {
    override fun toString(): String = "CrliteAttachment($filename, ${sha256.hex()}, $size bytes, $location)"
}

/** One schema-checked `cert-revocations` record (spec §7.1); [parent] is set on every delta. */
internal class CrliteRecord(
    val id: String,
    /** The wire name, `compat` or `default` today; records of other channels are filtered out. */
    val channel: String,
    val incremental: Boolean,
    val parent: String?,
    val effectiveTimestamp: Long,
    val attachment: CrliteAttachment,
) {
    override fun toString(): String =
        "CrliteRecord($id, $channel, ${if (incremental) "delta of $parent" else "full"}, $effectiveTimestamp, $attachment)"
}

/**
 * Spec §6.3 "Hardening": a filename matches `^(?!\.{1,2}$)[A-Za-z0-9._-]{1,64}$` and is never a reserved name, compared
 * exactly (only a C2SP mirror's manifest names are compared ignoring case, §7.3). `index.bin` is reserved since
 * revision 48.
 */
internal object AttachmentName {
    private const val MAX_LENGTH = 64

    val RESERVED: Set<String> =
        setOf("index.bin", "meta.json", "records.json", "current", "updater.json", "store.version", ".lock")

    fun isValid(name: String): Boolean =
        name.length in 1..MAX_LENGTH &&
            name != "." &&
            name != ".." &&
            name.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '_' || it == '-' } &&
            name !in RESERVED
}

/** The schema check's verdict on one record set. */
internal sealed class RecordCheck {
    /** Every record passed; [records] are the requested channel's, in the order given. */
    class Passed(
        val records: List<CrliteRecord>,
    ) : RecordCheck()

    /**
     * A record failed the schema ([index] is its position), or the channel holds more than the record cap ([index]
     * null).
     */
    class Rejected(
        val index: Int?,
        val detail: String,
    ) : RecordCheck()
}

/**
 * The CRLite collection schema (spec §7.1, revision 48: "`channel`, `incremental`, `attachment.{filename,hash,size,
 * location}` (the filename under §6.3's rule), `effectiveTimestamp`, `parent`"). The signed payload does not bind the
 * collection, so this is what tells a `cert-revocations` record from another security-state collection's. Each record
 * has a string `id`, a string `channel`, a boolean `incremental`, an integer `effectiveTimestamp` of at least 0, and an
 * `attachment` object with a [AttachmentName]-valid `filename`, a `hash` of 64 lowercase hex digits (SHA-256), an integer
 * `size` of at least 0 and a non-empty string `location`. `parent` is a string on every delta (`incremental: true`) and,
 * when present, on a full: Mozilla's full records carry none (checked against the live collection, 2026-11-07). Other
 * members are allowed.
 */
internal object CrliteSchema {
    private const val SHA256_HEX = 64

    /**
     * Checks [records] (the merged set, tombstones removed) whole, then keeps [channel]'s; more than [maxRecords] of
     * them is a rejection, before any body is fetched (spec §5.1 `MAX_CHANGESET_RECORDS`, "after channel filtering").
     */
    fun check(
        records: List<JsonObject>,
        channel: CrliteChannel,
        maxRecords: Int,
    ): RecordCheck {
        val wanted = channel.name.lowercase()
        val kept = ArrayList<CrliteRecord>()
        for ((i, json) in records.withIndex()) {
            val record =
                when (val read = read(json)) {
                    is Field.Bad -> return RecordCheck.Rejected(
                        i,
                        "record $i (${string(json["id"]) ?: "no id"}): ${read.what}",
                    )

                    is Field.Good -> read.value
                }
            if (record.channel == wanted) kept.add(record)
        }
        if (kept.size > maxRecords) {
            return RecordCheck.Rejected(null, "${kept.size} $wanted records, cap $maxRecords")
        }
        return RecordCheck.Passed(kept)
    }

    /** One read: its value, or what is wrong with it. */
    private sealed class Field<out T> {
        class Good<out T>(
            val value: T,
        ) : Field<T>()

        class Bad(
            val what: String,
        ) : Field<Nothing>()
    }

    private fun read(json: JsonObject): Field<CrliteRecord> {
        val id = string(json["id"]) ?: return Field.Bad("id is not a string")
        val channel = string(json["channel"]) ?: return Field.Bad("channel is not a string")
        val incremental =
            (json["incremental"] as? JsonBoolean)?.value ?: return Field.Bad("incremental is not a boolean")
        val parentValue = json["parent"]
        val parent = string(parentValue)
        if (parentValue != null && parent == null) return Field.Bad("parent is not a string")
        if (incremental && parent == null) return Field.Bad("a delta without a parent")
        val effective =
            count(json["effectiveTimestamp"]) ?: return Field.Bad("effectiveTimestamp is not an integer ≥ 0")
        val attachment =
            when (val read = attachment(json["attachment"])) {
                is Field.Bad -> return read
                is Field.Good -> read.value
            }
        return Field.Good(CrliteRecord(id, channel, incremental, parent, effective, attachment))
    }

    private fun attachment(value: JsonValue?): Field<CrliteAttachment> {
        val a = value as? JsonObject ?: return Field.Bad("attachment is not an object")
        val filename = string(a["filename"]) ?: return Field.Bad("attachment.filename is not a string")
        if (!AttachmentName.isValid(filename)) return Field.Bad("attachment.filename \"$filename\" fails §6.3's rule")
        val hash =
            string(a["hash"])?.takeIf(::isSha256Hex)
                ?: return Field.Bad("attachment.hash is not 64 lowercase hex digits")
        val size = count(a["size"]) ?: return Field.Bad("attachment.size is not an integer ≥ 0")
        val location = string(a["location"])
        if (location.isNullOrEmpty()) return Field.Bad("attachment.location is not a non-empty string")
        return Field.Good(CrliteAttachment(filename, hash.decodeHex(), size, location))
    }

    private fun isSha256Hex(hash: String): Boolean =
        hash.length == SHA256_HEX && hash.all { it in '0'..'9' || it in 'a'..'f' }

    private fun string(value: JsonValue?): String? = (value as? JsonString)?.value

    /** An integer literal from 0 to `Long.MAX_VALUE`; a double such as `1.0` is not one. */
    private fun count(value: JsonValue?): Long? = (value as? JsonInteger)?.takeIf { !it.negative }?.toLongOrNull()
}
