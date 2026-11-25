// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.Freshness
import dev.revokt.engine.json.CanonicalJson
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.verify.ContentSignature
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString

/**
 * A generation file (spec §6.5): one generation of [dataset] and [channel], stored under the SHA-256 of its own bytes
 * ([GenerationFileJson.name]). It holds the verified collection payload, [records] at [lastModified] (`<ts>`), and the
 * [signature] that verified it under the leaf whose SHA-256 is [signerLeafSha256]. [seedFormat] is set exactly for a
 * seed's generation ([Freshness.SEED_SIGNED_TIME]). Everything else a generation has (its placed filters and their names,
 * each blob's hash, its id, its format) is derived from [records] at load, never stored.
 *
 * [records] are the payload's records: sorted by id, tombstones removed, ids distinct, every number an integer, so
 * [payload], their canonical serialisation, is the signed bytes (§7.1). [payload] is computed once.
 */
internal class GenerationFile(
    val dataset: Dataset,
    val channel: CrliteChannel,
    val freshness: Freshness,
    val seedFormat: Int?,
    val signature: ByteString,
    val signerLeafSha256: ByteString,
    records: List<JsonObject>,
    val lastModified: Long,
) {
    val records: List<JsonObject> = records.toList()

    /** The signed payload `{"data": records, "last_modified": "<ts>"}` in canonical JSON: the seed's `records.json`. */
    val payload: ByteArray =
        requireNotNull(
            ContentSignature.recordsJson(this.records, lastModified),
        ) { "the records have no canonical form" }

    init {
        require(
            (freshness == Freshness.SEED_SIGNED_TIME) == (seedFormat != null),
        ) { "seedFormat is set exactly for a seed" }
        require(seedFormat == null || seedFormat > 0) { "seedFormat $seedFormat is not positive" }
        require(signature.size > 0 && signature.size % 2 == 0) { "the signature is not a raw r || s pair" }
        require(signerLeafSha256.size == SHA256_BYTES) { "the signer leaf SHA-256 is ${signerLeafSha256.size} bytes" }
        require(lastModified >= 0) { "the timestamp $lastModified is negative" }
        // The payload must hold the records as given: sorted, ids distinct, no tombstone, so that what is stored is what
        // was signed. Checked on the records first, so a tombstone holding a number with no canonical form is refused
        // here rather than thrown at the canonical write below.
        require(ContentSignature.payloadRecords(this.records) == this.records) {
            "the records are not sorted by id, or hold a tombstone"
        }
        require(CanonicalJson.write(payloadObject(this.records, lastModified)).contentEquals(payload)) {
            "the records are not the payload's"
        }
    }

    override fun toString(): String = "GenerationFile($dataset/$channel at $lastModified, $freshness)"
}

/**
 * The generation file's encoding (spec §6.5): one JSON object in canonical JSON, read strictly. Its members are
 * `generationVersion`, `dataset`, `channel` and `freshness` (enum names), `seedFormat` (a seed's only), `signature` and
 * `signerLeafSha256` (lowercase hex), and `records`, the payload object. A file is read only when it is exactly the
 * canonical encoding of what it decodes to: no other member, none twice, no member a seed's alone on a sync's file,
 * keys in order, no whitespace. So [write] of what [read] returns gives back the same bytes, and the same name.
 */
internal object GenerationFileJson {
    const val VERSION: Long = 1

    /** The envelope the cap allows beside the records: everything but `records` fits in a few hundred bytes. */
    const val ENVELOPE_BYTES: Long = 64L * 1024

    /** The size cap of a generation file: the configured [maxJsonBytes] plus [ENVELOPE_BYTES], saturating. */
    fun cap(maxJsonBytes: Long): Long {
        require(maxJsonBytes > 0) { "maxJsonBytes $maxJsonBytes is not positive" }
        return if (maxJsonBytes > Long.MAX_VALUE - ENVELOPE_BYTES) Long.MAX_VALUE else maxJsonBytes + ENVELOPE_BYTES
    }

    /** The name of a generation file of [bytes]: the lowercase hex SHA-256 of the bytes, a store key segment. */
    fun name(bytes: ByteArray): String = bytes.toByteString().sha256().hex()

    /**
     * [file]'s bytes, or null when they are over [cap]: the cap is checked before the write as well as at every read
     * (spec §6.5), so an install never stores a file its own load-back would refuse.
     */
    fun write(
        file: GenerationFile,
        cap: Long,
    ): ByteArray? = write(file).takeIf { it.size <= cap }

    /** [file]'s canonical bytes, whatever their size. */
    fun write(file: GenerationFile): ByteArray =
        StoreFields.encode(
            "channel" to StoreFields.string(file.channel.name),
            "dataset" to StoreFields.string(file.dataset.name),
            "freshness" to StoreFields.string(file.freshness.name),
            "generationVersion" to StoreFields.long(VERSION),
            "records" to payloadObject(file.records, file.lastModified),
            "seedFormat" to StoreFields.long(file.seedFormat?.toLong()),
            "signature" to StoreFields.string(file.signature.hex()),
            "signerLeafSha256" to StoreFields.string(file.signerLeafSha256.hex()),
        )

    /**
     * The generation file stored under [name]: null when [bytes] are over [cap], do not hash to [name], or do not
     * parse ([readUnhashed]). The cap is checked before the hash, and the hash before anything is parsed, so a flipped
     * byte never becomes another generation (spec §6.5 Load, step 1). The one read a store makes.
     */
    fun read(
        bytes: ByteArray,
        name: String,
        cap: Long,
    ): GenerationFile? {
        if (bytes.size > cap) return null
        if (name(bytes) != name) return null
        return readUnhashed(bytes, cap)
    }

    /**
     * The generation file in [bytes] with no re-hash against a name, or null when they are over [cap], are not the
     * canonical encoding of one, or are of another `generationVersion`: for the codec's own tests and fuzzing, never a
     * store read, which is [read] with the name. Dataset and channel are the caller's to compare.
     */
    fun readUnhashed(
        bytes: ByteArray,
        cap: Long,
    ): GenerationFile? {
        if (bytes.size > cap) return null
        val file = StoreFields.decodeOrNull(bytes, cap, ::decode) ?: return null
        // Canonical bytes only: what is read is what this code would write, byte for byte.
        return file.takeIf { write(it).contentEquals(bytes) }
    }

    /** The members of a generation file, strictly: a [MalformedStoreFileException] for anything else. */
    private fun decode(f: StoreFields): GenerationFile {
        f.only(
            "channel",
            "dataset",
            "freshness",
            "generationVersion",
            "records",
            "seedFormat",
            "signature",
            "signerLeafSha256",
        )
        if (f.long("generationVersion") != VERSION) f.wrong("generationVersion")
        val records = f.optObject("records") ?: f.missing("records")
        records.only("data", "last_modified")
        val data = records.array("data").map { it as? JsonObject ?: records.wrong("data") }
        return GenerationFile(
            dataset = f.enum("dataset"),
            channel = f.enum("channel"),
            freshness = f.enum("freshness"),
            seedFormat = seedFormat(f),
            signature = hex(f, "signature"),
            signerLeafSha256 = hex(f, "signerLeafSha256"),
            records = data,
            lastModified = timestamp(records),
        )
    }

    /** `seedFormat`, when present: a positive `Int`. */
    private fun seedFormat(f: StoreFields): Int? {
        val value = f.optLong("seedFormat") ?: return null
        if (value !in 1..Int.MAX_VALUE) f.wrong("seedFormat")
        return value.toInt()
    }

    /** `last_modified`: a non-negative decimal integer as a string, in its shortest form (no sign, no leading zero). */
    private fun timestamp(records: StoreFields): Long {
        val stamp = records.string("last_modified")
        val value = stamp.toLongOrNull()
        if (value == null || value < 0 || value.toString() != stamp) records.wrong("last_modified")
        return value
    }

    /** The bytes of the lowercase hex string [key] holds. */
    private fun hex(
        f: StoreFields,
        key: String,
    ): ByteString {
        val hex = f.string(key)
        if (hex.length % 2 != 0 || !hex.all { it in '0'..'9' || it in 'a'..'f' }) f.wrong(key)
        return hex.decodeHex()
    }
}

/** The payload object `{"data": [records], "last_modified": "<ts>"}`. */
private fun payloadObject(
    records: List<JsonObject>,
    lastModified: Long,
): JsonObject = JsonObject.of("data" to JsonArray(records), "last_modified" to JsonString(lastModified.toString()))
