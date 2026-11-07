// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.TrustClass
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.json.JsonString
import okio.ByteString
import okio.ByteString.Companion.decodeHex

/** The `SIGNED` members of a `meta.json` (spec §6.5): the changeset's timestamp, the signer leaf's SHA-256, the signature. */
internal data class SignedMeta(
    val changesetTimestampMillis: Long,
    val signerLeafSha256: ByteString,
    val signature: ByteString,
) {
    init {
        require(signerLeafSha256.size == SHA256_BYTES) { "the signer leaf SHA-256 is ${signerLeafSha256.size} bytes" }
        require(signature.size == P384_SIGNATURE_BYTES) { "the signature is ${signature.size} bytes, not raw r || s" }
    }
}

/**
 * A generation's `meta.json` (spec §6.5), the completeness marker written last in its directory. [channel] is the
 * channel enum's name; [blobs] maps each full filter's name in the generation (its derived name, never the attachment
 * filename) to the SHA-256 of its blob; [signed] is present exactly when [trustClass] is `SIGNED`. [collection] is the
 * Remote Settings collection, absent for a source that has none.
 */
internal data class GenerationMeta(
    val dataset: Dataset,
    val channel: String,
    val trustClass: TrustClass,
    val generationId: String,
    val format: FilterFormat,
    val freshness: Freshness,
    val sourceTimestampMillis: Long,
    val collection: String?,
    val blobs: Map<String, ByteString>,
    val signed: SignedMeta?,
) {
    /** The generation's directory name, `gen-<timestamp>-<hash16>`. */
    val directory: String = GenerationNames.directory(sourceTimestampMillis, generationId)

    init {
        require(StoreLayout.isChannelName(channel)) { "'$channel' is not a channel name" }
        require((signed != null) == (trustClass == TrustClass.SIGNED)) { "signed members iff SIGNED, got $trustClass" }
        for ((name, sha256) in blobs) {
            require(C2spIndex.isFilename(name)) { "'$name' is not a generation file name" }
            require(sha256.size == SHA256_BYTES) { "the blob of '$name' is not a SHA-256" }
        }
    }
}

internal const val SHA256_BYTES: Int = 32

/** A `p384ecdsa` content signature as stored: the raw `r || s`, 48 bytes each (spec §6.5 seed archive, §7.1). */
internal const val P384_SIGNATURE_BYTES: Int = 96

/** `meta.json`'s encoding: canonical JSON over the engine's JSON tree, enums by name, bytes as lowercase hex. */
internal object MetaJson {
    const val VERSION: Long = 1

    fun write(meta: GenerationMeta): ByteArray =
        StoreFields.encode(
            "metaVersion" to StoreFields.long(VERSION),
            "dataset" to StoreFields.string(meta.dataset.name),
            "channel" to StoreFields.string(meta.channel),
            "trustClass" to StoreFields.string(meta.trustClass.name),
            "generationId" to StoreFields.string(meta.generationId),
            "format" to StoreFields.string(meta.format.name),
            "freshness" to StoreFields.string(meta.freshness.name),
            "sourceTimestampMillis" to StoreFields.long(meta.sourceTimestampMillis),
            "collection" to StoreFields.string(meta.collection),
            "blobs" to
                StoreFields.objectOf(meta.blobs.map { (name, sha256) -> name to JsonString(BLOBS + sha256.hex()) }),
            "changesetTimestampMillis" to StoreFields.long(meta.signed?.changesetTimestampMillis),
            "signerLeafSha256" to StoreFields.string(meta.signed?.signerLeafSha256?.hex()),
            "signature" to StoreFields.string(meta.signed?.signature?.hex()),
        )

    /** The `meta.json` in [bytes], or null when it is malformed or of another `metaVersion`. */
    fun read(bytes: ByteArray): GenerationMeta? =
        StoreFields.decodeOrNull(bytes) { f ->
            if (f.long("metaVersion") != VERSION) f.wrong("metaVersion")
            val trustClass = f.enum<TrustClass>("trustClass")
            GenerationMeta(
                dataset = f.enum("dataset"),
                channel = f.string("channel"),
                trustClass = trustClass,
                generationId = f.string("generationId"),
                format = f.enum("format"),
                freshness = f.enum("freshness"),
                sourceTimestampMillis = f.long("sourceTimestampMillis"),
                collection = f.optString("collection"),
                blobs = blobs(f.optObject("blobs") ?: f.missing("blobs")),
                signed =
                    if (trustClass == TrustClass.SIGNED) {
                        SignedMeta(
                            changesetTimestampMillis = f.long("changesetTimestampMillis"),
                            signerLeafSha256 = hex(f, "signerLeafSha256"),
                            signature = hex(f, "signature"),
                        )
                    } else {
                        null
                    },
            )
        }

    /** The blob key segment prefix a `blobs` value carries: `blobs/<sha256>`. */
    private const val BLOBS = "blobs/"

    private fun blobs(f: StoreFields): Map<String, ByteString> =
        f.members.associate { (name, value) ->
            val key = (value as? JsonString)?.value ?: f.wrong(name)
            val hex = key.removePrefix(BLOBS)
            if (!key.startsWith(BLOBS) || !GenerationNames.isSha256Hex(hex)) f.wrong(name)
            name to hex.decodeHex()
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
