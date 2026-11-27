// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.store

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * A store file read three ways, so a caller can count a corrupt file as a store failure (spec §6.5, `storeFailures`)
 * rather than take it for an empty store.
 */
internal sealed interface StoreRead<out T> {
    /** No file has the key. */
    data object Absent : StoreRead<Nothing>

    /** The file is there but does not decode, or does not belong where it is. */
    data object Malformed : StoreRead<Nothing>

    data class Found<out T>(
        val value: T,
    ) : StoreRead<T>
}

/** What [StoreLayout.blob] found under a blob key. */
internal enum class BlobState { ABSENT, MATCH, MISMATCH }

/** What [StoreLayout.putBlob] did: wrote a new key, reused a matching blob, or rewrote a mismatching one. */
internal enum class BlobWrite { WRITTEN, REUSED, REWRITTEN }

/**
 * Spec §6.5's content-addressed layout over a [StorageBackend] for one [dataset] and [channel], under the key prefix
 * `<dataset>/<channel>/`, both lowercase enum names:
 * - `blobs/<sha256>`: every attachment, full or delta, under the SHA-256 its signed record gives;
 * - `generations/<sha256>`: one [GenerationFile] per generation, under the SHA-256 of its own bytes;
 * - `current`: the [Pointer], the one write that makes a generation live;
 * - `updater.json`: the [UpdaterRecord].
 *
 * Every key but `current` and `updater.json` is named by the hash of its bytes, and every read of one re-hashes it, so
 * a write there only ever writes the bytes its name promises. [maxJsonBytes] is the configured cap (§4 `limits { }`),
 * from which the generation file's cap derives ([generationCap]); [maxChangesetRecords] caps a stored generation's
 * records as a sync caps a changeset's.
 *
 * This class reads and writes keys. What a generation is (its records placed, its blobs, its index: Load, §6.5) and
 * what prune keeps are `dev.revokt.engine.update`'s, beside the install.
 */
internal class StoreLayout(
    private val storage: StorageBackend,
    val dataset: Dataset,
    val channel: CrliteChannel,
    val maxJsonBytes: Long = RevoktLimits.MAX_JSON_BYTES,
    val maxChangesetRecords: Int = RevoktLimits.MAX_CHANGESET_RECORDS,
) {
    /** The key prefix of this dataset and channel, `<dataset>/<channel>`, both lowercase enum names. */
    val root: String = dataset.name.lowercase() + "/" + channel.name.lowercase()

    /** The size cap of a generation file here: [maxJsonBytes] plus 64 KiB (spec §6.5). */
    val generationCap: Long = GenerationFileJson.cap(maxJsonBytes)

    private val currentKey = "$root/current"
    private val updaterKey = "$root/updater.json"
    private val blobPrefix = "$root/$BLOBS/"
    private val generationPrefix = "$root/$GENERATIONS/"

    fun blobKey(sha256: ByteString): String {
        require(sha256.size == SHA256_BYTES) { "a blob key is a SHA-256" }
        return blobPrefix + sha256.hex()
    }

    /** The key of the generation file [name], 64 lowercase hex characters. */
    fun generationKey(name: String): String {
        require(GenerationNames.isSha256Hex(name)) { "'$name' is not a generation file name" }
        return generationPrefix + name
    }

    /** Whether the blob of [sha256] is stored, re-hashed against its key. */
    fun blob(sha256: ByteString): BlobState {
        val stored = storage.read(blobKey(sha256)) ?: return BlobState.ABSENT
        return if (stored.toByteString().sha256() == sha256) BlobState.MATCH else BlobState.MISMATCH
    }

    /** The blob of [sha256], re-hashed against its key: its bytes on a match, null when it is absent or mismatches. */
    fun readBlob(sha256: ByteString): ByteArray? =
        storage.read(blobKey(sha256))?.takeIf { it.toByteString().sha256() == sha256 }

    /**
     * Stores [bytes] under the key of their SHA-256, unless that key already holds them: an existing blob is re-hashed
     * and reused on a match and rewritten on a mismatch, which the caller counts (`storeFailures++`).
     */
    fun putBlob(bytes: ByteArray): BlobWrite {
        val sha256 = bytes.toByteString().sha256()
        val state = blob(sha256)
        if (state == BlobState.MATCH) return BlobWrite.REUSED
        storage.write(blobKey(sha256), bytes)
        return if (state == BlobState.ABSENT) BlobWrite.WRITTEN else BlobWrite.REWRITTEN
    }

    /** The SHA-256s (lowercase hex) of every key under `blobs/` with a 64-hex name. */
    fun blobNames(): Set<String> = namesUnder(blobPrefix)

    /** The names of every key under `generations/` with a 64-hex name: the adopt scan's and prune's list (§6.5). */
    fun generationNames(): Set<String> = namesUnder(generationPrefix)

    /**
     * Stores the generation file [bytes] under its name, which it returns, unless that key already holds a file that
     * re-hashes to it (an install retried over the same changeset writes nothing new). [bytes] must fit [generationCap]:
     * the install checks it first, so it never writes a file its own load-back would refuse.
     */
    fun putGeneration(bytes: ByteArray): String {
        require(bytes.size <= generationCap) { "a generation file of ${bytes.size} bytes is over $generationCap" }
        val name = GenerationFileJson.name(bytes)
        val key = generationKey(name)
        val stored = storage.read(key)
        if (stored == null || GenerationFileJson.name(stored) != name) storage.write(key, bytes)
        return name
    }

    /**
     * Load's step 1 (spec §6.5) for the generation file [name]: read it, check [generationCap], re-hash it against
     * [name] and parse it strictly, with this dataset and channel and a `generationVersion` this binary reads.
     * [StoreRead.Absent] when no file has the key; [StoreRead.Malformed] for any other failure. Never throws for a file's
     * content; a storage read that fails throws.
     */
    fun readGeneration(name: String): StoreRead<GenerationFile> {
        val bytes = storage.read(generationKey(name)) ?: return StoreRead.Absent
        val file =
            GenerationFileJson
                .read(bytes, name, generationCap)
                ?.takeIf { it.dataset == dataset && it.channel == channel }
                ?: return StoreRead.Malformed
        return StoreRead.Found(file)
    }

    /** Deletes the generation file [name]; prune's alone. */
    fun deleteGeneration(name: String) {
        storage.delete(generationKey(name))
    }

    /** Deletes the blob of [sha256Hex]; prune's alone, after every generation file it deletes. */
    fun deleteBlob(sha256Hex: String) {
        require(GenerationNames.isSha256Hex(sha256Hex)) { "'$sha256Hex' is not a blob name" }
        storage.delete(blobPrefix + sha256Hex)
    }

    /** The `current` pointer. */
    fun pointer(): StoreRead<Pointer> = read(currentKey, PointerJson::read)

    /** Flips the pointer to [pointer]: the caller has loaded its `live` back and qualified its `previous`. */
    fun point(pointer: Pointer) {
        storage.write(currentKey, PointerJson.write(pointer))
    }

    /** The updater record, its backoffs clamped against [nowMillis], with the ids of any dropped source entries. */
    fun updater(nowMillis: Long): StoreRead<UpdaterRead> = read(updaterKey) { UpdaterJson.read(it, nowMillis) }

    fun writeUpdater(
        record: UpdaterRecord,
        nowMillis: Long,
    ) {
        storage.write(updaterKey, UpdaterJson.write(record, nowMillis))
    }

    /** The 64-hex last segments of the keys directly under [prefix]. */
    private fun namesUnder(prefix: String): Set<String> =
        storage
            .names()
            .mapNotNullTo(LinkedHashSet()) { key ->
                key.removePrefix(prefix).takeIf { key.startsWith(prefix) && GenerationNames.isSha256Hex(it) }
            }

    /** [key]'s file through [decode], whose null means malformed. */
    private fun <T> read(
        key: String,
        decode: (ByteArray) -> T?,
    ): StoreRead<T> {
        val bytes = storage.read(key) ?: return StoreRead.Absent
        return decode(bytes)?.let { StoreRead.Found(it) } ?: StoreRead.Malformed
    }

    companion object {
        /** The name of a generation's `index.bin` in its [dev.revokt.GenerationFiles]; it is never stored (§6.5). */
        const val INDEX: String = "index.bin"

        private const val BLOBS = "blobs"
        private const val GENERATIONS = "generations"
    }
}

internal const val SHA256_BYTES: Int = 32
