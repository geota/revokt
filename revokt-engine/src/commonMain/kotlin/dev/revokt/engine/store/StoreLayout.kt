// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.GenerationFiles
import dev.revokt.RevoktStorage
import dev.revokt.TrustClass
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.IndexFormatException
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** A stored generation: its directory name, its `meta.json` and its C2SP image under the generation's names. */
internal class StoredGeneration(
    val directory: String,
    val meta: GenerationMeta,
    val files: GenerationFiles,
)

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
 * Spec §6.5's layout over a [RevoktStorage] for one [dataset] and [channel], under the key prefix
 * `<dataset>/<channel>/`, both lowercase enum names:
 * - `current`: the [Pointer];
 * - `gen-<timestamp>-<hash16>/`: `index.bin`, the delta files and, for `SIGNED`, `records.json`, each under the file's
 *   name in the generation, then `meta.json` last as the completeness marker;
 * - `blobs/<sha256>`: content-addressed full filters, referenced from `meta.json`;
 * - `updater.json`: the [UpdaterRecord].
 *
 * Durability, `store.version`, crash recovery and the lock are 0.3 (§11); this is the key layout the updater runs over
 * `RevoktStorage.inMemory()` in 0.2.
 */
internal class StoreLayout(
    private val storage: RevoktStorage,
    val dataset: Dataset,
    val channel: CrliteChannel,
) {
    /** The key prefix of this dataset and channel, `<dataset>/<channel>`, both lowercase enum names. */
    val root: String = dataset.name.lowercase() + "/" + channel.name.lowercase()

    private val currentKey = "$root/current"
    private val updaterKey = "$root/updater.json"

    fun blobKey(sha256: ByteString): String {
        require(sha256.size == SHA256_BYTES) { "a blob key is a SHA-256" }
        return "$root/blobs/${sha256.hex()}"
    }

    /** The key of the file [name] in the generation directory [directory]. */
    fun fileKey(
        directory: String,
        name: String,
    ): String {
        require(GenerationNames.isDirectory(directory)) { "'$directory' is not a generation directory" }
        return "$root/$directory/$name"
    }

    /** Whether the blob of [sha256] is stored, re-hashed against its key. */
    fun blob(sha256: ByteString): BlobState {
        val stored = storage.read(blobKey(sha256)) ?: return BlobState.ABSENT
        return if (stored.toByteString().sha256() == sha256) BlobState.MATCH else BlobState.MISMATCH
    }

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

    /**
     * Writes the generation [meta] describes into its directory: [index], every file in [deltas] and, for `SIGNED`,
     * [records], then `meta.json` last. [index] must name exactly the keys of `meta.blobs` and [deltas], which do not
     * overlap; the blobs must already be stored. A directory that already holds a `meta.json` is immutable. Returns the
     * directory name.
     */
    fun writeGeneration(
        meta: GenerationMeta,
        index: ByteArray,
        deltas: Map<String, ByteArray>,
        records: ByteArray?,
    ): String {
        require(
            meta.dataset == dataset && meta.channel == channel,
        ) { "meta.json is for ${meta.dataset}/${meta.channel}" }
        require((records != null) == (meta.trustClass == TrustClass.SIGNED)) { "records.json iff SIGNED" }
        val named = GenerationFiles.filenamesIn(index)
        require(
            named.none { it == INDEX || it == META || it == RECORDS },
        ) { "$INDEX names a file the directory reserves" }
        require(deltas.keys.none { it in meta.blobs }) { "a file is both a blob and a delta" }
        require(named == meta.blobs.keys + deltas.keys) { "$INDEX names $named, not the generation's files" }
        val keys = storage.names()
        for (sha256 in meta.blobs.values) require(blobKey(sha256) in keys) { "blob ${sha256.hex()} is not stored" }
        val directory = meta.directory
        check(storage.read(fileKey(directory, META)) == null) { "$directory is complete and immutable" }
        storage.write(fileKey(directory, INDEX), index)
        for ((name, bytes) in deltas) storage.write(fileKey(directory, name), bytes)
        if (records != null) storage.write(fileKey(directory, RECORDS), records)
        storage.write(fileKey(directory, META), MetaJson.write(meta))
        return directory
    }

    /**
     * The `meta.json` in [directory]: [StoreRead.Malformed] when it does not decode, is another dataset's or channel's
     * ("a `channel` mismatch is no generation"), or belongs in another directory.
     */
    fun readMeta(directory: String): StoreRead<GenerationMeta> =
        read(fileKey(directory, META)) { bytes ->
            MetaJson.read(bytes)?.takeIf { it.dataset == dataset && it.channel == channel && it.directory == directory }
        }

    /** The complete generation's `meta.json` in [directory], or null when [readMeta] finds none that is valid here. */
    fun meta(directory: String): GenerationMeta? = (readMeta(directory) as? StoreRead.Found)?.value

    /**
     * The generation in [directory] as a C2SP image under its names, every blob re-hashed against its key, or null
     * when it is not a complete generation of this dataset and channel, a file is missing, or a blob does not match.
     */
    fun readGeneration(directory: String): StoredGeneration? {
        val meta = meta(directory) ?: return null
        if (meta.trustClass == TrustClass.SIGNED && storage.read(fileKey(directory, RECORDS)) == null) return null
        val index = storage.read(fileKey(directory, INDEX)) ?: return null
        val named =
            try {
                C2spIndex.read(index).filenames.toSet()
            } catch (ignored: IndexFormatException) {
                return null
            }
        if (!named.containsAll(meta.blobs.keys)) return null
        val files = LinkedHashMap<String, ByteArray>()
        files[INDEX] = index
        for (name in named) {
            val sha256 = meta.blobs[name]
            val bytes = if (sha256 == null) storage.read(fileKey(directory, name)) else storage.read(blobKey(sha256))
            if (bytes == null || (sha256 != null && bytes.toByteString().sha256() != sha256)) return null
            files[name] = bytes
        }
        val image =
            try {
                GenerationFiles(
                    meta.generationId,
                    meta.dataset,
                    meta.trustClass,
                    meta.format,
                    files,
                    meta.sourceTimestampMillis,
                )
            } catch (ignored: IllegalArgumentException) {
                return null
            }
        return StoredGeneration(directory, meta, image)
    }

    /** The `records.json` of the `SIGNED` generation in [directory], or null. */
    fun records(directory: String): ByteArray? = storage.read(fileKey(directory, RECORDS))

    /**
     * Deletes every key in [directory], `meta.json` first (the reverse of the write order), so an interrupted delete
     * never leaves a directory that reads as complete with files missing. Its blobs stay (content-addressed).
     */
    fun deleteGeneration(directory: String) {
        storage.delete(fileKey(directory, META))
        val prefix = fileKey(directory, "")
        for (key in storage.names()) if (key.startsWith(prefix)) storage.delete(key)
    }

    /** The `current` pointer. */
    fun pointer(): StoreRead<Pointer> = read(currentKey, PointerJson::read)

    /**
     * Flips the pointer to [pointer]. Both directories must hold complete generations of this dataset and channel, and
     * `previous` must be of the same or a higher trust class than `live`, so recovery never falls to a lower class.
     */
    fun point(pointer: Pointer) {
        val live = requireNotNull(meta(pointer.live)) { "${pointer.live} is not a complete generation" }
        pointer.previous?.let {
            val previous = requireNotNull(meta(it)) { "$it is not a complete generation" }
            require(previous.trustClass.rank >= live.trustClass.rank) {
                "previous is ${previous.trustClass}, below live's ${live.trustClass}"
            }
        }
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

    /**
     * Keeps exactly the directories the pointer names and the blobs their `meta.json` reference: deletes every other
     * directory under this dataset and channel, complete or not, and every other blob. Files directly under the prefix
     * (`current`, `updater.json`) stay. With no pointer nothing is kept. When it cannot tell what is referenced, it
     * keeps more: a malformed `current` deletes nothing, and a pointed directory whose `meta.json` is present but
     * malformed keeps every blob. Returns the number of keys deleted.
     *
     * Runs on the loader thread only, never between [putBlob] or [writeGeneration] and [point]: a blob or directory of
     * an install not yet pointed to is unreferenced, so prune would delete it.
     */
    fun prune(): Int {
        val pointer =
            when (val read = pointer()) {
                StoreRead.Absent -> null
                StoreRead.Malformed -> return 0
                is StoreRead.Found -> read.value
            }
        val kept = listOfNotNull(pointer?.live, pointer?.previous).toSet()
        val metas = kept.map(::readMeta)
        val blobs =
            if (StoreRead.Malformed in metas) {
                null
            } else {
                metas
                    .flatMap {
                        (it as? StoreRead.Found)
                            ?.value
                            ?.blobs
                            ?.values
                            .orEmpty()
                    }.mapTo(
                        HashSet(),
                    ) { "$BLOBS_DIR/${it.hex()}" }
            }
        val doomed = storage.names().filter { key -> isPruned(key, kept, blobs) }
        doomed.forEach(storage::delete)
        return doomed.size
    }

    /**
     * Whether prune deletes [key]: a key in a directory under [root] other than [kept], or a blob not in [blobs] (null
     * keeps every blob).
     */
    private fun isPruned(
        key: String,
        kept: Set<String>,
        blobs: Set<String>?,
    ): Boolean {
        val rest = key.removePrefix("$root/")
        val slash = rest.indexOf('/')
        if (rest == key || slash < 0) return false
        val top = rest.substring(0, slash)
        return if (top == BLOBS_DIR) blobs != null && rest !in blobs else top !in kept
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
        const val INDEX: String = "index.bin"
        const val META: String = "meta.json"
        const val RECORDS: String = "records.json"
        private const val BLOBS_DIR = "blobs"
    }
}
