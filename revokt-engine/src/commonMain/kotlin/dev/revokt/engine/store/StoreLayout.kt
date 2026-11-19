// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.GenerationFiles
import dev.revokt.RevoktStorage
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
 * - `gen-<timestamp>-<hash16>/`: `index.bin`, the delta files and `records.json`, each under the file's
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

    /**
     * Writes the generation [meta] describes into its directory: every file in [deltas], then [completeGeneration].
     * Returns the directory name.
     */
    fun writeGeneration(
        meta: GenerationMeta,
        index: ByteArray,
        deltas: Map<String, ByteArray>,
        records: ByteArray,
    ): String {
        requireConsistent(meta, index, deltas.keys, storage.names())
        check(meta(meta.directory) == null) { "${meta.directory} is complete and immutable" }
        for ((name, bytes) in deltas) stageFile(meta.directory, name, bytes)
        return completeGeneration(meta, index, deltas.mapValues { it.value.toByteString().sha256() }, records)
    }

    /**
     * Makes [directory] incomplete again by deleting its `meta.json` alone, so its files stay to be re-hashed and reused
     * by [completeGeneration]: for a directory referenced by nothing that an install completes afresh. Never for one the
     * engine holds live or the pointer names: a directory the pointer names throws [IllegalArgumentException] and stays
     * as it is, so a caller that mistakes a pointed generation for an orphan fails loudly rather than deleting it. It
     * fails closed: a pointer that is present but malformed may name any directory, so nothing is reopened then either
     * (a pointer that cannot be read at all throws from the read).
     */
    fun reopen(directory: String) {
        val named =
            when (val read = pointer()) {
                StoreRead.Absent -> emptySet()
                StoreRead.Malformed -> null
                is StoreRead.Found -> setOfNotNull(read.value.live, read.value.previous)
            }
        requireNotNull(named) { "the pointer is malformed, so $directory is never reopened" }
        require(directory !in named) { "$directory is pointed to and is never reopened" }
        storage.delete(fileKey(directory, META))
    }

    /**
     * Writes [bytes] as the file [name] of [directory], a generation not yet complete: a delta body written as it is
     * fetched, so the loader holds one body at a time (spec §6.5: "write …, drop the body"), and the directory is
     * completed later by [completeGeneration]. A complete directory is immutable.
     */
    fun stageFile(
        directory: String,
        name: String,
        bytes: ByteArray,
    ) {
        require(name != INDEX && name != META && name != RECORDS) { "$name is a file the directory reserves" }
        check(meta(directory) == null) { "$directory is complete and immutable" }
        storage.write(fileKey(directory, name), bytes)
    }

    /**
     * The file [name] of [directory] ([INDEX], [RECORDS] or a delta), or null when it is absent; with [sha256], the
     * signed record's hash, re-hashed against it, and null when it mismatches too (#201: a stored delta is re-hashed
     * before it is reused, as a blob is).
     */
    fun file(
        directory: String,
        name: String,
        sha256: ByteString? = null,
    ): ByteArray? =
        storage.read(fileKey(directory, name))?.takeIf { sha256 == null || it.toByteString().sha256() == sha256 }

    /**
     * Completes the generation [meta] describes in its directory, whose delta files [deltas] (each name to its signed
     * SHA-256) are already staged ([stageFile]): deletes every other key of the directory, a malformed `meta.json`
     * first, so no file of an earlier attempt stays; checks each staged delta re-hashes; then writes [index], [records]
     * and `meta.json` last. [index] must name exactly the keys of `meta.blobs` and [deltas], which
     * do not overlap; the blobs must already be stored. A directory that already holds a `meta.json` is immutable.
     * Returns the directory name; a staged delta that is missing or does not re-hash throws [IllegalStateException].
     */
    fun completeGeneration(
        meta: GenerationMeta,
        index: ByteArray,
        deltas: Map<String, ByteString>,
        records: ByteArray,
    ): String {
        val keys = storage.names()
        requireConsistent(meta, index, deltas.keys, keys)
        val directory = meta.directory
        check(meta(directory) == null) { "$directory is complete and immutable" }
        val prefix = fileKey(directory, "")
        val staged = deltas.keys.mapTo(HashSet()) { fileKey(directory, it) }
        storage.delete(fileKey(directory, META))
        for (key in keys) if (key.startsWith(prefix) && key !in staged) storage.delete(key)
        for ((name, sha256) in deltas) {
            checkNotNull(file(directory, name, sha256)) { "$directory/$name is not staged, or does not re-hash" }
        }
        storage.write(fileKey(directory, INDEX), index)
        storage.write(fileKey(directory, RECORDS), records)
        storage.write(fileKey(directory, META), MetaJson.write(meta))
        return directory
    }

    /**
     * The `meta.json` in [directory]: [StoreRead.Malformed] when it does not decode, is another dataset's or channel's
     * ("a `channel` mismatch is no generation"), or belongs in another directory.
     */
    fun readMeta(directory: String): StoreRead<GenerationMeta> =
        read(storage, fileKey(directory, META)) { bytes ->
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
        if (storage.read(fileKey(directory, RECORDS)) == null) return null
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
                    meta.format,
                    files,
                    meta.sourceTimestampMillis,
                )
            } catch (ignored: IllegalArgumentException) {
                return null
            }
        return StoredGeneration(directory, meta, image)
    }

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
    fun pointer(): StoreRead<Pointer> = read(storage, currentKey, PointerJson::read)

    /**
     * Flips the pointer to [pointer]. Both directories must hold complete generations of this dataset and channel.
     */
    fun point(pointer: Pointer) {
        requireNotNull(meta(pointer.live)) { "${pointer.live} is not a complete generation" }
        pointer.previous?.let { requireNotNull(meta(it)) { "$it is not a complete generation" } }
        storage.write(currentKey, PointerJson.write(pointer))
    }

    /** The updater record, its backoffs clamped against [nowMillis], with the ids of any dropped source entries. */
    fun updater(nowMillis: Long): StoreRead<UpdaterRead> = read(storage, updaterKey) { UpdaterJson.read(it, nowMillis) }

    fun writeUpdater(
        record: UpdaterRecord,
        nowMillis: Long,
    ) {
        storage.write(updaterKey, UpdaterJson.write(record, nowMillis))
    }

    /**
     * Keeps exactly the directories the pointer names and the blobs their `meta.json` reference: deletes every other
     * directory under this dataset and channel, complete or not, and every other blob. Files directly under the prefix
     * (`current`, `updater.json`) stay. When it cannot tell what is referenced, it keeps more: an absent or malformed
     * `current` deletes nothing (a data-loss guard, the #200 review: a storage that lost `current` must not lose its
     * generations too), and a pointed directory whose `meta.json` is present but malformed keeps every blob. Returns the
     * number of keys deleted.
     *
     * Runs on the loader thread only, never between [putBlob] or [writeGeneration] and [point]: a blob or directory of
     * an install not yet pointed to is unreferenced, so prune would delete it.
     */
    fun prune(): Int {
        val pointer =
            when (val read = pointer()) {
                StoreRead.Absent, StoreRead.Malformed -> return 0
                is StoreRead.Found -> read.value
            }
        val kept = listOfNotNull(pointer.live, pointer.previous).toSet()
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
        val doomed = storage.names().filter { key -> isPruned(root, key, kept, blobs) }
        doomed.forEach(storage::delete)
        return doomed.size
    }

    companion object {
        const val INDEX: String = "index.bin"
        const val META: String = "meta.json"
        const val RECORDS: String = "records.json"
    }
}

/**
 * [meta], [index] and the delta names [deltas] describe one generation of [meta]'s dataset and channel for a
 * [StoreLayout] whose store holds [keys]: [index] names exactly the blobs and deltas, none of them a reserved name, and
 * every blob is stored.
 */
private fun StoreLayout.requireConsistent(
    meta: GenerationMeta,
    index: ByteArray,
    deltas: Set<String>,
    keys: Set<String>,
) {
    require(
        meta.dataset == dataset && meta.channel == channel,
    ) { "meta.json is for ${meta.dataset}/${meta.channel}" }
    val named = GenerationFiles.filenamesIn(index)
    require(
        named.none { it == StoreLayout.INDEX || it == StoreLayout.META || it == StoreLayout.RECORDS },
    ) { "${StoreLayout.INDEX} names a file the directory reserves" }
    require(deltas.none { it in meta.blobs }) { "a file is both a blob and a delta" }
    require(named == meta.blobs.keys + deltas) { "${StoreLayout.INDEX} names $named, not the generation's files" }
    for (sha256 in meta.blobs.values) require(blobKey(sha256) in keys) { "blob ${sha256.hex()} is not stored" }
}

/**
 * Whether prune deletes [key] under [root]: a key in a directory under [root] other than [kept], or a blob not in
 * [blobs] (null keeps every blob).
 */
private fun isPruned(
    root: String,
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

/** [key]'s file in [storage] through [decode], whose null means malformed. */
private fun <T> read(
    storage: RevoktStorage,
    key: String,
    decode: (ByteArray) -> T?,
): StoreRead<T> {
    val bytes = storage.read(key) ?: return StoreRead.Absent
    return decode(bytes)?.let { StoreRead.Found(it) } ?: StoreRead.Malformed
}

/** The directory of the content-addressed full filters under a layout's root. */
private const val BLOBS_DIR = "blobs"
