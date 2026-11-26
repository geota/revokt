// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// detekt 1.23 resolves types with a Kotlin 2.0 compiler that cannot read the 2.4 stdlib's metadata, so it reports the code
// after an inline lambda's non-local return or `Nothing` call as unreachable; kotlinc's own unreachable-code check holds.
@file:Suppress("UnreachableCode")
@file:OptIn(dev.revokt.RevoktInternalApi::class, RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.FilterFormat
import dev.revokt.GenerationFiles
import dev.revokt.LogLevel
import dev.revokt.RevoktLogger
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.engine.fetch.CrliteRecord
import dev.revokt.engine.fetch.CrliteSchema
import dev.revokt.engine.fetch.RecordCheck
import dev.revokt.engine.store.BlobState
import dev.revokt.engine.store.GenerationFile
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import okio.ByteString

/**
 * A stored generation through Load's steps 1 and 2 (spec §6.5): the generation file [name] read, re-hashed and parsed
 * ([file]), and its channel's [records] schema-checked and placed ([placed], in `index.bin` order). Everything a
 * generation has beyond its file is derived here: [generationId], [timestampMillis] and each placed filter's signed
 * SHA-256 ([sha256]).
 */
internal class StoredGeneration(
    val name: String,
    val file: GenerationFile,
    val records: List<CrliteRecord>,
    val placed: List<PlacedFilter>,
) {
    private val byId: Map<String, CrliteRecord> = records.associateBy { it.id }

    /** `<ts>`, the signed `last_modified`. */
    val timestampMillis: Long get() = file.lastModified

    /** `"<ts>/<last placed record id>"` (spec §4 `DataState.generationId`). */
    val generationId: String = "${file.lastModified}/${placed.last().record.id}"

    /** The signed record of the placed filter [p]. */
    fun record(p: PlacedFilter): CrliteRecord = byId.getValue(p.record.id)

    /** The signed SHA-256 of the placed filter [p]'s attachment: its blob's key. */
    fun sha256(p: PlacedFilter): ByteString = record(p).attachment.sha256

    /** The blobs this generation names, as lowercase hex: what prune keeps for it. */
    val blobNames: Set<String> get() = placed.mapTo(LinkedHashSet()) { sha256(it).hex() }

    override fun toString(): String = "StoredGeneration($generationId in $name)"
}

/** A stored generation through Load's step 4: the [files] handed to `prepare`, and the full filter's [format]. */
internal class LoadedGeneration(
    val generation: StoredGeneration,
    val files: GenerationFiles,
    val format: FilterFormat,
)

/** How a full load of a stored generation ended (spec §6.5 Load): [Loaded], or [Failed] at the step [detail] names. */
internal sealed interface GenerationLoad {
    class Loaded(
        val value: LoadedGeneration,
    ) : GenerationLoad

    /** [absent] when no generation file has the name (the pointer names a key nothing stored hashes to). */
    class Failed(
        val absent: Boolean,
        val detail: String,
    ) : GenerationLoad {
        override fun toString(): String = "Failed($detail)"
    }
}

/**
 * Load's step 2 over [file], read as [name]: the records of this layout's channel schema-checked
 * ([CrliteSchema.check], capped at [StoreLayout.maxChangesetRecords]) and placed ([placeFilters]); null when either
 * refuses them.
 */
internal fun StoreLayout.place(
    name: String,
    file: GenerationFile,
): StoredGeneration? {
    val crlite = (CrliteSchema.check(file.records, channel, maxChangesetRecords) as? RecordCheck.Passed)?.records
    val placed =
        crlite?.let { records ->
            (placeFilters(records.map { it.toFilterRecord() }, channel) as? Placement.Placed)?.filters
        } ?: return null
    return StoredGeneration(name, file, checkNotNull(crlite), placed)
}

/**
 * Load's steps 1 and 2 (spec §6.5) for the generation file [name]: [StoreRead.Absent] when no file has the key,
 * [StoreRead.Malformed] when it does not read (cap, re-hash, strict parse, dataset, channel, version) or its records do
 * not place. Prune's keep test and the adopt scan's candidate read.
 */
internal fun StoreLayout.stored(name: String): StoreRead<StoredGeneration> =
    when (val read = readGeneration(name)) {
        StoreRead.Absent -> StoreRead.Absent
        StoreRead.Malformed -> StoreRead.Malformed
        is StoreRead.Found -> place(name, read.value)?.let { StoreRead.Found(it) } ?: StoreRead.Malformed
    }

/** Load's step 3 without keeping the bytes: whether every blob [generation] names is stored and re-hashes. */
internal fun StoreLayout.blobsMatch(generation: StoredGeneration): Boolean =
    generation.placed.all { blob(generation.sha256(it)) == BlobState.MATCH }

/**
 * Load's steps 3 and 4 for [generation]: each placed filter's blob read and re-hashed against its record, then
 * `index.bin` rebuilt with [buildIndex] and the [GenerationFiles] built under the derived names; null when a blob is
 * missing or does not re-hash, a filter does not decode, or the index is refused.
 *
 * An install's load-back passes [index] and [format], which it built in step 2 from the same records and the same
 * bytes, re-hashed here, so the install decodes its filters once beside that build (spec §6.5: "keeping the `index.bin`
 * just built").
 */
internal fun StoreLayout.loadFiles(
    generation: StoredGeneration,
    index: ByteArray? = null,
    format: FilterFormat? = null,
): LoadedGeneration? {
    require((index == null) == (format == null)) { "the index and the format are given together" }
    val bodies = LinkedHashMap<String, ByteArray>()
    for (p in generation.placed) bodies[p.record.id] = readBlob(generation.sha256(p)) ?: return null
    val built =
        index
            ?: when (val build = buildIndex(generation.placed.map { it.record }, channel) { bodies.getValue(it.id) }) {
                is IndexBuild.Built -> build.index
                is IndexBuild.Refused -> return null
            }
    val full = generation.placed.first { it.full }
    val encoding =
        format ?: try {
            ClubcardFilters.encodingOf(bodies.getValue(full.record.id)).toFilterFormat()
        } catch (ignored: ClubcardFormatException) {
            return null
        }
    val files = LinkedHashMap<String, ByteArray>()
    files[StoreLayout.INDEX] = built
    for (p in generation.placed) files[p.name] = bodies.getValue(p.record.id)
    val image =
        try {
            GenerationFiles(generation.generationId, dataset, encoding, files, generation.timestampMillis)
        } catch (ignored: IllegalArgumentException) {
            return null
        }
    return LoadedGeneration(generation, image, encoding)
}

/**
 * Load (spec §6.5), steps 1 to 4, for the generation file [name]: one function for the `start()` recovery chain and the
 * adopt scan. A failure is the caller's to count, once.
 */
internal fun StoreLayout.load(name: String): GenerationLoad {
    val generation =
        when (val read = stored(name)) {
            StoreRead.Absent -> return GenerationLoad.Failed(true, "$name is absent")

            StoreRead.Malformed -> return GenerationLoad.Failed(
                false,
                "$name does not read or its records do not place",
            )

            is StoreRead.Found -> read.value
        }
    val loaded =
        loadFiles(generation) ?: return GenerationLoad.Failed(false, "a blob of $name is missing or does not decode")
    return GenerationLoad.Loaded(loaded)
}

/**
 * Prunes the store after the sync install of [installed] (spec §6.5 "Prune"), whose caller has checked that the pointer
 * read `Found` before the install, with every generation it named passing Load's steps 1 and 2, and that the flip did
 * not heal a malformed pointer ([InstallResult.Installed.prunable]).
 *
 * It keeps the generation files the pointer names, every generation file newer than its `live` that passes Load's steps
 * 1 and 2, and the blobs those files name, and deletes every other key under `generations/` and `blobs/`, generation
 * files first, so that while the deletes keep their order every generation file names only blobs on disk. It deletes
 * nothing unless the pointer reads back as [installed] with every generation it names passing steps 1 and 2: otherwise
 * [failed] (a store failure, never the caller's outcome) and a warning. A blob that does not re-hash is kept, since its
 * name is known (the next install rewrites it). A throw is a store failure too. Returns the keys deleted.
 *
 * Runs on the loader dispatcher only, as the last step of a sync install: never between an install's first write and its
 * flip, when its keys are named by nothing yet.
 */
@Suppress("TooGenericExceptionCaught", "ReturnCount") // §6.5: the loader catches every throwable; one return per rule.
internal fun StoreLayout.pruneAfter(
    installed: String,
    logger: RevoktLogger,
    failed: () -> Unit,
): Int {
    fun refuse(why: String): Int {
        failed()
        logger.safeLog(LogLevel.WARN, "$root: $why; not pruned")
        return 0
    }
    return try {
        val pointer = (pointer() as? StoreRead.Found)?.value ?: return refuse("the pointer does not read back")
        if (pointer.live != installed) return refuse("the pointer does not read back as $installed")
        val named = listOfNotNull(pointer.live, pointer.previous)
        val kept = LinkedHashMap<String, StoredGeneration>()
        for (n in named) kept[n] = (stored(n) as? StoreRead.Found)?.value ?: return refuse("$n does not read")
        val live = kept.getValue(pointer.live)
        // One listing: a name only a second listing showed would be deleted without its steps 1 and 2 read (#335 review).
        val listed = generationNames()
        for (n in listed - named.toSet()) {
            val newer = (stored(n) as? StoreRead.Found)?.value?.takeIf { it.timestampMillis > live.timestampMillis }
            if (newer != null) kept[n] = newer
        }
        val blobs = kept.values.flatMapTo(HashSet()) { it.blobNames }
        val doomedGenerations = listed - kept.keys
        val doomedBlobs = blobNames() - blobs
        doomedGenerations.forEach(::deleteGeneration)
        doomedBlobs.forEach(::deleteBlob)
        doomedGenerations.size + doomedBlobs.size
    } catch (t: Throwable) {
        restoreInterrupt(t)
        failed()
        logger.safeLog(LogLevel.WARN, "pruning $root failed", t)
        0
    }
}
