// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.LogLevel
import dev.revokt.PreparedGeneration
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLogger
import dev.revokt.SyncFailure
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.GenerationFile
import dev.revokt.engine.store.GenerationFileJson
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.walker.absorb
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog

/**
 * A generation ready to install (spec §6.5): its generation [file], its filters as placed ([placed], in `index.bin`
 * order), the `index.bin` built from them ([index], by [buildIndex]) and the full filter's [format]. Its bodies are
 * already stored, one at a time before the install, each as the blob of its signed SHA-256, so no body is held until the
 * install.
 */
@OptIn(RevoktInternalApi::class)
internal class PendingGeneration(
    val file: GenerationFile,
    val placed: List<PlacedFilter>,
    index: ByteArray,
    val format: FilterFormat,
) {
    val index: ByteArray = index.copyOf()

    /** `"<ts>/<last placed record id>"`, as a load derives it (spec §4 `DataState.generationId`). */
    val generationId: String = "${file.lastModified}/${placed.last().record.id}"

    override fun toString(): String = "PendingGeneration($generationId)"
}

/**
 * What an install publishes beside the generation's own fields (spec §4 `DataState`, §5.1): whether it is the seed and
 * the seed's `seedFormat`, the seed `STALE` gate ([DatasetGeneration.staleGateOpen]), and the clock reading
 * `updater.json` is written at. [pointerCounted] when the caller has already counted a malformed pointer and each
 * pointed generation that fails Load's steps 1 and 2 (the seed load, which reads them first, #138), so the install's
 * own read of them does not count them again: each store fault is counted once. [counted] names the generation files
 * whose failure the caller has counted (the sync's served file, the seed load's rejected candidates), so neither the
 * install's read of the pointer's generations nor a `previous` candidate counts them again.
 */
internal class Publication(
    val fromSeed: Boolean,
    val seedFormat: Int?,
    val staleGateOpen: Boolean,
    val nowMillis: Long,
    val pointerCounted: Boolean = false,
    val counted: Set<String> = emptySet(),
) {
    init {
        require(fromSeed == (seedFormat != null)) { "seedFormat is set exactly for a seed" }
    }
}

/**
 * How an install ended: typed, so the sync (#137) ends with its [SyncFailure] and the seed loader (#138) maps it to
 * `SEED_UNREADABLE`. [storeFailures] is what the install adds to `storeFailures` (spec §6.5).
 */
internal sealed interface InstallResult {
    val storeFailures: Int

    /**
     * [generationId] is live in the engine, published at [generationEpoch], and named by the pointer as `live`, the
     * generation file [name]. [healed] when the pointer was malformed before this install, so the flip healed it.
     * [prunable] when the pointer read `Found` before the install with every generation it named passing Load's steps 1
     * and 2, which a heal never does: only then may a sync prune after it (spec §6.5 "Prune", #256).
     */
    class Installed(
        val name: String,
        val generationId: String,
        val generationEpoch: Long,
        override val storeFailures: Int,
        val healed: Boolean,
        val prunable: Boolean,
    ) : InstallResult {
        override fun toString(): String = "Installed($generationId in $name at epoch $generationEpoch)"
    }

    /**
     * The install failed with [failure]. [activated] is true when the failure came after `activate` returned: a store
     * failure at the pointer flip or `updater.json` (`STORE_FAILED`, the snapshot published), or a fatal error such as
     * an `OutOfMemoryError` while publishing (`INTERNAL_ERROR`, the snapshot possibly not published). The engine then
     * holds the new generation. Otherwise the engine, the snapshot and the pointer are untouched. A failed install
     * deletes nothing either way: its blobs and generation file are named by no pointer, and the next attempt reuses them.
     */
    class Failed(
        val failure: SyncFailure,
        val cause: Throwable?,
        val activated: Boolean,
        override val storeFailures: Int,
    ) : InstallResult {
        override fun toString(): String = "Failed($failure, activated=$activated, cause=$cause)"
    }
}

/**
 * Installs [generation] in spec §6.5's order, its bodies already stored: the `index.bin` cap → the format check (a
 * format [engine] does not list is never offered to `prepare`) → the generation file's cap, then its write (not again
 * when stored and re-hashing) → the load-back (the file re-read, re-hashed and placed, every blob re-hashed, with the
 * index just built) → `engine.prepare`, the install's only decode of the filters → `engine.activate` → publish the
 * generation snapshot (`generationEpoch++`) → flip the pointer → write [updater] when given.
 *
 * Nothing becomes live before every check passes, and nothing is ever deleted: a failure before `activate` returns
 * leaves the engine, [snapshot] and the pointer untouched. A `prepare` or `activate` failure, and every store failure,
 * counts a store failure. A store write failure is `STORE_FAILED`, a `prepare` or `activate` throw `ENGINE_FAILED`. Every
 * throwable is caught, an `OutOfMemoryError` included, which is `ENGINE_FAILED` in the engine's steps and
 * `INTERNAL_ERROR` elsewhere, so nothing escapes the loader thread.
 *
 * The publish follows `activate`: a verdict in between carries the new answer under the old epoch, for at most the
 * verdict-cache TTL (§6.5). The loader runs this on its dispatcher, or the `start()` caller in the sole-seed path, never
 * two at once.
 */
@OptIn(RevoktInternalApi::class)
internal fun install(
    generation: PendingGeneration,
    engine: RevocationEngine,
    store: StoreLayout,
    snapshot: SnapshotRef,
    publication: Publication,
    updater: UpdaterRecord?,
    logger: RevoktLogger,
): InstallResult = Install(generation, engine, store, snapshot, publication, updater, logger).run()

/** The name of the generation file the engine serves for [dataset], as the snapshot published it, or null. */
internal fun SnapshotRef.servedFile(dataset: Dataset = Dataset.CRLITE): String? =
    snapshot.datasets[dataset]?.takeIf { it.generationId != null }?.generationFile

/**
 * The re-flip of spec §6.5: the sync's verified `<ts>` is the served generation's (`UNCHANGED`) while `current` does not
 * name it as `live`, and its file and blobs pass Load's steps 1 to 3 ([served]). `current` is flipped to `{live:
 * served, previous: per the candidate rule}` and [updater] written, with no fetch, no `prepare` and no publish: the
 * engine already serves it. It is a heal flip, never pruned after ([InstallResult.Installed.prunable] is false). A store
 * failure is `STORE_FAILED`, counted.
 */
@OptIn(RevoktInternalApi::class)
internal fun reflip(
    served: StoredGeneration,
    store: StoreLayout,
    snapshot: SnapshotRef,
    publication: Publication,
    updater: UpdaterRecord?,
): InstallResult = Reflip(served, store, snapshot, publication, updater).run()

/**
 * What an install and a re-flip share: the pointer as it read before anything was written, the generations it named
 * through Load's steps 1 and 2, and the `previous` candidate rule over them (spec §6.5), each fault counted once.
 */
private open class PointerFlip(
    protected val store: StoreLayout,
    protected val snapshot: SnapshotRef,
    protected val publication: Publication,
) {
    protected var storeFailures = 0

    /** The generation file the engine served when this flip began, before any publish. */
    protected val servedBefore: String? = snapshot.servedFile(store.dataset)

    /** The pointer as it read when this flip began. */
    protected var pointerBefore: StoreRead<Pointer> = StoreRead.Absent

    /** Each generation the pointer named when this flip began, through Load's steps 1 and 2. */
    protected val pointedBefore = LinkedHashMap<String, StoreRead<StoredGeneration>>()

    /**
     * Reads the pointer and, when it reads, each generation it names through Load's steps 1 and 2, once, before anything
     * is written: whether a sync may prune after this install (spec §6.5 "Prune") and the `previous` candidates. A
     * malformed pointer and each named generation that does not read count a store failure, unless the caller counted
     * them ([Publication.pointerCounted], [Publication.counted]).
     */
    protected fun readBefore() {
        pointerBefore = store.pointer()
        val read = pointerBefore
        if (read is StoreRead.Malformed && !publication.pointerCounted) storeFailures++
        if (read !is StoreRead.Found) return
        for (n in listOfNotNull(read.value.live, read.value.previous)) {
            val stored = store.stored(n)
            pointedBefore[n] = stored
            if (stored !is StoreRead.Found && !publication.pointerCounted && n !in publication.counted) storeFailures++
        }
    }

    /**
     * The pointer's new `previous`: the first of the generation the engine served before this install, then the old
     * `live` and `previous`, that is another generation passing Load's steps 1 to 3 ([qualifies], spec §6.5), else none.
     * The served one comes first so that a flip that failed after activation, which left the engine serving a
     * generation `current` does not name, never loses it to the next prune (#249: never delete what is served); so a
     * running loader keeps its fallback beside an absent or malformed pointer too (#236), while a fresh one has none.
     * Every candidate is read once, so each that does not qualify counts its store failure, even when an earlier one
     * qualifies; a pointed one already counted by [readBefore] is not counted again.
     */
    protected fun previous(name: String): String? {
        val pointed = pointedBefore.keys.toList()
        val candidates = (listOfNotNull(servedBefore) + pointed).distinct().filter { it != name }
        return candidates.filter(::qualifies).firstOrNull()
    }

    /**
     * Whether [candidate] passes Load's steps 1 to 3, as a `previous` must, so the fallback always loads (#246, the #247
     * review): its file reads, re-hashes and places, and every blob it names re-hashes. Step 4 rebuilds the index from
     * those same bytes, which an earlier install already decoded. One that does not counts a store failure.
     */
    private fun qualifies(candidate: String): Boolean {
        val read = pointedBefore[candidate]
        val stored = (read ?: store.stored(candidate)) as? StoreRead.Found
        if (stored == null) {
            // A pointed one that does not read was counted by readBefore (or by the caller).
            if (read == null && candidate !in publication.counted) storeFailures++
            return false
        }
        if (!store.blobsMatch(stored.value)) {
            if (candidate !in publication.counted) storeFailures++
            return false
        }
        return true
    }
}

/** One re-flip ([reflip]). */
@OptIn(RevoktInternalApi::class)
private class Reflip(
    private val served: StoredGeneration,
    store: StoreLayout,
    snapshot: SnapshotRef,
    publication: Publication,
    private val updater: UpdaterRecord?,
) : PointerFlip(store, snapshot, publication) {
    @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError included.
    fun run(): InstallResult =
        try {
            readBefore()
            store.point(Pointer(served.name, previous(served.name)))
            updater?.let { store.writeUpdater(it, publication.nowMillis) }
            InstallResult.Installed(
                served.name,
                served.generationId,
                snapshot.snapshot.generationEpoch,
                storeFailures,
                healed = pointerBefore is StoreRead.Malformed,
                prunable = false,
            )
        } catch (t: Throwable) {
            restoreInterrupt(t)
            storeFailures++
            val failure = if (isFatal(t)) SyncFailure.INTERNAL_ERROR else SyncFailure.STORE_FAILED
            InstallResult.Failed(failure, t, activated = true, storeFailures = storeFailures)
        }
}

/** One install's steps. */
@OptIn(RevoktInternalApi::class)
private class Install(
    private val generation: PendingGeneration,
    private val engine: RevocationEngine,
    store: StoreLayout,
    snapshot: SnapshotRef,
    publication: Publication,
    private val updater: UpdaterRecord?,
    private val logger: RevoktLogger,
) : PointerFlip(store, snapshot, publication) {
    private val file = generation.file

    /**
     * What a throw here fails the install with: `STORE_FAILED` (a non-fatal one), `ENGINE_FAILED` or `INTERNAL_ERROR`.
     */
    private var step = SyncFailure.INTERNAL_ERROR
    private var prepared: PreparedGeneration? = null
    private var activated = false

    @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError included.
    fun run(): InstallResult =
        try {
            steps()
        } catch (t: Throwable) {
            // An injected engine's prepare or activate may have cleared the interrupt flag; a fatal error is FAILED
            // here, never rethrown, since nothing escapes the loader (§6.5).
            restoreInterrupt(t)
            fail(if (step == SyncFailure.STORE_FAILED && isFatal(t)) SyncFailure.INTERNAL_ERROR else step, t)
        }

    private fun steps(): InstallResult {
        step = SyncFailure.STORE_FAILED
        readBefore()
        step = SyncFailure.INTERNAL_ERROR
        if (generation.index.size > C2spIndex.MAX_BYTES) {
            // §3.2: a built index over the cap fails before the generation file is written.
            return fail(SyncFailure.INDEX_INCONSISTENT, null, counted = false)
        }
        if (generation.format !in engine.formats) return fail(SyncFailure.FORMAT_UNSUPPORTED, null, counted = false)
        val bytes = GenerationFileJson.write(file, store.generationCap)
        if (bytes == null) {
            // §6.5: never write a file this install's own load-back, or a later load, would refuse.
            val detail = "the generation file is over maxJsonBytes (${store.maxJsonBytes}) + 64 KiB"
            logger.safeLog(LogLevel.WARN, "${store.root}: $detail; raise maxJsonBytes to install it")
            return fail(SyncFailure.STORE_FAILED, IllegalStateException(detail))
        }
        step = SyncFailure.STORE_FAILED
        val name = store.putGeneration(bytes)
        val files =
            loadBack(name) ?: return fail(SyncFailure.STORE_FAILED, IllegalStateException("$name does not load back"))
        step = SyncFailure.ENGINE_FAILED
        val p = engine.prepare(files.files).also { prepared = it }
        engine.activate(p)
        activated = true
        step = SyncFailure.INTERNAL_ERROR
        val epoch = publish(name)
        step = SyncFailure.STORE_FAILED
        store.point(Pointer(name, previous(name)))
        updater?.let { store.writeUpdater(it, publication.nowMillis) }
        val healed = pointerBefore is StoreRead.Malformed
        val prunable = pointerBefore is StoreRead.Found && pointedBefore.values.all { it is StoreRead.Found }
        return InstallResult.Installed(name, generation.generationId, epoch, storeFailures, healed, prunable)
    }

    /**
     * The generation file [name] loaded back as `start()` would load it, but with the index this install built in step 2
     * from the same records and bytes (spec §6.5): re-read, re-hashed against its name, its records placed, every blob
     * re-hashed. Null when it does not read back as this generation.
     */
    private fun loadBack(name: String): LoadedGeneration? {
        val stored = (store.stored(name) as? StoreRead.Found)?.value ?: return null
        if (stored.generationId != generation.generationId) return null
        return store.loadFiles(stored, generation.index, generation.format)
    }

    /**
     * Publishes the snapshot with this generation for its dataset, under its file [name], the engine's coverage end (null
     * when the engine cannot tell, or throws), and the next epoch, which it returns.
     */
    @Suppress("TooGenericExceptionCaught") // An injected engine's getter that throws means it cannot tell (§3.2).
    private fun publish(name: String): Long {
        val current = snapshot.snapshot
        val installed =
            DatasetGeneration(
                generationId = generation.generationId,
                freshness = file.freshness,
                fromSeed = publication.fromSeed,
                sourceTimestampMillis = file.lastModified,
                seedFormat = publication.seedFormat,
                pending = false,
                staleGateOpen = publication.staleGateOpen,
                generationFile = name,
            )
        val datasets = current.datasets + (file.dataset to installed)
        val coverageEnd =
            try {
                engine.coverageEndMillis
            } catch (t: Throwable) {
                absorb(t)
                null
            }
        val epoch = current.generationEpoch + 1
        snapshot.publish(GenerationSnapshot(epoch, datasets, coverageEnd))
        return epoch
    }

    /**
     * Ends the install as [failure]: before activation, closes the prepared generation. Nothing is deleted. [counted]
     * adds the store failure the step's failure counts.
     */
    @Suppress("TooGenericExceptionCaught") // §6.5: the failure path catches every throwable too.
    private fun fail(
        failure: SyncFailure,
        cause: Throwable?,
        counted: Boolean = true,
    ): InstallResult {
        if (counted) storeFailures++
        if (!activated) {
            try {
                prepared?.close()
            } catch (t: Throwable) {
                logger.safeLog(LogLevel.WARN, "closing an unactivated generation failed", t)
            }
        }
        return InstallResult.Failed(failure, cause, activated, storeFailures)
    }
}
