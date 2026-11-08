// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.DiagnosticCode
import dev.revokt.GenerationFiles
import dev.revokt.LogLevel
import dev.revokt.PreparedGeneration
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLogger
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.clubcard.port.CrliteClubcard
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.walker.isFatal
import dev.revokt.safeLog
import okio.ByteString

/**
 * A generation ready to install (spec §6.5): its [meta], its `index.bin` ([index]), its delta files by name and, for
 * `SIGNED`, its `records.json`. Its full filters are already stored as blobs (fetched, verified and written one body at
 * a time before the install). [index] was built by the loader ([buildIndex]) for every trust class but `SYSTEM`, whose
 * index the loader reads from the system cache.
 */
internal class PendingGeneration(
    val meta: GenerationMeta,
    index: ByteArray,
    deltas: Map<String, ByteArray>,
    records: ByteArray?,
) {
    val index: ByteArray = index.copyOf()
    val deltas: Map<String, ByteArray> = deltas.mapValues { it.value.copyOf() }
    val records: ByteArray? = records?.copyOf()

    /** Whether the loader built [index], rather than read it. */
    val indexBuilt: Boolean get() = meta.trustClass != TrustClass.SYSTEM

    override fun toString(): String = "PendingGeneration(${meta.generationId} in ${meta.directory})"
}

/**
 * What an install publishes beside the generation's own fields (spec §4 `DataState`, §5.1): whether it is the seed and
 * the seed's `seedFormat`, the seed `STALE` gate ([DatasetGeneration.staleGateOpen]), and the clock reading and
 * `clockSkew` that `clockBehind` is recomputed from at the publish.
 */
internal class Publication(
    val fromSeed: Boolean,
    val seedFormat: Int?,
    val staleGateOpen: Boolean,
    val nowMillis: Long,
    val clockSkewMillis: Long,
) {
    init {
        require(fromSeed == (seedFormat != null)) { "seedFormat is set exactly for a seed" }
        require(clockSkewMillis >= 0) { "clockSkew is negative" }
    }
}

/**
 * How an install ended: typed, so the sync (#137) maps it to `SyncOutcome`/`SyncStage` and the seed loader (#138) to
 * `SEED_UNREADABLE`. [storeFailures] is what the install adds to `storeFailures` (spec §6.5).
 */
internal sealed interface InstallResult {
    val storeFailures: Int

    /** [generationId] is live in the engine, published at [generationEpoch], and named by the pointer as `live`. */
    class Installed(
        val directory: String,
        val generationId: String,
        val generationEpoch: Long,
        override val storeFailures: Int,
    ) : InstallResult {
        override fun toString(): String = "Installed($generationId in $directory at epoch $generationEpoch)"
    }

    /**
     * [outcome] is `FAILED` or `STORE_FAILED`, at [stage], with [code] when the spec names one. [activated] is true when
     * the failure came after `activate` returned: a store failure at the pointer flip or `updater.json` (`STORE_FAILED`
     * at `STORE`, the snapshot published), or a fatal error such as an `OutOfMemoryError` while publishing (`FAILED` at
     * `ACTIVATE`, the snapshot possibly not published). The engine then holds the new generation and its directory
     * stays. Otherwise the engine, the snapshot and the pointer are untouched, and any directory this install wrote is
     * deleted.
     */
    class Failed(
        val outcome: SyncOutcome,
        val stage: SyncStage,
        val code: DiagnosticCode?,
        val cause: Throwable?,
        val activated: Boolean,
        override val storeFailures: Int,
    ) : InstallResult {
        override fun toString(): String = "Failed($outcome at $stage, code=$code, activated=$activated, cause=$cause)"
    }
}

/**
 * Installs [generation] in spec §6.5's order: the `index.bin` cap → the format check (a format [engine] does not list is
 * never offered to `prepare`) → write the generation directory, `meta.json` last → for a `SYSTEM` generation the §3.2
 * consistency check → `engine.prepare` → the [SelfCheck] on the prepared state → `engine.activate` → publish the
 * generation snapshot (`generationEpoch++`) → flip the pointer → write [updater] when given.
 *
 * Nothing becomes live before every check passes. A failure before `activate` returns leaves the engine, [snapshot] and
 * the pointer untouched and deletes the directory this install wrote (its blobs stay, content-addressed); a `prepare`,
 * self-check or `activate` failure counts a store failure. A store write failure is `STORE_FAILED` at `STORE`. Every
 * throwable is caught, an `OutOfMemoryError` included, which is `FAILED` at the stage it hit with a store failure, so
 * nothing escapes the loader thread.
 *
 * The publish follows `activate`: a verdict in between carries the new answer under the old epoch, for at most the
 * verdict-cache TTL (§6.5). The loader runs this on its dispatcher, or the `start()` caller in the sole-seed path, never
 * two at once.
 */
internal fun install(
    generation: PendingGeneration,
    engine: RevocationEngine,
    store: StoreLayout,
    snapshot: SnapshotRef,
    publication: Publication,
    updater: UpdaterRecord?,
    logger: RevoktLogger,
): InstallResult = Install(generation, engine, store, snapshot, publication, updater, logger).run()

/** One install's steps, and what its failure path must undo. */
@OptIn(RevoktInternalApi::class)
private class Install(
    private val generation: PendingGeneration,
    private val engine: RevocationEngine,
    private val store: StoreLayout,
    private val snapshot: SnapshotRef,
    private val publication: Publication,
    private val updater: UpdaterRecord?,
    private val logger: RevoktLogger,
) {
    private val meta = generation.meta
    private var stage = SyncStage.INDEX
    private var storeFailures = 0

    /** The directory this install wrote into, deleted on a failure before activation. */
    private var written: String? = null
    private var prepared: PreparedGeneration? = null
    private var activated = false

    @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError included.
    fun run(): InstallResult =
        try {
            steps()
        } catch (t: Throwable) {
            val storeWrite = stage == SyncStage.STORE && !isFatal(t)
            fail(if (storeWrite) SyncOutcome.STORE_FAILED else SyncOutcome.FAILED, null, t)
        }

    private fun steps(): InstallResult {
        if (generation.index.size > C2spIndex.MAX_BYTES) {
            // §3.2: a built index over the cap fails before the directory is written; a read one is unreadable.
            val code = if (generation.indexBuilt) DiagnosticCode.INDEX_INCONSISTENT else DiagnosticCode.STORE_UNREADABLE
            return fail(SyncOutcome.FAILED, code, null, counted = false)
        }
        stage = SyncStage.PREPARE
        if (meta.format !in engine.formats) {
            return fail(SyncOutcome.FAILED, DiagnosticCode.FORMAT_UNSUPPORTED, null, counted = false)
        }
        stage = SyncStage.STORE
        val directory = meta.directory
        directory(directory)?.let { return it }
        val files =
            store.readGeneration(directory)?.files
                ?: return fail(SyncOutcome.STORE_FAILED, null, IllegalStateException("$directory does not read back"))
        stage = SyncStage.PREPARE
        val filters =
            try {
                decode(files)
            } catch (e: ClubcardFormatException) {
                return fail(SyncOutcome.FAILED, null, e)
            }
        val index = C2spIndex.read(files.bytes(StoreLayout.INDEX))
        // 0.3 (§3.2, §11, the system cache): a SYSTEM index.bin that does not parse is STORE_UNREADABLE; today it fails
        // writeGeneration above as STORE_FAILED, since no SYSTEM source exists in 0.2.
        if (!generation.indexBuilt) {
            stage = SyncStage.INDEX
            val mismatches = C2spIndex.inconsistencies(index, filters.mapValues { coverage(it.value) })
            if (mismatches.isNotEmpty()) {
                val cause = IllegalStateException("index.bin is inconsistent: $mismatches")
                return fail(SyncOutcome.FAILED, DiagnosticCode.STORE_UNREADABLE, cause, counted = false)
            }
            stage = SyncStage.PREPARE
        }
        val p = engine.prepare(files).also { prepared = it }
        stage = SyncStage.SELF_CHECK
        val check = SelfCheck.run(index, filters, { q -> probe(p, q) }, logger)
        if (check is SelfCheckResult.Mismatch) {
            val cause = IllegalStateException("engine self-check: $check")
            return fail(SyncOutcome.FAILED, DiagnosticCode.ENGINE_SELF_CHECK_FAILED, cause)
        }
        stage = SyncStage.ACTIVATE
        engine.activate(p)
        activated = true
        val epoch = publish()
        stage = SyncStage.STORE
        store.point(Pointer(directory, previous(directory)))
        updater?.let { store.writeUpdater(it, publication.nowMillis) }
        return InstallResult.Installed(directory, meta.generationId, epoch, storeFailures)
    }

    /**
     * Writes the generation directory, `meta.json` last, or returns the failure. A directory that already holds this
     * generation (the same `meta.json` and `index.bin`, left by an install that failed after writing it) is prepared as
     * it stands; one whose `meta.json` is malformed or missing is replaced whole, unless the engine holds it live; one
     * holding another generation stays and fails the install.
     */
    private fun directory(directory: String): InstallResult? {
        when (val existing = store.readMeta(directory)) {
            is StoreRead.Found -> {
                if (existing.value != meta || !store.index(directory).contentEquals(generation.index)) {
                    val cause = IllegalStateException("$directory holds another generation")
                    return fail(SyncOutcome.STORE_FAILED, null, cause)
                }
                // Already written, by an install that failed after it (a retry): prepare it as it stands. A failure
                // deletes it only when nothing else holds it.
                if (directory != liveDirectory() && directory !in pointed()) written = directory
            }

            StoreRead.Malformed, StoreRead.Absent -> {
                if (directory == liveDirectory()) {
                    val cause = IllegalStateException("$directory is the live generation's and its meta.json is not")
                    return fail(SyncOutcome.STORE_FAILED, null, cause)
                }
                // A malformed or incomplete directory is replaced whole, so no file of an earlier attempt stays.
                written = directory
                store.deleteGeneration(directory)
                store.writeGeneration(meta, generation.index, generation.deltas, generation.records)
            }
        }
        return null
    }

    /** The directory of the generation the engine holds live for this dataset, as the snapshot published it. */
    private fun liveDirectory(): String? {
        val live = snapshot.snapshot.datasets[meta.dataset] ?: return null
        val id = live.generationId ?: return null
        return live.sourceTimestampMillis?.let { GenerationNames.directory(it, id) }
    }

    /** The directories the pointer names; none when it is absent or malformed (counted by [previous]). */
    private fun pointed(): Set<String> =
        (store.pointer() as? StoreRead.Found)?.value?.let { setOfNotNull(it.live, it.previous) }.orEmpty()

    /** The loader's own decode of every filter, for the self-check's reference evaluator and coverage. */
    private fun decode(files: GenerationFiles): Map<String, CrliteClubcard> =
        files.names.filter { it != StoreLayout.INDEX }.associateWith { ClubcardFilters.decode(files.bytes(it)) }

    private fun coverage(filter: CrliteClubcard): Map<ByteString, Window> =
        filter.universe.logs.entries.associate { (log, interval) ->
            log.bytes to Window(interval.low.value.toULong(), interval.high.value.toULong())
        }

    /**
     * [p]'s answer to a self-check probe. A throw breaks `query`'s never-throws contract and fails the check as
     * [CrliteQueryResult.ENGINE_ERROR], which no probe expects; a fatal error is rethrown to [run].
     */
    @Suppress("TooGenericExceptionCaught") // §3.2: query never throws, so any throwable is the engine's error.
    private fun probe(
        p: PreparedGeneration,
        q: CrliteQuery,
    ): CrliteQueryResult =
        try {
            p.query(q)
        } catch (t: Throwable) {
            if (isFatal(t)) throw t
            CrliteQueryResult.ENGINE_ERROR
        }

    /**
     * Publishes the snapshot with this generation for its dataset, `clockBehind` recomputed for every dataset, the
     * engine's coverage end (null when the engine cannot tell, or throws), and the next epoch, which it returns.
     */
    @Suppress("TooGenericExceptionCaught") // An injected engine's getter that throws means it cannot tell (§3.2).
    private fun publish(): Long {
        val current = snapshot.snapshot
        val installed =
            DatasetGeneration(
                generationId = meta.generationId,
                trustClass = meta.trustClass,
                freshness = meta.freshness,
                fromSeed = publication.fromSeed,
                sourceTimestampMillis = meta.sourceTimestampMillis,
                seedFormat = publication.seedFormat,
                pending = false,
                staleGateOpen = publication.staleGateOpen,
                clockBehind = false,
            )
        val datasets =
            (current.datasets + (meta.dataset to installed)).mapValues { (_, d) ->
                d.copy(clockBehind = d.sourceTimestampMillis?.let(::clockBehind) ?: false)
            }
        val coverageEnd =
            try {
                engine.coverageEndMillis
            } catch (t: Throwable) {
                if (isFatal(t)) throw t
                null
            }
        val epoch = current.generationEpoch + 1
        snapshot.publish(GenerationSnapshot(epoch, datasets, coverageEnd))
        return epoch
    }

    /** §6.3: `sourceTimestampMillis > now + clockSkew`, at this publish. */
    private fun clockBehind(sourceTimestampMillis: Long): Boolean =
        sourceTimestampMillis - publication.clockSkewMillis > publication.nowMillis

    /**
     * The pointer's new `previous`: the first of the old `live` and `previous` that is another complete generation of
     * the same or a higher trust class (spec §6.5), else none. A malformed pointer, and a pointed directory whose
     * `meta.json` is missing or malformed, each count a store failure.
     */
    private fun previous(directory: String): String? {
        val pointer =
            when (val read = store.pointer()) {
                StoreRead.Absent -> {
                    return null
                }

                StoreRead.Malformed -> {
                    storeFailures++
                    return null
                }

                is StoreRead.Found -> {
                    read.value
                }
            }
        return listOfNotNull(pointer.live, pointer.previous).filter { it != directory }.firstOrNull { candidate ->
            when (val read = store.readMeta(candidate)) {
                is StoreRead.Found -> {
                    read.value.trustClass.rank >= meta.trustClass.rank
                }

                else -> {
                    storeFailures++
                    false
                }
            }
        }
    }

    /**
     * Ends the install as [outcome]: before activation, closes the prepared generation and deletes the directory this
     * install wrote. [counted] adds the store failure the stage's failure counts.
     */
    @Suppress("TooGenericExceptionCaught") // §6.5: the failure path catches every throwable too.
    private fun fail(
        outcome: SyncOutcome,
        code: DiagnosticCode?,
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
            written?.let {
                try {
                    store.deleteGeneration(it)
                } catch (t: Throwable) {
                    storeFailures++
                    logger.safeLog(LogLevel.WARN, "deleting $it failed", t)
                }
            }
        }
        return InstallResult.Failed(outcome, stage, code, cause, activated, storeFailures)
    }
}
