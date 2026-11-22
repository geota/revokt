// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.DiagnosticCode
import dev.revokt.LogLevel
import dev.revokt.PreparedGeneration
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLogger
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.walker.absorb
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import okio.ByteString

/**
 * A generation ready to install (spec §6.5): its [meta], its `index.bin` ([index]), its delta files' names, each with the
 * SHA-256 of its signed record ([deltas]), and its `records.json`. Its bodies are already written, one at
 * a time before the install: its full filters as blobs, and its delta files staged in its directory
 * ([StoreLayout.stageFile]) unless the directory is already complete, so no delta body is held until the install. [index]
 * was built by the loader ([buildIndex]).
 */
internal class PendingGeneration(
    val meta: GenerationMeta,
    index: ByteArray,
    val deltas: Map<String, ByteString>,
    records: ByteArray,
) {
    val index: ByteArray = index.copyOf()
    val records: ByteArray = records.copyOf()

    override fun toString(): String = "PendingGeneration(${meta.generationId} in ${meta.directory})"
}

/**
 * What an install publishes beside the generation's own fields (spec §4 `DataState`, §5.1): whether it is the seed and
 * the seed's `seedFormat`, the seed `STALE` gate ([DatasetGeneration.staleGateOpen]), and the clock reading
 * `updater.json` is written at. [pointerCounted] when the caller has already counted a malformed pointer and each
 * pointed `meta.json` that does not read (the seed load, which reads them first, #138), so the install's own read of
 * them for the new `previous` does not count them again: each store fault is counted once.
 * [heal] when the caller found no trustworthy pointer (rule (b) of the seed-load rule, lead 2026-11-16): a complete
 * directory of this generation's name is then held and installed as it stands when it is this generation, and one whose
 * `meta.json` is absent or does not read is this install's to complete, pointed or not, and never deleted by it on a
 * failure: the caller deletes only a directory it staged afresh.
 */
internal class Publication(
    val fromSeed: Boolean,
    val seedFormat: Int?,
    val staleGateOpen: Boolean,
    val nowMillis: Long,
    val pointerCounted: Boolean = false,
    val heal: Boolean = false,
) {
    init {
        require(fromSeed == (seedFormat != null)) { "seedFormat is set exactly for a seed" }
    }
}

/**
 * How an install ended: typed, so the sync (#137) maps it to `SyncOutcome`/`SyncStage` and the seed loader (#138) to
 * `SEED_UNREADABLE`. [storeFailures] is what the install adds to `storeFailures` (spec §6.5).
 */
internal sealed interface InstallResult {
    val storeFailures: Int

    /**
     * [generationId] is live in the engine, published at [generationEpoch], and named by the pointer as `live`. [healed]
     * is true when the pointer was malformed before this install, so the flip healed it: a heal is never pruned after,
     * since the damaged pointer may have named any directory (#256); the next install over a valid pointer prunes.
     */
    class Installed(
        val directory: String,
        val generationId: String,
        val generationEpoch: Long,
        override val storeFailures: Int,
        val healed: Boolean,
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
 * never offered to `prepare`) → write the generation directory, `meta.json` last → `engine.prepare`, the install's only
 * decode of the filters → `engine.activate` → publish the generation snapshot (`generationEpoch++`) → flip the pointer → write
 * [updater] when given.
 *
 * Nothing becomes live before every check passes. A failure before `activate` returns leaves the engine, [snapshot] and
 * the pointer untouched and deletes the directory this install wrote (its blobs stay, content-addressed); a `prepare`
 * or `activate` failure counts a store failure. A store write failure is `STORE_FAILED` at `STORE`. Every
 * throwable is caught, an `OutOfMemoryError` included, which is `FAILED` at the stage it hit with a store failure, so
 * nothing escapes the loader thread.
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

    /** The directory of the generation the engine held live when this install began, before its publish. */
    private var liveBefore: String? = null

    /** Whether the pointer was malformed when this install began, so its flip heals it ([InstallResult.Installed.healed]). */
    private var healing = false

    /** The directory this install wrote into, deleted on a failure before activation. */
    private var written: String? = null
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
            val storeWrite = stage == SyncStage.STORE && !isFatal(t)
            fail(if (storeWrite) SyncOutcome.STORE_FAILED else SyncOutcome.FAILED, null, t)
        }

    private fun steps(): InstallResult {
        stage = SyncStage.STORE
        val directory = meta.directory
        val (held, existing) = claim(directory)
        stage = SyncStage.INDEX
        if (generation.index.size > C2spIndex.MAX_BYTES) {
            // §3.2: a built index over the cap fails before the directory is written.
            return fail(SyncOutcome.FAILED, DiagnosticCode.INDEX_INCONSISTENT, null, counted = false)
        }
        stage = SyncStage.PREPARE
        if (meta.format !in engine.formats) {
            return fail(SyncOutcome.FAILED, DiagnosticCode.FORMAT_UNSUPPORTED, null, counted = false)
        }
        stage = SyncStage.STORE
        directory(directory, held, existing)?.let { return it }
        val files =
            store.readGeneration(directory)?.files
                ?: return fail(SyncOutcome.STORE_FAILED, null, IllegalStateException("$directory does not read back"))
        stage = SyncStage.PREPARE
        val p = engine.prepare(files).also { prepared = it }
        stage = SyncStage.ACTIVATE
        engine.activate(p)
        activated = true
        val epoch = publish()
        stage = SyncStage.STORE
        store.point(Pointer(directory, previous(directory)))
        updater?.let { store.writeUpdater(it, publication.nowMillis) }
        return InstallResult.Installed(directory, meta.generationId, epoch, storeFailures, healing)
    }

    /**
     * Whether [directory] is held and its `meta.json` as it reads. It is held when it is the engine's live generation or
     * one the pointer names, or when the pointer is malformed (it may name any directory) and [directory]'s `meta.json`
     * is present, complete or malformed (#236, fail closed). A directory nothing holds is this install's: it is
     * completed over its staged deltas, or deleted on a failure before activation. A complete one becomes this install's
     * only once [StoreLayout.reopen] accepts it. Under [Publication.heal] (the seed's rule (b), #138) it is held when it is
     * complete or is the engine's live generation: an incomplete one the engine does not serve is this install's, pointed
     * or not, a complete one is never reopened, and the live one is never rewritten whatever its `meta.json` says.
     */
    private fun claim(directory: String): Pair<Boolean, StoreRead<GenerationMeta>> {
        liveBefore = liveDirectory()
        val existing = store.readMeta(directory)
        // #236, fail closed: a malformed pointer may name a directory whose meta.json is present, so it is held: compared,
        // reused when it is this generation, never reopened, rewritten or deleted. The flip then writes a pointer that
        // reads. Only a directory with no meta.json is staged.
        healing = store.pointer() is StoreRead.Malformed
        val unknown = healing && existing !is StoreRead.Absent
        val held =
            if (publication.heal) {
                // The engine's live directory is held whatever its meta.json says: it is never rewritten while served.
                existing is StoreRead.Found || directory == liveDirectory()
            } else {
                directory == liveDirectory() || directory in pointed() || unknown
            }
        // Under heal the caller owns its directory's cleanup: it never deletes one it reopened (#235's review).
        if (!held && existing !is StoreRead.Found && !publication.heal) written = directory
        return held to existing
    }

    /**
     * Completes the generation directory, `meta.json` last, or returns the failure. [held] and [existing] were read at
     * the start of the install ([claim]).
     * - A held directory (live, pointed to, or beside a malformed pointer with its `meta.json` present) is never
     *   replaced. When it holds this generation ([sameGeneration]: left by an install that failed after the publish,
     *   the pointer's `previous` when an older changeset installs with no generation loaded, or the same `<ts>` served
     *   again beside a malformed pointer) it is prepared as it stands, its stored `meta.json` kept, so a retry can
     *   succeed. When it holds another
     *   generation, a stored delta that does not re-hash included (#201), or its `meta.json` is malformed (a newer
     *   binary's `metaVersion`, say, #178) or missing, it stays and fails the install, `STORE_FAILED`.
     * - Any other directory is referenced by nothing, complete or not (beside a malformed pointer, only one with no
     *   `meta.json`). It is completed again over its staged delta files ([StoreLayout.reopen], then
     *   [StoreLayout.completeGeneration], which deletes every other file of an earlier attempt, re-hashes each staged
     *   delta and writes this install's own `meta.json` with the signature it verified). A staged delta that is missing
     *   or does not re-hash fails the install, and the directory is deleted, so the next sync stages it afresh rather
     *   than failing on it at every sync (the #205 review).
     */
    private fun directory(
        directory: String,
        held: Boolean,
        existing: StoreRead<GenerationMeta>,
    ): InstallResult? {
        if (held) {
            if (existing is StoreRead.Found) {
                if (sameGeneration(existing.value, directory)) return null
                val cause = IllegalStateException("$directory holds another generation")
                return fail(SyncOutcome.STORE_FAILED, null, cause)
            }
            val cause = IllegalStateException("$directory is held, and its meta.json is not readable")
            return fail(SyncOutcome.STORE_FAILED, null, cause)
        }
        if (existing is StoreRead.Found) {
            // A complete orphan: only once reopen accepts it (never a pointed one) is it this install's to delete.
            store.reopen(directory)
            written = directory
        }
        store.completeGeneration(meta, generation.index, generation.deltas, generation.records)
        return null
    }

    /**
     * Whether [directory], whose `meta.json` is [stored], holds this generation: the same `meta.json` but for its
     * signed members (the signature that verified, and its leaf), byte-equal `index.bin` and `records.json`, and each
     * delta file re-hashing against its signed record (#201: a stored filter is re-hashed before it is reused, as Firefox's
     * `isFilterOnDisk` and upki's `Plan::construct` re-hash theirs; the full filters' blobs are re-hashed when the
     * directory is read). A collection re-signed under the same `<ts>` is the same signed records, so a retried flip over
     * it installs rather than failing every sync until the next `<ts>` (the maintainer's decision on #200; Firefox treats
     * an equal timestamp as up to date, `RemoteSettingsClient.sys.mjs:778` at `cac25a6`). Under [Publication.heal] the
     * `freshness` is not compared either: a seed and a sync of one `<ts>` are one generation (#138, the seed-load rule).
     */
    private fun sameGeneration(
        stored: GenerationMeta,
        directory: String,
    ): Boolean =
        stored.copy(signed = meta.signed, freshness = if (publication.heal) meta.freshness else stored.freshness) ==
            meta &&
            store.file(directory, StoreLayout.INDEX).contentEquals(generation.index) &&
            store.file(directory, StoreLayout.RECORDS).contentEquals(generation.records) &&
            generation.deltas.all { (name, sha256) -> store.file(directory, name, sha256) != null }

    /** The directory of the generation the engine holds live for this dataset, as the snapshot published it. */
    private fun liveDirectory(): String? {
        val live = snapshot.snapshot.datasets[meta.dataset] ?: return null
        val id = live.generationId ?: return null
        return live.sourceTimestampMillis?.let { GenerationNames.directory(it, id) }
    }

    /** The directories the pointer names; none when it is absent or malformed (counted by [previous]). */
    private fun pointed(): Set<String> =
        (store.pointer() as? StoreRead.Found)?.value?.let { setOfNotNull(it.live, it.previous) }.orEmpty()

    /**
     * Publishes the snapshot with this generation for its dataset, the engine's coverage end (null when the engine
     * cannot tell, or throws), and the next epoch, which it returns.
     */
    @Suppress("TooGenericExceptionCaught") // An injected engine's getter that throws means it cannot tell (§3.2).
    private fun publish(): Long {
        val current = snapshot.snapshot
        val installed =
            DatasetGeneration(
                generationId = meta.generationId,
                freshness = meta.freshness,
                fromSeed = publication.fromSeed,
                sourceTimestampMillis = meta.sourceTimestampMillis,
                seedFormat = publication.seedFormat,
                pending = false,
                staleGateOpen = publication.staleGateOpen,
            )
        val datasets = current.datasets + (meta.dataset to installed)
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
     * The pointer's new `previous`: the first of the generation the engine served before this install, then the old
     * `live` and `previous`, that is another complete generation that reads back ([qualifies], spec §6.5), else none.
     * The served one comes first so that a flip that failed after activation, which left the engine serving a
     * generation `current` does not name, never loses it to the next install's prune (#249: never delete what is
     * served); so a running loader keeps its fallback beside an absent or malformed pointer too (#236), while a fresh one
     * has none. A malformed pointer, and each candidate that does not qualify, count a store failure. A heal (the flip
     * beside a malformed pointer) is not pruned after (#256). A caller that read the pointer and its directories first
     * and counted their faults ([Publication.pointerCounted]) has them not counted again: the malformed pointer, and a
     * pointed candidate whose `meta.json` does not read.
     */
    private fun previous(directory: String): String? {
        val pointed =
            when (val read = store.pointer()) {
                StoreRead.Absent -> {
                    emptyList()
                }

                StoreRead.Malformed -> {
                    if (!publication.pointerCounted) storeFailures++
                    emptyList()
                }

                is StoreRead.Found -> {
                    listOfNotNull(read.value.live, read.value.previous)
                }
            }
        // Every candidate is read, once, so a pointed directory that does not read counts its store failure even when
        // an earlier candidate qualifies.
        val candidates = (listOfNotNull(liveBefore) + pointed).distinct().filter { it != directory }
        return candidates
            .filter { qualifies(it, callerCounted = publication.pointerCounted && it in pointed) }
            .firstOrNull()
    }

    /**
     * Whether [candidate] is a complete generation, as a `previous` must be. Complete is what loading it needs
     * ([StoreLayout.readGeneration]: `meta.json`, `index.bin`, `records.json`, every file it names, each blob
     * re-hashed), so the fallback is always one that can load (#246, the #247 review). One whose `meta.json` is missing
     * or malformed, or that does not read back, counts a store failure.
     */
    private fun qualifies(
        candidate: String,
        callerCounted: Boolean = false,
    ): Boolean {
        if (store.readMeta(candidate) !is StoreRead.Found) {
            // The seed loader counted a pointed directory whose meta.json does not read ([Publication.pointerCounted]).
            if (!callerCounted) storeFailures++
            return false
        }
        if (store.readGeneration(candidate) == null) {
            storeFailures++
            return false
        }
        return true
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
