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
import dev.revokt.engine.walker.absorb
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import okio.ByteString

/**
 * A generation ready to install (spec §6.5): its [meta], its `index.bin` ([index]), its delta files' names, each with the
 * SHA-256 of its signed record ([deltas]), and, for `SIGNED`, its `records.json`. Its bodies are already written, one at
 * a time before the install: its full filters as blobs, and its delta files staged in its directory
 * ([StoreLayout.stageFile]) unless the directory is already complete, so no delta body is held until the install. [index]
 * was built by the loader ([buildIndex]) for every trust class but `SYSTEM`, whose index the loader reads from the system
 * cache.
 */
internal class PendingGeneration(
    val meta: GenerationMeta,
    index: ByteArray,
    val deltas: Map<String, ByteString>,
    records: ByteArray?,
) {
    val index: ByteArray = index.copyOf()
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
            // §3.2: a built index over the cap fails before the directory is written; a read one is unreadable.
            val code = if (generation.indexBuilt) DiagnosticCode.INDEX_INCONSISTENT else DiagnosticCode.STORE_UNREADABLE
            return fail(SyncOutcome.FAILED, code, null, counted = false)
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
        val epoch = publish(maxCoverageMillis(index))
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
     * only once [StoreLayout.reopen] accepts it.
     */
    private fun claim(directory: String): Pair<Boolean, StoreRead<GenerationMeta>> {
        liveBefore = liveDirectory()
        val existing = store.readMeta(directory)
        // #236, fail closed: a malformed pointer may name a directory whose meta.json is present, so it is held: compared,
        // reused when it is this generation, never reopened, rewritten or deleted. The flip then writes a pointer that
        // reads. Only a directory with no meta.json is staged.
        healing = store.pointer() is StoreRead.Malformed
        val unknown = healing && existing !is StoreRead.Absent
        val held = directory == liveDirectory() || directory in pointed() || unknown
        if (!held && existing !is StoreRead.Found) written = directory
        return held to existing
    }

    /**
     * Completes the generation directory, `meta.json` last, or returns the failure. [held] and [existing] were read at
     * the start of the install ([claim]).
     * - A held directory (live, pointed to, or beside a malformed pointer with its `meta.json` present) is never
     *   replaced. When it holds this generation ([sameGeneration]: left by an install that failed after the publish,
     *   the pointer's `previous` on a rollback inside the window, or the same `<ts>` served again beside a malformed
     *   pointer) it is prepared as it stands, its stored `meta.json` kept, so a retry can succeed. When it holds another
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
     * `SIGNED` members (the signature that verified, and its leaf), byte-equal `index.bin` and `records.json`, and each
     * delta file re-hashing against its signed record (#201: a stored filter is re-hashed before it is reused, as Firefox's
     * `isFilterOnDisk` and upki's `Plan::construct` re-hash theirs; the full filters' blobs are re-hashed when the
     * directory is read). A collection re-signed under the same `<ts>` is the same signed records, so a retried flip over
     * it installs rather than failing every sync until the next `<ts>` (the maintainer's decision on #200; Firefox treats
     * an equal timestamp as up to date, `RemoteSettingsClient.sys.mjs:778` at `cac25a6`).
     */
    private fun sameGeneration(
        stored: GenerationMeta,
        directory: String,
    ): Boolean =
        // Same trust class first, so the copy keeps "signed members iff SIGNED".
        stored.trustClass == meta.trustClass &&
            stored.copy(signed = meta.signed) == meta &&
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

    /** The loader's own decode of every filter, for the self-check's reference evaluator and coverage. */
    private fun decode(files: GenerationFiles): Map<String, CrliteClubcard> =
        files.names.filter { it != StoreLayout.INDEX }.associateWith { ClubcardFilters.decode(files.bytes(it)) }

    private fun coverage(filter: CrliteClubcard): Map<ByteString, Window> =
        filter.universe.logs.entries.associate { (log, interval) ->
            log.bytes to Window(interval.low.value.toULong(), interval.high.value.toULong())
        }

    /**
     * [p]'s answer to a self-check probe. A throw breaks `query`'s never-throws contract and fails the check as
     * [CrliteQueryResult.ENGINE_ERROR], which no probe expects; a fatal error is rethrown to [run], and an interrupt is
     * kept.
     */
    @Suppress("TooGenericExceptionCaught") // §3.2: query never throws, so any throwable is the engine's error.
    private fun probe(
        p: PreparedGeneration,
        q: CrliteQuery,
    ): CrliteQueryResult =
        try {
            p.query(q)
        } catch (t: Throwable) {
            absorb(t)
            CrliteQueryResult.ENGINE_ERROR
        }

    /**
     * Publishes the snapshot with this generation for its dataset, carrying [maxCoverage], the maximum coverage the
     * loader decoded from its `index.bin`; `clockBehind` recomputed for every dataset, the engine's coverage end (null
     * when the engine cannot tell, or throws), and the next epoch, which it returns.
     */
    @Suppress("TooGenericExceptionCaught") // An injected engine's getter that throws means it cannot tell (§3.2).
    private fun publish(maxCoverage: Long?): Long {
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
                maxCoverageMillis = maxCoverage,
            )
        val datasets =
            (current.datasets + (meta.dataset to installed)).mapValues { (_, d) ->
                d.copy(clockBehind = d.sourceTimestampMillis?.let(::clockBehind) ?: false)
            }
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

    /** §6.3: `sourceTimestampMillis > now + clockSkew`, at this publish. */
    private fun clockBehind(sourceTimestampMillis: Long): Boolean =
        sourceTimestampMillis - publication.clockSkewMillis > publication.nowMillis

    /**
     * The pointer's new `previous`: the first of the generation the engine served before this install, then the old
     * `live` and `previous`, that is another complete generation of the same or a higher trust class and reads back
     * ([qualifies], spec §6.5), else none. The served one comes first so that a flip that failed after activation, which left the engine serving a
     * generation `current` does not name, never loses it to the next install's prune (#249: never delete what is served);
     * so a running loader keeps its fallback beside an absent or malformed pointer too (#236), while a fresh one has none.
     * A malformed pointer, and each candidate that does not qualify for a reason other than its class, count a store
     * failure. A heal (the flip beside a malformed pointer) is not pruned after (#256).
     */
    private fun previous(directory: String): String? {
        val pointed =
            when (val read = store.pointer()) {
                StoreRead.Absent -> {
                    emptyList()
                }

                StoreRead.Malformed -> {
                    storeFailures++
                    emptyList()
                }

                is StoreRead.Found -> {
                    listOfNotNull(read.value.live, read.value.previous)
                }
            }
        // Every candidate is read, once, so a pointed directory that does not read counts its store failure even when
        // an earlier candidate qualifies.
        val candidates = (listOfNotNull(liveBefore) + pointed).distinct().filter { it != directory }
        return candidates.filter(::qualifies).firstOrNull()
    }

    /**
     * Whether [candidate] is a complete generation of the same or a higher trust class, as a `previous` must be.
     * Complete is what loading it needs ([StoreLayout.readGeneration]: `meta.json`, `index.bin`, `records.json` for a
     * `SIGNED` one, every file it names, each blob re-hashed), so the fallback is always one that can load (#246, the
     * #247 review). One whose `meta.json` is missing or malformed, or that does not read back, counts a store failure.
     */
    private fun qualifies(candidate: String): Boolean {
        val stored = store.readMeta(candidate)
        if (stored !is StoreRead.Found) {
            storeFailures++
            return false
        }
        if (stored.value.trustClass.rank < meta.trustClass.rank) return false
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
