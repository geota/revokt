// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.DiagnosticCode.INDEX_INCONSISTENT
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.LogLevel
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktTestingApi
import dev.revokt.Severity
import dev.revokt.SyncOutcome
import dev.revokt.SyncResult
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.clubcard.port.Encoding
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import dev.revokt.engine.fetch.C2spManifest
import dev.revokt.engine.fetch.C2spMirrorClient
import dev.revokt.engine.fetch.ClientResult
import dev.revokt.engine.fetch.ManifestCheck
import dev.revokt.engine.fetch.ManifestNames
import dev.revokt.engine.fetch.ManifestRead
import dev.revokt.engine.fetch.MirrorFile
import dev.revokt.engine.store.BlobState
import dev.revokt.engine.store.BlobWrite
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import okio.ByteString

/**
 * The C2SP mirror loader of spec §7.3 for one mirror source, the `CRLITE` dataset and one channel (the `MIRROR` trust
 * class): [syncOnce] fetches the mirror's `manifest.json`, checks it, fetches its files and installs them as one
 * `MIRROR` generation whose `index.bin` it builds itself (revision 53; a mirror's `index.bin` is never fetched). The
 * schedule and the order of sources are the loader's (#147): "a lower-class source is fetched only after every
 * higher-class source failed in this sync and the bootstrap condition holds" ([bootstrapHolds]).
 *
 * [client] is the source's client, [store] the dataset and channel's layout, [snapshot] the published snapshot this
 * sync reads the live generation from and publishes to, and [clockSkewMillis] the policy's `clockSkew` (§4). The
 * dataset's `minTrustClass` while `UNSIGNED_DATA` rejects is the caller's check before it runs a mirror at all.
 */
internal class MirrorSync(
    private val client: C2spMirrorClient,
    private val store: StoreLayout,
    private val engine: RevocationEngine,
    private val snapshot: SnapshotRef,
    private val clockSkewMillis: Long,
    private val logger: RevoktLogger,
) {
    init {
        require(store.dataset == Dataset.CRLITE) { "the mirror loader syncs CRLITE, not ${store.dataset}" }
        require(clockSkewMillis >= 0) { "clockSkew is negative" }
    }

    /**
     * §7.3 "Bootstrap only": whether the dataset has no generation of a higher trust class than `MIRROR` at all, neither
     * live in [snapshot] (a seed, or a `SIGNED` generation) nor stored, so a mirror may install. A `SYSTEM` or an earlier
     * `MIRROR` generation does not stop it. It fails closed whenever the store cannot tell, since the prune after a
     * mirror install would delete a `SIGNED` generation it did not see (#207's review):
     * - a malformed `current` pointer;
     * - a directory the pointer names, `live` or `previous`, whose `meta.json` is absent or malformed;
     * - any generation directory under the dataset and channel whose `meta.json` is of a higher class, or malformed (its
     *   class unknown); a directory without one is an interrupted install, which says nothing.
     *
     * Reads the store, which may throw.
     */
    fun bootstrapHolds(): Boolean {
        val live = snapshot.snapshot.datasets[Dataset.CRLITE]?.trustClass
        if (live != null && live.rank > TrustClass.MIRROR.rank) return false
        val pointed =
            when (val read = store.pointer()) {
                StoreRead.Absent -> emptyList()
                StoreRead.Malformed -> return false
                is StoreRead.Found -> listOfNotNull(read.value.live, read.value.previous)
            }
        // A pointed directory is under the root, so the scan below reads its class; here only its meta.json must read.
        if (pointed.any { store.readMeta(it) !is StoreRead.Found }) return false
        return store.directories.none { directory ->
            when (val read = store.readMeta(directory)) {
                StoreRead.Absent -> false
                StoreRead.Malformed -> true
                is StoreRead.Found -> higher(read.value.trustClass)
            }
        }
    }

    private fun higher(trustClass: TrustClass): Boolean = trustClass.rank > TrustClass.MIRROR.rank

    /**
     * One sync at [nowMillis], the loader's one clock read for it (spec §6.3, §6.5, §7.3):
     * 1. Unless [bootstrapHolds], the sync does not run: nothing is fetched or written and the result is null, which the
     *    loader never publishes (the maintainer's decision on #207, Q1: a mirror is bootstrap-only, and the loader never
     *    runs one then, so this is a guard, not an outcome). Under the source's persisted backoff → `BACKOFF`.
     * 2. `GET <base>manifest.json`, with `If-Modified-Since` the time the live `MIRROR` generation's manifest was stored
     *    (its `meta.json`), none without a live `MIRROR` generation; a 304 to it is `UNCHANGED`. Redirects are the
     *    client's ([C2spMirrorClient]); any other failure is `FAILED` at `CHANGESET`, as is a body that is not a
     *    manifest ([C2spManifest.parse]).
     * 3. More than `MAX_MANIFEST_ENTRIES` entries is `FAILED` at `CHANGESET` before any body fetch. A manifest body above
     *    half of `MAX_JSON_BYTES`, more than half of `MAX_MANIFEST_ENTRIES` (128) entries, and (step 6) a file declared
     *    above half of `MAX_FILTER_BYTES` are each a `CAP_NEAR_LIMIT` warning, once per item, on whatever result the sync
     *    ends with (§4: "a body, record count or manifest above half the `RevoktLimits` constant, not the overridden
     *    value"), and the sync goes on. A fetched file is its declared size, so its declared size is the one checked.
     * 4. The names and hashes ([ManifestNames]): any failure is `FAILED` with `INDEX_INCONSISTENT` at `INDEX`; no files is
     *    `FAILED` with `SOURCE_EMPTY` at `INDEX` (revision 56, Q24). Both before any body is fetched or written.
     * 5. The manifest's SHA-256 is the generation id (§4 `DataState.generationId`): the live generation's, pointed to,
     *    is `UNCHANGED`.
     * 6. A file declaring more than `MAX_FILTER_BYTES` is `FAILED` with `CAP_NEAR_LIMIT` at `ATTACHMENT`, nothing
     *    fetched. Then each file, one at a time: reused without a fetch when its blob is stored and re-hashes,
     *    otherwise fetched, checked against its manifest size and hash, and written as its blob (`blobs/<sha256>`).
     * 7. The index is built locally ([buildMirrorIndex]): a filter that does not decode is `FAILED` at `PREPARE`, an
     *    index over 1 MiB `FAILED` with `INDEX_INCONSISTENT` at `INDEX`; every filter's coverage empty is `FAILED` with
     *    `SOURCE_EMPTY` at `INDEX`.
     * 8. Freshness (§6.3, §7.2): `sourceTimestampMillis` is the newest coverage end (`MANIFEST_LAST_MODIFIED`); a
     *    coverage end beyond now + `clockSkew` is `FAILED` at `INDEX`, while one within it installs, its age 0 and not
     *    `clockBehind`.
     * 9. The format check over every filter (`FORMAT_UNSUPPORTED` at `PREPARE`), then [install] in §6.5's order and,
     *    after `INSTALLED`, the prune. The watermark, the cursor and `lastVerified*` are never read or written (§6.3).
     *
     * Every throwable is caught, an `OutOfMemoryError` included, and is `FAILED` at the stage it hit (§6.5).
     */
    fun syncOnce(nowMillis: Long): SyncRun? = Attempt(nowMillis).run()

    /** One sync's state: what it read, what it fetched and what the failure path writes. */
    @OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
    private inner class Attempt(
        private val now: Long,
    ) {
        private val source = client.source
        private val clock = SyncClock(now, clockSkewMillis, 0)
        private var stage = SyncStage.STORE

        /**
         * The `updater.json` this sync read, set once the record is read and the bootstrap check has passed; while it is
         * null nothing writes `updater.json`, so a store that throws during the check never has an unread record written
         * over it (#207's follow-up review).
         */
        private var record: UpdaterRecord? = null
        private var storeFailures = 0
        private var lastStatus: Int? = null

        /** The `CAP_NEAR_LIMIT` warnings of this sync (§4), on whatever result it ends with. */
        private val notes = ArrayList<PolicyDiagnostic>()

        /** Set once the first body fetch starts: from there on the sync is an *install* (§6.5's order). */
        private var installing = false

        /** The result once [install] activated, flipped and wrote `updater.json`: nothing after may undo it. */
        private var done: SyncResult? = null

        @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError too.
        fun run(): SyncRun? {
            val result =
                try {
                    steps() ?: return null
                } catch (t: Throwable) {
                    restoreInterrupt(t)
                    thrown(t)
                }
            return SyncRun(result, storeFailures)
        }

        /** As [CrliteSync]'s: once the install flipped it stays `INSTALLED`; otherwise `STORE_FAILED` or `FAILED`. */
        private fun thrown(t: Throwable): SyncResult {
            done?.let {
                storeFailures++
                logger.safeLog(LogLevel.WARN, "${source.sourceId} ${store.root}: threw after the install", t)
                return it
            }
            val storeFailure = stage == SyncStage.STORE && !isFatal(t)
            if (storeFailure || installing) storeFailures++
            val outcome = if (storeFailure) SyncOutcome.STORE_FAILED else SyncOutcome.FAILED
            return end(Ended(outcome, stage, null, "the sync threw at $stage", cause = t))
        }

        /** [read] at stage `STORE`, so a store that throws is `STORE_FAILED`; the stage before is restored after it. */
        private inline fun <T> stored(read: () -> T): T {
            val before = stage
            stage = SyncStage.STORE
            val value = read()
            stage = before
            return value
        }

        /** The sync's result, or null when it does not run ([bootstrapHolds] false). */
        private fun steps(): SyncResult? {
            stage = SyncStage.STORE
            val loaded = LoadedUpdater.of(store.updater(now))
            if (!bootstrapHolds()) return null
            val record = loaded.record.also { record = it }
            storeFailures += loaded.storeFailures
            val nextAttempt = UpdaterTransitions.nextAttemptAtMillis(record, source.sourceId, now)
            if (nextAttempt != null && nextAttempt > now) return end(Ended(SyncOutcome.BACKOFF, null, null, "backoff"))
            val live = liveMirror()
            // A live generation the pointer does not name (its flip failed) is fetched again, never answered with a 304.
            val since = live?.takeIf(::pointed)?.let(::manifestStoredAt)
            stage = SyncStage.CHANGESET
            val fetched = client.fetchManifest(since)
            fetched.httpStatus?.let { lastStatus = it }
            return when (fetched) {
                is ClientResult.Ok -> manifest(fetched.value, live)
                is ClientResult.Unchanged -> end(Ended(SyncOutcome.UNCHANGED, null, null, "304"))
                is ClientResult.Failed -> failed(fetched)
            }
        }

        /** Steps 3 to 5 for the manifest's [bytes], against [live], the live `MIRROR` generation if any. */
        private fun manifest(
            bytes: ByteString,
            live: DatasetGeneration?,
        ): SyncResult {
            nearCap(bytes.size.toLong(), RevoktLimits.MAX_JSON_BYTES) { "manifest.json is $it bytes" }
            val manifest =
                when (val read = C2spManifest.parse(bytes, client.limits.maxJsonBytes)) {
                    is ManifestRead.Parsed -> read.manifest
                    is ManifestRead.Malformed -> return end(Ended(SyncOutcome.FAILED, stage, null, read.detail))
                }
            val count = manifest.files.size
            val cap = client.maxManifestEntries
            nearCap(count.toLong(), RevoktLimits.MAX_MANIFEST_ENTRIES.toLong()) {
                "manifest.json lists $it files"
            }
            if (count > cap) return end(Ended(SyncOutcome.FAILED, stage, null, "$count manifest entries, cap $cap"))
            stage = SyncStage.INDEX
            val files =
                when (val check = ManifestNames.check(manifest.files)) {
                    is ManifestCheck.Checked -> check.files

                    is ManifestCheck.Refused -> return end(
                        Ended(SyncOutcome.FAILED, stage, INDEX_INCONSISTENT, check.detail),
                    )
                }
            if (files.isEmpty()) {
                return end(Ended(SyncOutcome.FAILED, stage, DiagnosticCode.SOURCE_EMPTY, "the manifest lists no files"))
            }
            val generationId = bytes.sha256().hex()
            if (live != null && live.generationId == generationId && pointed(live)) {
                return end(Ended(SyncOutcome.UNCHANGED, null, null, "manifest $generationId is live"))
            }
            return fetched(files, generationId)
        }

        /** Step 6 for the checked [files] of the manifest whose SHA-256 is [generationId], then [built]. */
        private fun fetched(
            files: List<MirrorFile>,
            generationId: String,
        ): SyncResult {
            stage = SyncStage.ATTACHMENT
            val max = client.limits.maxFilterBytes
            // Each body above half its cap warns (§4), on a manifest that a file over the cap refuses too; that file's own
            // warning is the refusal's code.
            for (f in files.filter { it.size <= max }) {
                nearCap(f.size, RevoktLimits.MAX_FILTER_BYTES) { "${f.filename}: $it bytes" }
            }
            files.firstOrNull { it.size > max }?.let {
                val detail = "${it.filename}: ${it.size} bytes declared, cap $max"
                return end(Ended(SyncOutcome.FAILED, stage, DiagnosticCode.CAP_NEAR_LIMIT, detail))
            }
            val reused = files.filter { stored { store.blob(it.sha256) } == BlobState.MATCH }
            installing = true
            for (file in files) {
                if (file in reused) continue
                val body =
                    when (val result = client.fetchFile(file)) {
                        is ClientResult.Ok -> result.value
                        is ClientResult.Unchanged -> error("a file request is unconditional")
                        is ClientResult.Failed -> return failed(result)
                    }
                lastStatus = ClientResult.OK
                if (stored { store.putBlob(body.toByteArray()) } == BlobWrite.REWRITTEN) storeFailures++
            }
            return built(files, generationId)
        }

        /** Steps 7 to 9 for [files], every one stored as its blob. */
        private fun built(
            files: List<MirrorFile>,
            generationId: String,
        ): SyncResult {
            stage = SyncStage.INDEX
            val built =
                when (val build = buildMirrorIndex(files) { stored { blob(it) } }) {
                    is MirrorBuild.Built -> build
                    is MirrorBuild.Refused -> return refused(build.refusal)
                }
            if (built.coverageHighs.isEmpty()) {
                return end(Ended(SyncOutcome.FAILED, stage, DiagnosticCode.SOURCE_EMPTY, "no filter covers a log"))
            }
            if (!SyncRules.coverageWithinBound(TrustClass.MIRROR, built.coverageHighs, null, clock)) {
                return end(Ended(SyncOutcome.FAILED, stage, null, "a coverage end is beyond now $now + clockSkew"))
            }
            stage = SyncStage.PREPARE
            built.formats.withIndex().firstOrNull { it.value !in engine.formats }?.let { (i, format) ->
                val detail = "${files[i].filename} is $format, which the engine does not list (${engine.formats})"
                return end(Ended(SyncOutcome.FAILED, stage, DiagnosticCode.FORMAT_UNSUPPORTED, detail))
            }
            return installed(pending(files, generationId, built))
        }

        /**
         * The generation to install: id [generationId] (the manifest's SHA-256), `sourceTimestampMillis` the newest
         * coverage end, `meta.format` the first file's encoding (a mirror has no full filter; each file is read in its
         * own), every file a blob under its name, and the time its manifest was stored: now, or the stored time when
         * this generation's directory is already written (an install whose flip failed, retried), so `meta.json` reads
         * back the same.
         */
        private fun pending(
            files: List<MirrorFile>,
            generationId: String,
            built: MirrorBuild.Built,
        ): PendingGeneration {
            val newest = minOf(checkNotNull(built.coverageHighs.maxOrNull()), Long.MAX_VALUE.toULong()).toLong()
            val directory = GenerationNames.directory(newest, generationId)
            val written = stored { store.meta(directory) }?.takeIf { it.trustClass == TrustClass.MIRROR }
            val meta =
                GenerationMeta(
                    dataset = Dataset.CRLITE,
                    channel = store.channel,
                    trustClass = TrustClass.MIRROR,
                    generationId = generationId,
                    format = built.formats.first(),
                    freshness = Freshness.MANIFEST_LAST_MODIFIED,
                    sourceTimestampMillis = newest,
                    collection = null,
                    blobs = files.associateTo(LinkedHashMap()) { it.name to it.sha256 },
                    signed = null,
                    manifestStoredAtMillis = written?.manifestStoredAtMillis ?: now,
                )
            return PendingGeneration(meta, built.index, emptyMap(), null)
        }

        /** Runs [install] for [pending] and ends the sync with its outcome; a successful install is then pruned to. */
        private fun installed(pending: PendingGeneration): SyncResult {
            val updated = UpdaterTransitions.afterUnsignedInstall(checkNotNull(record), source.sourceId, now)
            val publication = Publication(false, null, true, now, clockSkewMillis)
            return when (val result = install(pending, engine, store, snapshot, publication, updated, logger)) {
                is InstallResult.Installed -> {
                    storeFailures += result.storeFailures
                    val installed =
                        result(SyncOutcome.INSTALLED, null, notes, mapOf(Dataset.CRLITE to result.generationId))
                    done = installed
                    prune(result.directory)
                    installed
                }

                is InstallResult.Failed -> {
                    storeFailures += result.storeFailures
                    end(Ended(result.outcome, result.stage, result.code, "the install failed", cause = result.cause))
                }
            }
        }

        /**
         * A `CAP_NEAR_LIMIT` warning when [value] is above half of [cap], the `RevoktLimits` constant (§4), in the shape
         * of [CrliteSync]'s (#205). Each item is checked once per sync (the manifest's body and count once, each file
         * once, filenames being unique), so there is one warning per item.
         */
        private inline fun nearCap(
            value: Long,
            cap: Long,
            what: (Long) -> String,
        ) {
            if (value > cap / 2) {
                notes += warning(DiagnosticCode.CAP_NEAR_LIMIT, "${what(value)}, above half of $cap")
            }
        }

        /** The live generation when it is a `MIRROR` one, else null: the If-Modified-Since source and the id compared. */
        private fun liveMirror(): DatasetGeneration? =
            snapshot.snapshot.datasets[Dataset.CRLITE]?.takeIf {
                it.trustClass == TrustClass.MIRROR && it.generationId != null && it.sourceTimestampMillis != null
            }

        private fun directoryOf(live: DatasetGeneration): String =
            GenerationNames.directory(checkNotNull(live.sourceTimestampMillis), checkNotNull(live.generationId))

        /**
         * The time [live]'s manifest was stored, from its `meta.json`; null when it carries none or cannot be read (a
         * malformed one is a store failure), so the request is unconditional.
         */
        private fun manifestStoredAt(live: DatasetGeneration): Long? =
            when (val read = stored { store.readMeta(directoryOf(live)) }) {
                is StoreRead.Found -> {
                    read.value.manifestStoredAtMillis
                }

                StoreRead.Malformed -> {
                    storeFailures++
                    null
                }

                StoreRead.Absent -> {
                    null
                }
            }

        /** Whether the pointer names [live]'s directory as `live`. */
        private fun pointed(live: DatasetGeneration): Boolean =
            (stored { store.pointer() } as? StoreRead.Found)?.value?.live == directoryOf(live)

        /** As [CrliteSync]'s prune: to the directories the pointer names, never when it does not read back. */
        @Suppress("TooGenericExceptionCaught") // §6.5: the loader catches every throwable.
        private fun prune(installed: String) {
            try {
                if ((store.pointer() as? StoreRead.Found)?.value?.live != installed) {
                    storeFailures++
                    logger.safeLog(
                        LogLevel.WARN,
                        "${store.root}: the pointer does not read back as $installed; not pruned",
                    )
                    return
                }
                store.prune()
            } catch (t: Throwable) {
                restoreInterrupt(t)
                storeFailures++
                logger.safeLog(LogLevel.WARN, "pruning ${store.root} failed", t)
            }
        }

        private fun failed(result: ClientResult.Failed): SyncResult {
            result.httpStatus?.let { lastStatus = it }
            // A fetcher's fatal error during the body phase is an OutOfMemoryError during an install (§6.5).
            if (installing && result.cause?.let(::isFatal) == true) storeFailures++
            return end(Ended(SyncOutcome.FAILED, result.stage, result.code, result.detail, cause = result.cause))
        }

        private fun refused(refusal: IndexBuild.Refused): SyncResult =
            end(
                Ended(
                    SyncOutcome.FAILED,
                    refusal.stage,
                    refusal.code,
                    "${refusal.reason}: ${refusal.detail}",
                    refusal.cause,
                ),
            )

        /**
         * Ends the sync as [ended] without an install: writes `updater.json` (a failure there is a store failure), unless
         * the record was never read or the bootstrap check never passed ([record] null): a store read that threw there is
         * `STORE_FAILED` at `STORE`, counted, and leaves `updater.json` as it was.
         */
        @Suppress("TooGenericExceptionCaught") // §6.5: the failure path catches every throwable too.
        private fun end(ended: Ended): SyncResult {
            try {
                record?.let {
                    store.writeUpdater(
                        UpdaterTransitions.after(it, source.sourceId, ended.outcome, now),
                        now,
                    )
                }
            } catch (t: Throwable) {
                restoreInterrupt(t)
                storeFailures++
                logger.safeLog(LogLevel.WARN, "writing ${store.root}/updater.json failed", t)
            }
            val warnings = ArrayList<PolicyDiagnostic>()
            if (ended.outcome == SyncOutcome.FAILED || ended.outcome == SyncOutcome.STORE_FAILED) {
                val message = "${ended.outcome} at ${ended.stage}: ${ended.detail}"
                logger.safeLog(LogLevel.WARN, "${source.sourceId} ${store.root}: $message", ended.cause)
                val cause = ended.cause?.let { ": $it" } ?: ""
                warnings += warning(DiagnosticCode.SYNC_FAILED, message + cause)
            }
            ended.code?.let { warnings += warning(it, ended.detail) }
            warnings += notes
            return result(ended.outcome, ended.stage, warnings, emptyMap(), ended.cause)
        }

        private fun result(
            outcome: SyncOutcome,
            stage: SyncStage?,
            warnings: List<PolicyDiagnostic>,
            installed: Map<Dataset, String>,
            cause: Throwable? = null,
        ): SyncResult =
            SyncResult
                .Builder()
                .outcome(outcome)
                .atMillis(now)
                .installed(installed)
                .sourceId(source.sourceId)
                .stage(stage)
                .httpStatus(if (outcome == SyncOutcome.BACKOFF) null else lastStatus)
                .cause(cause)
                .warnings(warnings)
                .build()
    }

    @OptIn(RevoktTestingApi::class)
    private fun warning(
        code: DiagnosticCode,
        message: String,
    ): PolicyDiagnostic =
        PolicyDiagnostic
            .Builder()
            .code(code)
            .severity(Severity.WARNING)
            .dataset(Dataset.CRLITE)
            .message("${client.source.sourceId}: $message")
            .build()

    /** [file]'s stored body, re-hashed against its key; a blob gone since it was written is a store failure. */
    private fun blob(file: MirrorFile): ByteArray =
        checkNotNull(store.readBlob(file.sha256)) { "the blob of ${file.filename} is gone" }

    /** How a sync that installs nothing ended: [outcome] at [stage], with the diagnostic [code] beyond `SYNC_FAILED`. */
    private class Ended(
        val outcome: SyncOutcome,
        val stage: SyncStage?,
        val code: DiagnosticCode?,
        val detail: String,
        val cause: Throwable? = null,
    )
}

/** What [buildMirrorIndex] produced. */
internal sealed interface MirrorBuild {
    /**
     * A mirror generation's locally built `index.bin` ([index]), the latest coverage `high` of each file that covers a
     * log ([coverageHighs], the input of the §6.3 coverage rules) and each file's encoding ([formats], manifest order).
     */
    class Built(
        val index: ByteArray,
        val coverageHighs: List<ULong>,
        val formats: List<FilterFormat>,
    ) : MirrorBuild

    /** The files build no generation, for [refusal]'s reason, stage and code. */
    class Refused(
        val refusal: IndexBuild.Refused,
    ) : MirrorBuild
}

/**
 * Builds a `MIRROR` generation's `index.bin` (spec §7.3 "The index is built locally", revision 53, as `upki fetch`
 * does): each of [files], in manifest order, under its name in the generation (the derived name of a manifest name over
 * 32 bytes included), its [body] read once and its coverage decoded with the clubcard decoders. A file that does not
 * decode is [IndexRefusal.FILTER_UNREADABLE] (`FAILED` at `PREPARE`); an index over [C2spIndex.MAX_BYTES] is
 * [IndexRefusal.OVER_CAP] (`FAILED` with `INDEX_INCONSISTENT` at `INDEX`), before a generation directory is written.
 */
@OptIn(RevoktInternalApi::class)
internal fun buildMirrorIndex(
    files: List<MirrorFile>,
    body: (MirrorFile) -> ByteArray,
): MirrorBuild {
    val coverage = ArrayList<Pair<String, Map<ByteString, Window>>>(files.size)
    val formats = ArrayList<FilterFormat>(files.size)
    for (f in files) {
        val bytes = body(f)
        val decoded =
            try {
                formats +=
                    when (ClubcardFilters.encodingOf(bytes)) {
                        Encoding.V3 -> FilterFormat.V3
                        Encoding.V4 -> FilterFormat.V4
                    }
                ClubcardFilters.decode(bytes)
            } catch (e: ClubcardFormatException) {
                return MirrorBuild.Refused(
                    IndexBuild.Refused(IndexRefusal.FILTER_UNREADABLE, "${f.filename}: ${e.message}", e),
                )
            }
        coverage +=
            f.name to
            decoded.universe.logs.entries.associate { (log, interval) ->
                log.bytes to Window(interval.low.value.toULong(), interval.high.value.toULong())
            }
    }
    val index = C2spIndex.index(coverage)
    val size = C2spIndex.byteSize(index)
    if (size > C2spIndex.MAX_BYTES) {
        val detail = "index.bin would be $size bytes, over ${C2spIndex.MAX_BYTES}"
        return MirrorBuild.Refused(IndexBuild.Refused(IndexRefusal.OVER_CAP, detail))
    }
    return MirrorBuild.Built(C2spIndex.write(index), coverageHighs(index), formats)
}
