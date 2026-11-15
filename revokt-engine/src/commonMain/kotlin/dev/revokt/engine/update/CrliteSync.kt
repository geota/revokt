// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.LogLevel
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLogger
import dev.revokt.RevoktTestingApi
import dev.revokt.Severity
import dev.revokt.SignatureVerifier
import dev.revokt.SyncOutcome
import dev.revokt.SyncResult
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.clubcard.port.Encoding
import dev.revokt.engine.fetch.ChangesetVerification
import dev.revokt.engine.fetch.ChangesetVerifier
import dev.revokt.engine.fetch.ClientResult
import dev.revokt.engine.fetch.CrliteRecord
import dev.revokt.engine.fetch.RemoteSettingsClient
import dev.revokt.engine.store.BlobState
import dev.revokt.engine.store.BlobWrite
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.SignedMeta
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.engine.verify.RawSignature
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** One sync's [result], and what it added to `storeFailures` (spec §6.5), for the loader to count. */
internal class SyncRun(
    val result: SyncResult,
    val storeFailures: Int,
) {
    override fun toString(): String = "SyncRun($result, storeFailures=$storeFailures)"
}

/**
 * The CRLite updater for one Remote Settings source, dataset and channel (spec §11's 0.2 row: "CRLite updater and the
 * updater record over `RevoktStorage.inMemory()`"): [syncOnce] syncs one **full** generation, the whole collection's
 * changeset. Deltas from the cursor, `_since` tombstones, reset-and-retry, the metered deferral and the half-cap
 * warnings are #141's; the schedule is the loader's (#147), which runs [syncOnce] on its dispatcher, never two at once.
 *
 * [client] is the source's client for `CRLITE`, [store] the dataset and channel's layout over the store, [snapshot] the
 * published snapshot this sync reads the live generation from and publishes to, [verifier] the content-signature and
 * x5u-chain verifier, and [clockSkewMillis] and [rollbackWindowMillis] the policy's (`RevoktPolicy`, §4).
 */
internal class CrliteSync(
    private val client: RemoteSettingsClient,
    private val store: StoreLayout,
    private val engine: RevocationEngine,
    private val snapshot: SnapshotRef,
    private val verifier: SignatureVerifier,
    private val clockSkewMillis: Long,
    private val rollbackWindowMillis: Long,
    private val logger: RevoktLogger,
) {
    init {
        require(store.dataset == Dataset.CRLITE) { "the CRLite updater syncs CRLITE, not ${store.dataset}" }
        requireNotNull(
            client.source.collection(Dataset.CRLITE),
        ) { "${client.source.sourceId} has no CRLite collection" }
        require(clockSkewMillis >= 0) { "clockSkew is negative" }
        require(rollbackWindowMillis >= 0) { "rollbackWindow is negative" }
    }

    /**
     * One sync at [nowMillis], the loader's one clock read for it, in the order of #137 (spec §5.1, §6.3, §6.5, §7.1):
     * 1. Under the source's persisted backoff (`backoffUntilMillis` after now) → `BACKOFF`, the attempt fields written.
     * 2. Poll `monitor/changes`, then fetch the whole collection's changeset at its `_expected`.
     * 3. Verify it ([ChangesetVerifier]); everything after reads only the verified records and `<ts>`
     *    ([ChangesetVerification.Verified]), never the changeset's `changes`.
     * 4. The schema check and the channel filter ([RemoteSettingsClient.checkRecords]): `SYNC_SCHEMA_REJECTED`.
     * 5. The generation's records and names ([placeFilters]): not exactly one full, or two attachments that map to one
     *    name, is `FAILED` with `INDEX_INCONSISTENT` at `INDEX` before any body is fetched.
     * 6. The decision before any body ([SyncRules.admit]): `UNCHANGED`, `ROLLBACK_REFUSED`, `CLOCK_SKEW`, or on.
     * 7. The cap before any body: a signed record over `MAX_FILTER_BYTES` is `FAILED` with `CAP_NEAR_LIMIT` at
     *    `ATTACHMENT`, and nothing is fetched. There is no per-sync total, as neither Firefox nor upki has one (the
     *    maintainer's decision on #137; `MAX_SYNC_BYTES` is dropped). Then each body is fetched, checked
     *    against its signed size and hash, and written one at a time: a full as a blob, reused without a fetch when its
     *    blob is stored and re-hashes (§6.5; a mismatch is fetched and rewritten, `storeFailures++`), a delta for the
     *    generation directory.
     * 8. [buildIndex], then the decision on the coverage ([SyncRules.decide]), then [install] in §6.5's order, which
     *    writes `updater.json` after the pointer flip; on success the store is pruned to what the pointer names.
     *
     * Every outcome but `INSTALLED` writes `updater.json` itself ([UpdaterTransitions.after]): the cursor,
     * `lastVerified*` and the watermark advance only through an install. Every throwable is caught, an
     * `OutOfMemoryError` included, and is `FAILED` at the stage it hit (§6.5: "every loader task catches `Throwable`").
     *
     * `UNCHANGED`-by-timestamp against a generation the snapshot holds live but the pointer does not name (an install
     * whose flip or `updater.json` failed after `activate`, #184) is not the end: the install is retried, which skips the
     * already-written directory and flips the pointer (#137's notes from #184 and #190).
     */
    fun syncOnce(nowMillis: Long): SyncRun = Attempt(nowMillis).run()

    /** One sync's state: what it read, what it fetched and what the failure path writes. */
    @OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
    private inner class Attempt(
        private val now: Long,
    ) {
        private val source = client.source
        private val channel = store.channel
        private val clock = SyncClock(now, clockSkewMillis, rollbackWindowMillis)
        private var stage = SyncStage.STORE
        private var record = UpdaterRecord()
        private var storeFailures = 0
        private var backoff: Long? = null
        private var lastStatus: Int? = null

        @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError too.
        fun run(): SyncRun {
            val result =
                try {
                    steps()
                } catch (t: Throwable) {
                    restoreInterrupt(t)
                    // As in install: a store read or write that throws is STORE_FAILED; anything else, FAILED.
                    val storeFailure = stage == SyncStage.STORE && !isFatal(t)
                    if (storeFailure) storeFailures++
                    val outcome = if (storeFailure) SyncOutcome.STORE_FAILED else SyncOutcome.FAILED
                    end(Ended(outcome, stage, null, "the sync threw at $stage", cause = t))
                }
            return SyncRun(result, storeFailures)
        }

        private fun steps(): SyncResult {
            stage = SyncStage.STORE
            val loaded = LoadedUpdater.of(store.updater(now))
            record = loaded.record
            storeFailures += loaded.storeFailures
            val nextAttempt = UpdaterTransitions.nextAttemptAtMillis(record, source.sourceId, now)
            if (nextAttempt != null && nextAttempt > now) return end(Ended(SyncOutcome.BACKOFF, null, null, "backoff"))
            stage = SyncStage.CHANGESET
            val expected = ok(client.pollChanges()) { return it }
            val changeset = ok(client.fetchChangeset(expected, since = null)) { return it }
            stage = SyncStage.SIGNATURE
            val merged = ContentSignature.merge(emptyList(), changeset.changes) ?: changeset.changes
            val verified =
                when (val verification = ChangesetVerifier(client, verifier, now).verify(changeset, merged)) {
                    is ChangesetVerification.Verified -> verification.also { backoff(it.backoffMillis) }
                    is ChangesetVerification.Failed -> return unverified(verification)
                }
            stage = SyncStage.SCHEMA
            val crlite = ok(client.checkRecords(verified.records, channel)) { return it }
            return generation(verified, crlite)
        }

        /** Steps 5 and 6, over the [verified] changeset's schema-checked records of the channel, [crlite]. */
        private fun generation(
            verified: ChangesetVerification.Verified,
            crlite: List<CrliteRecord>,
        ): SyncResult {
            val ts = verified.timestamp
            stage = SyncStage.INDEX
            val records =
                crlite.map {
                    FilterRecord(
                        it.id,
                        it.channel,
                        it.incremental,
                        it.effectiveTimestamp,
                        it.attachment.filename,
                    )
                }
            val placed =
                when (val placement = placeFilters(records, channel)) {
                    is Placement.Placed -> placement.filters
                    is IndexBuild.Refused -> return refused(placement)
                }
            val live = liveGeneration()
            var ruled = live
            var admitted = SyncRules.admit(ts, record.watermarkMillis, ruled, clock)
            if (admitted == SyncDecision.UNCHANGED && live != null && !pointed(live)) {
                // The live generation's install activated but its flip did not land: retry it, never stop (#190).
                ruled = null
                admitted = SyncRules.admit(ts, record.watermarkMillis, null, clock)
            }
            decided(admitted, ts)?.let { return it }
            return fetched(verified, crlite, records, placed, ruled)
        }

        /**
         * Steps 7 and 8 for the [placed] filters of [records] (the channel's [crlite] records), decided against
         * [ruled], the live generation the rules compare with.
         */
        private fun fetched(
            verified: ChangesetVerification.Verified,
            crlite: List<CrliteRecord>,
            records: List<FilterRecord>,
            placed: List<PlacedFilter>,
            ruled: LiveGeneration?,
        ): SyncResult {
            val ts = verified.timestamp
            stage = SyncStage.ATTACHMENT
            val byId = crlite.associateBy { it.id }
            val attachments = placed.map { byId.getValue(it.record.id) }
            val reused = attachments.filter { !it.incremental && store.blob(it.attachment.sha256) == BlobState.MATCH }
            cap(attachments)?.let { return it }
            val bodies = Bodies()
            for (r in attachments) bodies.fetch(r, r in reused)?.let { return it }
            stage = SyncStage.INDEX
            val built =
                when (val build = buildIndex(records, channel) { bodies.bytes(byId.getValue(it.id)) }) {
                    is IndexBuild.Built -> build
                    is IndexBuild.Refused -> return refused(build)
                }
            val decision = SyncRules.decide(ts, record.watermarkMillis, ruled, built.coverageHighs, clock)
            decided(decision, ts)?.let { return it }
            stage = SyncStage.PREPARE
            stage = SyncStage.PREPARE
            bodies.unlisted(placed)?.let { filter ->
                val detail = "${filter.record.id} is in an encoding the engine does not list (${engine.formats})"
                return end(Ended(SyncOutcome.FAILED, SyncStage.PREPARE, DiagnosticCode.FORMAT_UNSUPPORTED, detail))
            }
            val pending = pending(verified, placed, built, bodies, bodies.format(placed))
            return installed(pending, decision == SyncDecision.INSTALL_CLOCK_BEHIND)
        }

        /**
         * The generation to install: id `"<ts>/<last placed record id>"` (spec §4 `DataState.generationId`), its
         * `meta.json`, [built]'s index, the fetched deltas and `records.json`, the verified payload without its prefix.
         */
        private fun pending(
            verified: ChangesetVerification.Verified,
            placed: List<PlacedFilter>,
            built: IndexBuild.Built,
            bodies: Bodies,
            format: FilterFormat,
        ): PendingGeneration {
            val ts = verified.timestamp
            val generationId = "$ts/${placed.last().record.id}"
            val meta =
                GenerationMeta(
                    dataset = Dataset.CRLITE,
                    channel = channel,
                    trustClass = TrustClass.SIGNED,
                    generationId = generationId,
                    format = format,
                    freshness = Freshness.RECORD_LAST_MODIFIED,
                    sourceTimestampMillis = ts,
                    collection = source.bucket + "/" + source.collection(Dataset.CRLITE),
                    blobs = bodies.blobs,
                    signed = signedMeta(verified),
                )
            val recordsJson = checkNotNull(ContentSignature.recordsJson(verified.records, ts)) { "verified records" }
            return PendingGeneration(meta, built.index, bodies.deltas, recordsJson)
        }

        /** Runs [install] for [pending] and ends the sync with its outcome; a successful install is then pruned to. */
        private fun installed(
            pending: PendingGeneration,
            clockBehind: Boolean,
        ): SyncResult {
            val ts = pending.meta.sourceTimestampMillis
            val updated =
                UpdaterTransitions.after(record, source.sourceId, SyncOutcome.INSTALLED, now, ts, clockBehind, backoff)
            val publication =
                Publication(
                    fromSeed = false,
                    seedFormat = null,
                    staleGateOpen = true,
                    nowMillis = now,
                    clockSkewMillis = clockSkewMillis,
                )
            return when (val result = install(pending, engine, store, snapshot, publication, updated, logger)) {
                is InstallResult.Installed -> {
                    storeFailures += result.storeFailures
                    prune()
                    val warnings =
                        if (clockBehind) {
                            listOf(warning(DiagnosticCode.CLOCK_BEHIND, "installed $ts, beyond now $now + clockSkew"))
                        } else {
                            emptyList()
                        }
                    result(SyncOutcome.INSTALLED, null, warnings, mapOf(Dataset.CRLITE to result.generationId))
                }

                is InstallResult.Failed -> {
                    storeFailures += result.storeFailures
                    end(Ended(result.outcome, result.stage, result.code, "the install failed", cause = result.cause))
                }
            }
        }

        /** The sync for an [admitted] or decided changeset at [ts] that does not go on to install, or null. */
        private fun decided(
            decision: SyncDecision,
            ts: Long,
        ): SyncResult? =
            when (decision) {
                SyncDecision.INSTALL, SyncDecision.INSTALL_CLOCK_BEHIND -> {
                    null
                }

                SyncDecision.UNCHANGED -> {
                    end(Ended(SyncOutcome.UNCHANGED, null, null, "$ts is live"))
                }

                SyncDecision.ROLLBACK_REFUSED -> {
                    end(Ended(SyncOutcome.ROLLBACK_REFUSED, null, null, "$ts rolls back"))
                }

                SyncDecision.CLOCK_SKEW -> {
                    end(Ended(SyncOutcome.CLOCK_SKEW, decision.stage, null, "$ts is beyond now $now + clockSkew"))
                }

                SyncDecision.FAILED -> {
                    end(Ended(SyncOutcome.FAILED, decision.stage, null, "a coverage end is beyond $ts + clockSkew"))
                }
            }

        /**
         * Spec §5.1's cap over [attachments], every placed record's, before any body is fetched: a signed record
         * declaring more than `MAX_FILTER_BYTES` is `FAILED` with `CAP_NEAR_LIMIT` at `ATTACHMENT`, or null.
         */
        private fun cap(attachments: List<CrliteRecord>): SyncResult? {
            val max = client.limits.maxFilterBytes
            val over = attachments.firstOrNull { it.attachment.size > max } ?: return null
            val detail = "${over.id}: ${over.attachment.size} bytes declared, cap $max"
            return end(Ended(SyncOutcome.FAILED, SyncStage.ATTACHMENT, DiagnosticCode.CAP_NEAR_LIMIT, detail))
        }

        /** The bodies of one generation, fetched one at a time; a full's bytes stay in its blob, not here. */
        private inner class Bodies {
            val blobs = LinkedHashMap<String, ByteString>()
            val deltas = LinkedHashMap<String, ByteArray>()
            private val deltaBytes = HashMap<String, ByteArray>()
            private val encodings = HashMap<String, Encoding?>()

            /**
             * Fetches [r]'s body and writes it, or for a [reuse]d full only names its stored blob; the failure that ends
             * the sync, or null.
             */
            fun fetch(
                r: CrliteRecord,
                reuse: Boolean,
            ): SyncResult? {
                val name = GenerationNames.derive(r.attachment.filename)
                val sha256 = r.attachment.sha256
                if (reuse) {
                    blobs[name] = sha256
                    return null
                }
                val bytes = ok(client.fetchAttachment(r)) { return it }.toByteArray()
                if (r.incremental) {
                    deltas[name] = bytes
                    deltaBytes[r.id] = bytes
                } else {
                    stage = SyncStage.STORE
                    if (store.putBlob(bytes) == BlobWrite.REWRITTEN) storeFailures++
                    stage = SyncStage.ATTACHMENT
                    blobs[name] = sha256
                }
                return null
            }

            /**
             * [r]'s body for [buildIndex], which reads each once: a delta's as fetched, a full's read back from its blob
             * and re-hashed. The full's encoding is noted for [format].
             */
            fun bytes(r: CrliteRecord): ByteArray {
                val bytes =
                    deltaBytes[r.id]
                        ?: checkNotNull(store.readBlob(r.attachment.sha256)) { "the blob of ${r.id} is gone" }
                encodings[r.id] = encoding(bytes)
                return bytes
            }

            /**
             * The first of [placed] whose encoding [engine] does not list (spec §3.2 `FORMAT_UNSUPPORTED`; the lead's
             * decision on #137: the check covers every placed filter, a full or a delta), or null. Called after
             * [buildIndex] decoded every placed filter, so each encoding is known.
             */
            fun unlisted(placed: List<PlacedFilter>): PlacedFilter? =
                placed.firstOrNull { format(checkNotNull(encodings[it.record.id]) { "decoded" }) !in engine.formats }

            /**
             * The generation's `meta.format`: the full's encoding. A delta may be in another one the engine lists, and
             * each is read as served (the maintainer's decision on #137, as Firefox's `cert_storage` and upki read each
             * filter). Called after [buildIndex] decoded every placed filter.
             */
            fun format(placed: List<PlacedFilter>): FilterFormat =
                format(checkNotNull(encodings[placed.first { it.full }.record.id]) { "decoded" })

            private fun format(encoding: Encoding): FilterFormat =
                when (encoding) {
                    Encoding.V3 -> FilterFormat.V3
                    Encoding.V4 -> FilterFormat.V4
                }

            private fun encoding(bytes: ByteArray): Encoding? =
                try {
                    ClubcardFilters.encodingOf(bytes)
                } catch (ignored: ClubcardFormatException) {
                    null // buildIndex decodes every placed filter and refuses this one (FILTER_UNREADABLE).
                }
        }

        /** `meta.json`'s `SIGNED` members: `<ts>`, the x5u leaf's SHA-256 and the verified entry's raw signature. */
        private fun signedMeta(verified: ChangesetVerification.Verified): SignedMeta {
            val raw = checkNotNull(verified.entry.signature?.let(RawSignature::decode)) { "a verified signature" }
            return SignedMeta(
                verified.timestamp,
                verified.path.links[0]
                    .der
                    .toByteString()
                    .sha256(),
                raw.toByteString(),
            )
        }

        /** The dataset's live generation as the snapshot publishes it, for [SyncRules]; null when it has none. */
        private fun liveGeneration(): LiveGeneration? {
            val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
            val trustClass = live.trustClass ?: return null
            val timestamp = live.sourceTimestampMillis ?: return null
            return LiveGeneration(trustClass, timestamp, live.maxCoverageMillis)
        }

        /** Whether the pointer names [live]'s directory as `live`. */
        private fun pointed(live: LiveGeneration): Boolean {
            val id = snapshot.snapshot.datasets[Dataset.CRLITE]?.generationId ?: return false
            val directory = GenerationNames.directory(live.sourceTimestampMillis, id)
            return (store.pointer() as? StoreRead.Found)?.value?.live == directory
        }

        /** Prunes the store to the directories the pointer names; a failure is a store failure, never the sync's. */
        @Suppress("TooGenericExceptionCaught") // §6.5: the loader catches every throwable.
        private fun prune() {
            try {
                store.prune()
            } catch (t: Throwable) {
                restoreInterrupt(t)
                storeFailures++
                logger.safeLog(LogLevel.WARN, "pruning ${store.root} failed", t)
            }
        }

        /** [result]'s value, its backoff and status kept; on a failure, [failed] with the sync it ends. */
        private inline fun <T> ok(
            result: ClientResult<T>,
            failed: (SyncResult) -> Nothing,
        ): T {
            backoff(result.backoffMillis)
            result.httpStatus?.let { lastStatus = it }
            return when (result) {
                is ClientResult.Ok -> {
                    result.value
                }

                is ClientResult.Failed -> {
                    failed(
                        end(Ended(SyncOutcome.FAILED, result.stage, result.code, result.detail, cause = result.cause)),
                    )
                }

                // Only the conditional changeset fetch answers Unchanged, and this sync's is unconditional (#141's).
                is ClientResult.Unchanged -> {
                    failed(end(Ended(SyncOutcome.FAILED, stage, null, "304 to an unconditional request")))
                }
            }
        }

        private fun unverified(failure: ChangesetVerification.Failed): SyncResult {
            backoff(failure.backoffMillis)
            failure.httpStatus?.let { lastStatus = it }
            return end(
                Ended(failure.outcome, failure.stage, null, "${failure.failure}: ${failure.detail}", failure.cause),
            )
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

        private fun backoff(millis: Long?) {
            if (millis != null) backoff = maxOf(backoff ?: millis, millis)
        }

        /**
         * Ends the sync as [ended] without an install: writes `updater.json` ([UpdaterTransitions.after]; a write that
         * fails is a store failure and leaves the outcome), then the result.
         */
        @Suppress("TooGenericExceptionCaught") // §6.5: the failure path catches every throwable too.
        private fun end(ended: Ended): SyncResult {
            try {
                val next =
                    UpdaterTransitions.after(
                        record,
                        source.sourceId,
                        ended.outcome,
                        now,
                        serverBackoffMillis = backoff,
                    )
                store.writeUpdater(next, now)
            } catch (t: Throwable) {
                restoreInterrupt(t)
                storeFailures++
                logger.safeLog(LogLevel.WARN, "writing ${store.root}/updater.json failed", t)
            }
            val warnings = ArrayList<PolicyDiagnostic>()
            val failure =
                ended.outcome == SyncOutcome.FAILED || ended.outcome == SyncOutcome.STORE_FAILED ||
                    ended.outcome == SyncOutcome.CLOCK_SKEW
            if (failure) {
                val message = "${ended.outcome} at ${ended.stage}: ${ended.detail}"
                logger.safeLog(LogLevel.WARN, "${source.sourceId} ${store.root}: $message", ended.cause)
                val cause = ended.cause?.let { ": $it" } ?: ""
                warnings += warning(DiagnosticCode.SYNC_FAILED, message + cause)
            }
            ended.code?.let { warnings += warning(it, ended.detail) }
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

        private fun warning(
            code: DiagnosticCode,
            message: String,
        ): PolicyDiagnostic =
            PolicyDiagnostic
                .Builder()
                .code(code)
                .severity(Severity.WARNING)
                .dataset(Dataset.CRLITE)
                .message("${source.sourceId}: $message")
                .build()
    }

    /** How a sync that installs nothing ended: [outcome] at [stage], with the diagnostic [code] beyond `SYNC_FAILED`. */
    private class Ended(
        val outcome: SyncOutcome,
        val stage: SyncStage?,
        val code: DiagnosticCode?,
        val detail: String,
        val cause: Throwable? = null,
    )
}
