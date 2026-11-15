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
import dev.revokt.RevoktLimits
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
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonParseException
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
import dev.revokt.engine.walker.absorb
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
 * The policy inputs of one [CrliteSync] (`RevoktPolicy`, §4): `clockSkew` and `rollbackWindow`, and CRLite's
 * `staleAfter`, null when the policy has no staleness entry for it (§7.2's metered deferral lasts until the live data is
 * past it).
 */
internal class SyncPolicy(
    val clockSkewMillis: Long,
    val rollbackWindowMillis: Long,
    val staleAfterMillis: Long?,
) {
    init {
        require(clockSkewMillis >= 0) { "clockSkew is negative" }
        require(rollbackWindowMillis >= 0) { "rollbackWindow is negative" }
        require(staleAfterMillis == null || staleAfterMillis >= 0) { "staleAfter is negative" }
    }
}

/**
 * The CRLite updater for one Remote Settings source, dataset and channel (spec §11's 0.2 row: "CRLite updater and the
 * updater record over `RevoktStorage.inMemory()`"): [syncOnce] syncs one generation, from the cursor when the store holds
 * one (#141) and the whole collection otherwise (#137). The schedule is the loader's (#147), which runs [syncOnce] on its
 * dispatcher, never two at once.
 *
 * [client] is the source's client for `CRLITE`, [store] the dataset and channel's layout over the store, [snapshot] the
 * published snapshot this sync reads the live generation from and publishes to, [verifier] the content-signature and
 * x5u-chain verifier, [policy] the policy's inputs, and [meteredNetwork] the builder's seam (§4: sampled once per sync
 * before a full download; a throw reads as false).
 */
internal class CrliteSync(
    private val client: RemoteSettingsClient,
    private val store: StoreLayout,
    private val engine: RevocationEngine,
    private val snapshot: SnapshotRef,
    private val verifier: SignatureVerifier,
    private val policy: SyncPolicy,
    private val logger: RevoktLogger,
    private val meteredNetwork: () -> Boolean = { false },
) {
    init {
        require(store.dataset == Dataset.CRLITE) { "the CRLite updater syncs CRLITE, not ${store.dataset}" }
        requireNotNull(
            client.source.collection(Dataset.CRLITE),
        ) { "${client.source.sourceId} has no CRLite collection" }
    }

    /**
     * One sync at [nowMillis], the loader's one clock read for it, in the order of #137 and #141 (spec §5.1, §6.3, §6.5,
     * §7.1, §7.2):
     * 1. Under the source's persisted backoff (`backoffUntilMillis` after now) → `BACKOFF`, the attempt fields written.
     * 2. Poll `monitor/changes`, then fetch the collection's changeset at its `_expected`: from the cursor
     *    (`_since=<cursor>` and `If-None-Match: "<cursor>"`) when `updater.json` holds one and the pointed generation's
     *    `records.json` reads, else the whole collection. A 304 is `UNCHANGED`.
     * 3. Verify it ([ChangesetVerifier]) over the stored records with its changes merged, tombstones first
     *    ([ContentSignature.merge]); everything after reads only the verified records and `<ts>`
     *    ([ChangesetVerification.Verified]), never the changeset's `changes`. A `_since` changeset that does not verify is
     *    fetched once more as the whole collection, which must verify (§7.1 "reset-and-retry once").
     * 4. The schema check and the channel filter ([RemoteSettingsClient.checkRecords]): `SYNC_SCHEMA_REJECTED`.
     * 5. The generation's records and names ([placeFilters]): not exactly one full, or two attachments that map to one
     *    name, is `FAILED` with `INDEX_INCONSISTENT` at `INDEX` before any body is fetched.
     * 6. The decision before any body ([SyncRules.admit]): `UNCHANGED`, `ROLLBACK_REFUSED`, `CLOCK_SKEW`, or on.
     * 7. The cap before any body: a signed record over `MAX_FILTER_BYTES` is `FAILED` with `CAP_NEAR_LIMIT` at
     *    `ATTACHMENT`, and nothing is fetched. There is no per-sync total, as neither Firefox nor upki has one (the
     *    maintainer's decision on #137; `MAX_SYNC_BYTES` is dropped).
     * 8. The metered deferral (§7.2): when the full must be downloaded (no stored blob re-hashes to it), the dataset has
     *    data, and that data is not past `staleAfter`, a metered network defers the sync: `DEFERRED` with
     *    `METERED_DEFERRED`.
     * 9. Each body, one at a time, checked against its signed size and hash and written: a full as a blob, reused without
     *    a fetch when its blob is stored and re-hashes (§6.5; a mismatch is fetched and rewritten, `storeFailures++`); a
     *    delta staged as a file of the generation directory, copied without a fetch from a pointed generation whose file
     *    of that name re-hashes to it, as Firefox and upki reuse a filter on disk whose hash matches.
     * 10. [buildIndex], then the decision on the coverage ([SyncRules.decide]), then [install] in §6.5's order, which
     *    writes `updater.json` after the pointer flip; on success the store is pruned to what the pointer names.
     *
     * Every outcome but `INSTALLED` writes `updater.json` itself ([UpdaterTransitions.after]) and deletes any directory
     * this sync staged: the cursor, `lastVerified*` and the watermark advance only through an install. Every throwable is
     * caught, an `OutOfMemoryError` included, and is `FAILED` at the stage it hit (§6.5: "every loader task catches
     * `Throwable`"). A body, record count or response above half its `RevoktLimits` constant is a `CAP_NEAR_LIMIT` warning
     * on whatever result the sync ends with (§4), and the sync goes on.
     *
     * `UNCHANGED`-by-timestamp against a generation the snapshot holds live but the pointer does not name (an install
     * whose flip or `updater.json` failed after `activate`, #184) is not the end: the install is retried, which reuses
     * the already-written directory and flips the pointer (#137's notes from #184 and #190).
     */
    fun syncOnce(nowMillis: Long): SyncRun = Attempt(nowMillis).run()

    /** What fetching one changeset gave: its verified records, a failure to verify, or the end of the sync. */
    private sealed interface Fetched {
        class Verified(
            val verified: ChangesetVerification.Verified,
        ) : Fetched

        class Unverified(
            val failure: ChangesetVerification.Failed,
        ) : Fetched

        class Ended(
            val result: SyncResult,
        ) : Fetched
    }

    /** One sync's state: what it read, what it fetched and what the failure path writes. */
    @OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
    private inner class Attempt(
        private val now: Long,
    ) {
        private val source = client.source
        private val channel = store.channel
        private val clock = SyncClock(now, policy.clockSkewMillis, policy.rollbackWindowMillis)
        private var stage = SyncStage.STORE
        private var record = UpdaterRecord()
        private var storeFailures = 0
        private var backoff: Long? = null
        private var lastStatus: Int? = null

        private val reads = Reads()
        private val gates = Gates()

        /** The generation directory this sync staged delta files in, until an install takes it over. */
        private var staged: String? = null

        /** Set once the first body fetch starts: from there on the sync is an *install* (§6.5's order). */
        private var installing = false

        /** The result once [install] activated, flipped and wrote `updater.json`: nothing after may undo it. */
        private var done: SyncResult? = null

        @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError too.
        fun run(): SyncRun {
            val result =
                try {
                    steps()
                } catch (t: Throwable) {
                    restoreInterrupt(t)
                    thrown(t)
                }
            return SyncRun(result, storeFailures)
        }

        /**
         * The sync after [t] escaped a step. Once the install has flipped ([done]) it stays `INSTALLED` and its
         * `updater.json` stands: the throw is a store failure. Otherwise, as in [install]: a non-fatal throw at `STORE`
         * is `STORE_FAILED`, anything else `FAILED`; either counts a store failure from the first body fetch on (§6.5:
         * "an `OutOfMemoryError` during an install is `SyncOutcome.FAILED` for that sync, `storeFailures++`").
         */
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

        /**
         * [read] at stage `STORE`, so a store that throws is `STORE_FAILED` ([thrown]); the stage before is restored
         * after it returns, never on a throw.
         */
        private inline fun <T> stored(read: () -> T): T {
            val before = stage
            stage = SyncStage.STORE
            val value = read()
            stage = before
            return value
        }

        private fun steps(): SyncResult {
            stage = SyncStage.STORE
            val loaded = LoadedUpdater.of(store.updater(now))
            record = loaded.record
            storeFailures += loaded.storeFailures
            val nextAttempt = UpdaterTransitions.nextAttemptAtMillis(record, source.sourceId, now)
            if (nextAttempt != null && nextAttempt > now) return end(Ended(SyncOutcome.BACKOFF, null, null, "backoff"))
            val base = stored { reads.deltaBase() }
            stage = SyncStage.CHANGESET
            val polled = client.pollChanges()
            val expected = ok(polled) { return it }
            gates.nearCap(polled, "monitor/changes", RevoktLimits.MAX_JSON_BYTES)
            val cursor = record.sources[source.sourceId]?.lastVerifiedLastModified
            val verified =
                when (val fetched = Changesets().verified(expected, cursor?.takeIf { base != null }, base.orEmpty())) {
                    is Fetched.Verified -> fetched.verified
                    is Fetched.Unverified -> return unverified(fetched.failure)
                    is Fetched.Ended -> return fetched.result
                }
            stage = SyncStage.SCHEMA
            val crlite = ok(client.checkRecords(verified.records, channel)) { return it }
            val count = crlite.size.toLong()
            gates.nearCap(
                count,
                RevoktLimits.MAX_CHANGESET_RECORDS.toLong(),
                "records",
            ) { "$channel holds $count records" }
            return generation(verified, crlite)
        }

        /** The changeset fetches of one sync, which share one [ChangesetVerifier] (§7.1: one x5u fetch per URL per sync). */
        private inner class Changesets {
            /**
             * The changeset at [expected], verified: from [since] over [base] (the pointed generation's records) when
             * [since] is set, and once more as the whole collection when that does not verify ([ChangesetVerifier] shared,
             * so an x5u URL is fetched once per sync, §7.1); the whole collection when [since] is null.
             */
            fun verified(
                expected: Long,
                since: Long?,
                base: List<JsonObject>,
            ): Fetched {
                val signatures = ChangesetVerifier(client, verifier, now)
                val first = changeset(signatures, expected, since, base)
                // Every verification failure resets, as Firefox retries every InvalidSignatureError of an import from scratch.
                if (first !is Fetched.Unverified || since == null) return first
                backoff(first.failure.backoffMillis)
                first.failure.httpStatus?.let { lastStatus = it }
                logger.safeLog(
                    LogLevel.WARN,
                    "${source.sourceId} ${store.root}: the changeset since $since did not verify (${first.failure}); " +
                        "fetching the whole collection",
                )
                if (first.failure.stage == SyncStage.X5U) {
                    // §7.1: an x5u URL is fetched and validated once per sync, so the retry reuses this failure.
                    logger.safeLog(
                        LogLevel.WARN,
                        "${source.sourceId} ${store.root}: the retry reuses this sync's failed x5u result; it fails " +
                            "the same way when the whole collection names the same x5u",
                    )
                }
                return changeset(signatures, expected, null, emptyList())
            }

            /** One changeset at [expected] from [since] (null: the whole collection), verified over [base] merged with it. */
            private fun changeset(
                signatures: ChangesetVerifier,
                expected: Long,
                since: Long?,
                base: List<JsonObject>,
            ): Fetched {
                stage = SyncStage.CHANGESET
                val fetched = client.fetchChangeset(expected, since)
                if (fetched is ClientResult.Unchanged) {
                    backoff(fetched.backoffMillis)
                    lastStatus = fetched.httpStatus
                    return Fetched.Ended(
                        end(Ended(SyncOutcome.UNCHANGED, null, null, "304: the collection is at $since")),
                    )
                }
                val changeset = ok(fetched) { return Fetched.Ended(it) }
                gates.nearCap(fetched, "the changeset", RevoktLimits.MAX_JSON_BYTES)
                stage = SyncStage.SIGNATURE
                val merged = ContentSignature.merge(base, changeset.changes) ?: changeset.changes
                return when (val verification = signatures.verify(changeset, merged)) {
                    is ChangesetVerification.Verified -> {
                        backoff(verification.backoffMillis)
                        val x5u = verification.x5uBody.size.toLong()
                        gates.nearCap(x5u, RevoktLimits.MAX_X5U_BYTES, "x5u") { "the x5u is $x5u bytes" }
                        Fetched.Verified(verification)
                    }

                    is ChangesetVerification.Failed -> {
                        Fetched.Unverified(verification)
                    }
                }
            }
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
            val live = reads.liveGeneration()
            var ruled = live
            var admitted = SyncRules.admit(ts, record.watermarkMillis, ruled, clock)
            if (admitted == SyncDecision.UNCHANGED && live != null && !reads.pointed(live)) {
                // The live generation's install activated but its flip did not land: retry it, never stop (#190).
                ruled = null
                admitted = SyncRules.admit(ts, record.watermarkMillis, null, clock)
            }
            decided(admitted, ts)?.let { return it }
            return fetched(verified, crlite, records, placed, ruled)
        }

        /**
         * Steps 7 to 10 for the [placed] filters of [records] (the channel's [crlite] records), decided against
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
            val full = attachments.single { !it.incremental }
            val reuse = stored { store.blob(full.attachment.sha256) } == BlobState.MATCH
            gates.cap(attachments)?.let { return it }
            if (!reuse) gates.deferred()?.let { return it }
            installing = true
            val generationId = "$ts/${placed.last().record.id}"
            val bodies = Bodies(GenerationNames.directory(ts, generationId))
            bodies.open()?.let { return it }
            for (r in attachments) bodies.fetch(r, reuse)?.let { return it }
            stage = SyncStage.INDEX
            val built =
                when (val build = buildIndex(records, channel) { bodies.bytes(byId.getValue(it.id)) }) {
                    is IndexBuild.Built -> build
                    is IndexBuild.Refused -> return refused(build)
                }
            val decision = SyncRules.decide(ts, record.watermarkMillis, ruled, built.coverageHighs, clock)
            decided(decision, ts)?.let { return it }
            stage = SyncStage.PREPARE
            bodies.unlisted(placed)?.let { filter ->
                val detail = "${filter.record.id} is in an encoding the engine does not list (${engine.formats})"
                return end(Ended(SyncOutcome.FAILED, SyncStage.PREPARE, DiagnosticCode.FORMAT_UNSUPPORTED, detail))
            }
            val pending = pending(verified, generationId, built, bodies, bodies.format(placed))
            return installed(pending, decision == SyncDecision.INSTALL_CLOCK_BEHIND)
        }

        /**
         * The generation to install: id [generationId], `"<ts>/<last placed record id>"` (spec §4
         * `DataState.generationId`), its `meta.json`, [built]'s index, the staged deltas and `records.json`, the verified
         * payload without its prefix.
         */
        private fun pending(
            verified: ChangesetVerification.Verified,
            generationId: String,
            built: IndexBuild.Built,
            bodies: Bodies,
            format: FilterFormat,
        ): PendingGeneration {
            val ts = verified.timestamp
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
                    clockSkewMillis = policy.clockSkewMillis,
                )
            return when (val result = install(pending, engine, store, snapshot, publication, updated, logger)) {
                is InstallResult.Installed -> {
                    staged = null
                    storeFailures += result.storeFailures
                    val warnings =
                        if (clockBehind) {
                            listOf(warning(DiagnosticCode.CLOCK_BEHIND, "installed $ts, beyond now $now + clockSkew"))
                        } else {
                            emptyList()
                        }
                    val installed =
                        result(SyncOutcome.INSTALLED, null, warnings, mapOf(Dataset.CRLITE to result.generationId))
                    done = installed
                    reads.prune(result.directory)
                    installed
                }

                is InstallResult.Failed -> {
                    // An activated generation's directory is live in the engine: it stays for the retried flip (#184).
                    if (result.activated) staged = null
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
         * The checks on sizes and the network before and around the bodies: the cap and the half-cap warnings (§4, §5.1
         * limits) and the metered deferral (§7.2).
         */
        private inner class Gates {
            /** The `CAP_NEAR_LIMIT` warnings of this sync (§4), on whatever result it ends with. */
            val nearCaps = ArrayList<PolicyDiagnostic>()

            /** The items [nearCaps] warns about. */
            private val warned = HashSet<String>()

            /**
             * Spec §5.1's cap over [attachments], every placed record's, before any body is fetched: a signed record
             * declaring more than `MAX_FILTER_BYTES` is `FAILED` with `CAP_NEAR_LIMIT` at `ATTACHMENT`, or null. Otherwise
             * each declared size above half of `MAX_FILTER_BYTES` is a `CAP_NEAR_LIMIT` warning (§4: "the signed size
             * notwithstanding"), a reused full's included.
             */
            fun cap(attachments: List<CrliteRecord>): SyncResult? {
                val max = client.limits.maxFilterBytes
                attachments.firstOrNull { it.attachment.size > max }?.let { over ->
                    val detail = "${over.id}: ${over.attachment.size} bytes declared, cap $max"
                    return end(Ended(SyncOutcome.FAILED, SyncStage.ATTACHMENT, DiagnosticCode.CAP_NEAR_LIMIT, detail))
                }
                for (r in attachments) {
                    nearCap(
                        r.attachment.size,
                        RevoktLimits.MAX_FILTER_BYTES,
                        r.id,
                    ) { "${r.id}: ${r.attachment.size} bytes" }
                }
                return null
            }

            /**
             * §7.2's metered deferral of a full download, or null: `DEFERRED` with `METERED_DEFERRED` while the dataset's
             * live generation is not past `staleAfter` and [meteredNetwork], sampled here once, reports true. A dataset with
             * no data always downloads ("missing data always downloads"), and so does one whose policy has no
             * `staleAfter`.
             */
            fun deferred(): SyncResult? {
                val live = reads.liveGeneration() ?: return null
                val staleAfter = policy.staleAfterMillis ?: return null
                if (now > saturatingAdd(live.sourceTimestampMillis, staleAfter) || !metered()) return null
                val detail = "a full download on a metered network, while ${live.sourceTimestampMillis} is fresh"
                return end(Ended(SyncOutcome.DEFERRED, null, DiagnosticCode.METERED_DEFERRED, detail))
            }

            /** [meteredNetwork], a throw read as false (§4); a fatal error is rethrown, to [run]'s catch. */
            @Suppress("TooGenericExceptionCaught") // §4: a throwing meteredNetwork reads as false.
            private fun metered(): Boolean =
                try {
                    meteredNetwork()
                } catch (t: Throwable) {
                    absorb(t)
                    logger.safeLog(LogLevel.WARN, "${source.sourceId}: meteredNetwork threw; read as false", t)
                    false
                }

            /** A `CAP_NEAR_LIMIT` warning for [what]'s body when [result] read one above half of [cap] (§4). */
            fun nearCap(
                result: ClientResult<*>,
                what: String,
                cap: Long,
            ) {
                val size = (result as? ClientResult.Ok)?.bodyBytes ?: return
                nearCap(size, cap, what) { "$what is $size bytes" }
            }

            /**
             * A `CAP_NEAR_LIMIT` warning when [value] is above half of [cap], the `RevoktLimits` constant (§4), once per
             * [item] per sync: a reset that fetches the changeset twice warns about it once.
             */
            fun nearCap(
                value: Long,
                cap: Long,
                item: String,
                what: () -> String,
            ) {
                if (value > cap / 2 && warned.add(item)) {
                    nearCaps += warning(DiagnosticCode.CAP_NEAR_LIMIT, "${what()}, above half of $cap")
                }
            }
        }

        /**
         * The bodies of one generation in [directory], fetched one at a time and written as each arrives: a full as its
         * blob, a delta as a file staged in [directory] (§6.5: "write …, drop the body"). Neither stays here.
         */
        private inner class Bodies(
            private val directory: String,
        ) {
            val blobs = LinkedHashMap<String, ByteString>()
            val deltas = LinkedHashMap<String, ByteString>()
            private val encodings = HashMap<String, Encoding?>()

            /** Whether [directory] is a complete generation the engine holds live or the pointer names, read as it stands. */
            private var held = false

            /** The live and pointed generations' directories, which a delta of the same name and hash is copied from. */
            private var pointed: List<String> = emptyList()

            /**
             * Readies [directory]. One the engine holds live or the pointer names is never written: a complete one is read
             * as it stands ([install] then compares it with this generation), and one that is not complete fails the sync
             * as [install] would, `STORE_FAILED`. Any other is referenced by nothing, so it is completed afresh: its
             * `meta.json` is deleted ([StoreLayout.reopen]), each of its files is reused only when it re-hashes to a
             * placed delta, and [install] deletes the rest, so neither a corrupted delta nor another generation's
             * `meta.json` or `index.bin` there fails every sync of this `<ts>` (the #205 review). The failure that ends
             * the sync, or null.
             */
            fun open(): SyncResult? {
                val pointer = stored { (store.pointer() as? StoreRead.Found)?.value }
                val live = reads.liveDirectory()
                val holders = listOfNotNull(live, pointer?.live, pointer?.previous).distinct()
                pointed = holders.filter { it != directory }
                if (directory in holders) {
                    held = stored { store.readMeta(directory) } is StoreRead.Found
                    if (held) return null
                    return storeFailed("$directory is live or pointed to, and its meta.json is not readable")
                }
                staged = directory
                stored { store.reopen(directory) }
                return null
            }

            /**
             * Fetches [r]'s body and writes it, or for a [reuse]d full only names its stored blob; the failure that ends
             * the sync, or null. A delta is read from a held [directory]; otherwise it is kept when [directory] already
             * holds it re-hashing, else copied from a pointed generation's file of its name that re-hashes to its signed
             * hash, else fetched, and staged in [directory].
             */
            fun fetch(
                r: CrliteRecord,
                reuse: Boolean,
            ): SyncResult? {
                val name = GenerationNames.derive(r.attachment.filename)
                val sha256 = r.attachment.sha256
                if (!r.incremental) {
                    if (!reuse) {
                        val bytes = ok(client.fetchAttachment(r)) { return it }.toByteArray()
                        if (stored { store.putBlob(bytes) } == BlobWrite.REWRITTEN) storeFailures++
                    }
                    blobs[name] = sha256
                    return null
                }
                deltas[name] = sha256
                // #201: a stored delta is re-hashed against its signed record before it is reused.
                if (stored { store.file(directory, name, sha256) } != null) return null
                if (held) return storeFailed("$directory holds another generation: $name does not re-hash")
                val bytes =
                    stored { pointed.firstNotNullOfOrNull { store.file(it, name, sha256) } }
                        ?: ok(client.fetchAttachment(r)) { return it }.toByteArray()
                stored { store.stageFile(directory, name, bytes) }
                return null
            }

            /**
             * [r]'s body for [buildIndex], which reads each once: a delta's from [directory], a full's from its blob, each
             * re-hashed. Its encoding is noted for [format] and [unlisted].
             */
            fun bytes(r: CrliteRecord): ByteArray {
                val sha256 = r.attachment.sha256
                val bytes =
                    stored {
                        if (r.incremental) {
                            val name = GenerationNames.derive(r.attachment.filename)
                            checkNotNull(store.file(directory, name, sha256)) { "$directory/$name is gone" }
                        } else {
                            checkNotNull(store.readBlob(sha256)) { "the blob of ${r.id} is gone" }
                        }
                    }
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

        /** What this sync reads of the store and the snapshot beyond `updater.json`, and the prune after an install. */
        private inner class Reads {
            /**
             * The pointed generation's verified records, which a `_since` changeset is merged with (spec §6.5: "so a `_since`
             * changeset can be verified against it (tombstones merged) without a full re-fetch"), or null when there is none
             * to merge with: no pointer, no complete `SIGNED` generation, or a `records.json` that does not read.
             *
             * Only the last counts a store failure here: it is the one store fault no other step of the sync reads. A
             * malformed pointer, or a pointed `meta.json` that is malformed, is counted by the install when it reads the
             * pointer for its new `previous` (`Install.previous`), so counting it here too would count it twice; and a
             * pointed generation that is not `SIGNED` is not a fault (a mirror's has no `records.json`).
             */
            fun deltaBase(): List<JsonObject>? {
                val live = (store.pointer() as? StoreRead.Found)?.value?.live ?: return null
                if (store.meta(live)?.trustClass != TrustClass.SIGNED) return null
                val records = store.file(live, StoreLayout.RECORDS)?.let(::recordsOf)
                if (records == null) {
                    storeFailures++
                    logger.safeLog(LogLevel.WARN, "${store.root}: $live/records.json does not read; fetching in full")
                }
                return records
            }

            /** The records under `data` of a `records.json`, or null when it is not one. */
            private fun recordsOf(bytes: ByteArray): List<JsonObject>? {
                val root =
                    try {
                        Json.parse(bytes, client.limits.maxJsonBytes) as? JsonObject
                    } catch (ignored: JsonParseException) {
                        null
                    }
                return (root?.get("data") as? JsonArray)?.items?.map { it as? JsonObject ?: return null }
            }

            /** The dataset's live generation as the snapshot publishes it, for [SyncRules]; null when it has none. */
            fun liveGeneration(): LiveGeneration? {
                val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
                val trustClass = live.trustClass ?: return null
                val timestamp = live.sourceTimestampMillis ?: return null
                return LiveGeneration(trustClass, timestamp, live.maxCoverageMillis)
            }

            /** The directory of the generation the snapshot publishes live, or null. */
            fun liveDirectory(): String? {
                val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
                val id = live.generationId ?: return null
                return live.sourceTimestampMillis?.let { GenerationNames.directory(it, id) }
            }

            /** Whether the pointer names [live]'s directory as `live`. */
            fun pointed(live: LiveGeneration): Boolean {
                val id = snapshot.snapshot.datasets[Dataset.CRLITE]?.generationId ?: return false
                val directory = GenerationNames.directory(live.sourceTimestampMillis, id)
                return (stored { store.pointer() } as? StoreRead.Found)?.value?.live == directory
            }

            /**
             * Prunes the store to the directories the pointer names, after the install of [installed]; a failure is a store
             * failure, never the sync's. When the pointer does not read back as [installed] (a storage that breaks
             * read-after-write), nothing is deleted: a store failure and a warning, never "delete everything".
             */
            @Suppress("TooGenericExceptionCaught") // §6.5: the loader catches every throwable.
            fun prune(installed: String) {
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
                    // A fetcher's fatal error during the body phase is an OutOfMemoryError during an install (§6.5).
                    if (installing && result.cause?.let(::isFatal) == true) storeFailures++
                    failed(
                        end(Ended(SyncOutcome.FAILED, result.stage, result.code, result.detail, cause = result.cause)),
                    )
                }

                // Only the conditional changeset fetch answers Unchanged, and [changeset] reads that one itself.
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

        /** `STORE_FAILED` at `STORE` for a directory that cannot be this generation, as [install] fails it. */
        private fun storeFailed(detail: String): SyncResult {
            storeFailures++
            return end(Ended(SyncOutcome.STORE_FAILED, SyncStage.STORE, null, detail, IllegalStateException(detail)))
        }

        private fun backoff(millis: Long?) {
            if (millis != null) backoff = maxOf(backoff ?: millis, millis)
        }

        /**
         * Ends the sync as [ended] without an install: deletes the directory this sync staged, then writes
         * `updater.json` ([UpdaterTransitions.after]; a delete or write that fails is a store failure and leaves the
         * outcome), then the result.
         */
        @Suppress("TooGenericExceptionCaught") // §6.5: the failure path catches every throwable too.
        private fun end(ended: Ended): SyncResult {
            staged?.let {
                staged = null
                try {
                    store.deleteGeneration(it)
                } catch (t: Throwable) {
                    restoreInterrupt(t)
                    storeFailures++
                    logger.safeLog(LogLevel.WARN, "deleting ${store.root}/$it failed", t)
                }
            }
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
                .warnings(warnings + gates.nearCaps)
                .build()
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

    /** How a sync that installs nothing ended: [outcome] at [stage], with the diagnostic [code] beyond `SYNC_FAILED`. */
    private class Ended(
        val outcome: SyncOutcome,
        val stage: SyncStage?,
        val code: DiagnosticCode?,
        val detail: String,
        val cause: Throwable? = null,
    )
}
