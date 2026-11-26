// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// detekt 1.23 resolves types with a Kotlin 2.0 compiler that cannot read the 2.4 stdlib's metadata, so it reports the code
// after an inline lambda's non-local return or `Nothing` call as unreachable; kotlinc's own unreachable-code check holds.
@file:Suppress("UnreachableCode")

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.LogLevel
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktWarning
import dev.revokt.SignatureVerifier
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.SyncResult
import dev.revokt.WarningCode
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.clubcard.port.Encoding
import dev.revokt.engine.fetch.ChangesetVerification
import dev.revokt.engine.fetch.ChangesetVerifier
import dev.revokt.engine.fetch.ClientResult
import dev.revokt.engine.fetch.CrliteRecord
import dev.revokt.engine.fetch.RemoteSettingsClient
import dev.revokt.engine.fetch.resets
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.store.BlobState
import dev.revokt.engine.store.BlobWrite
import dev.revokt.engine.store.GenerationFile
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

/**
 * One sync's [result], what it added to `storeFailures` (spec §6.5), for the loader to count, and the `updater.json`
 * record it wrote ([updater]; null when it wrote none: its read or its write threw), which the schedule reads the
 * source's `backoffUntilMillis` and the seed `STALE` gate from (#147), so it never reads the store again.
 */
internal class SyncRun(
    val result: SyncResult,
    val storeFailures: Int,
    val updater: UpdaterRecord? = null,
) {
    override fun toString(): String = "SyncRun($result, storeFailures=$storeFailures, updater=$updater)"
}

/**
 * The CRLite updater for one Remote Settings source, dataset and channel (spec §11's 0.2 row: "CRLite updater and the
 * updater record over `RevoktStorage.inMemory()`"): [syncOnce] syncs one generation, from the cursor when the store holds
 * one (#141) and the whole collection otherwise (#137). The schedule is the loader's (#147), which runs [syncOnce] on its
 * dispatcher, never two at once.
 *
 * [client] is the source's client for `CRLITE`, [store] the dataset and channel's layout over the store, [snapshot] the
 * published snapshot this sync reads the live generation from and publishes to, and [verifier] the content-signature
 * and x5u-chain verifier. No step reads a policy value: the sync rules compare signed timestamps only (§7.1).
 */
@OptIn(dev.revokt.RevoktInternalApi::class)
internal class CrliteSync(
    private val client: RemoteSettingsClient,
    private val store: StoreLayout,
    private val engine: RevocationEngine,
    private val snapshot: SnapshotRef,
    private val verifier: SignatureVerifier,
    private val logger: RevoktLogger,
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
     * 1. Under the source's persisted backoff (`backoffUntilMillis` after now) → `SKIPPED` (`BACKOFF`), the attempt
     *    fields written.
     * 2. Poll `monitor/changes`, then fetch the collection's changeset at its `_expected`: from the served generation's
     *    own `<ts>` (`_since=<ts>`) when its file loads (spec §6.5 Load), that `<ts>` is the live generation's and the
     *    pointer names it, else the whole collection; `If-None-Match: "<ts>"` goes beside it only while `updater.json`
     *    is not behind `<ts>`, so a 304, which is `UNCHANGED`, never stands in for the repair (§7.1).
     * 3. Verify it ([ChangesetVerifier]) over the stored records with its changes merged, tombstones first
     *    ([ContentSignature.merge]); everything after reads only the verified records and `<ts>`
     *    ([ChangesetVerification.Verified]), never the changeset's `changes`. A `_since` changeset whose changes do not
     *    merge, or whose signature fails as Firefox's `InvalidSignatureError` does ([SyncFailure.resets]), is
     *    fetched once more as the whole collection, which must verify (§7.1 "reset-and-retry once"); any other failure
     *    ends the sync.
     * 4. The schema check and the channel filter ([RemoteSettingsClient.checkRecords]): `SCHEMA_REJECTED`.
     * 5. The generation's records and names ([placeFilters]): not exactly one full, or two attachments that map to one
     *    name, is `INDEX_INCONSISTENT` before any body is fetched.
     * 6. The rollback guard before any body ([SyncRules.decide]): `UNCHANGED`, `SKIPPED` (`ROLLBACK_REFUSED`), or on.
     * 7. The cap before any body: a signed record over `MAX_FILTER_BYTES` is `ATTACHMENT_OVER_CAP`, and nothing is
     *    fetched. There is no per-sync total, as neither Firefox nor upki has one (the maintainer's decision on #137;
     *    `MAX_SYNC_BYTES` is dropped).
     * 8. Each body, one at a time, full or delta: reused without a fetch when its blob is stored and re-hashes (§6.5,
     *    #201), as Firefox and upki reuse a filter on disk whose hash matches; otherwise fetched, checked against its
     *    signed size and hash and written as its blob (a stored blob that did not re-hash is rewritten,
     *    `storeFailures++`).
     * 9. [buildIndex], then [install] in §6.5's order, which writes `updater.json` after the pointer flip; on success
     *    the store is pruned ([pruneAfter]) when the pointer read `Found` before the install with every generation it
     *    named reading, which a flip that healed a malformed pointer never does (#256).
     *
     * Every outcome but `INSTALLED` writes `updater.json` itself ([UpdaterTransitions.after]), and none deletes anything:
     * a failed install's blobs and generation file are reused by the next attempt. The cursor, `lastVerified*` and the
     * watermark advance only through an install, or through a repair at the live generation's `<ts>`: the re-flip, the
     * heal-install, or an `UNCHANGED` whose `updater.json` was behind it (spec §6.5). Every throwable is
     * caught, an `OutOfMemoryError` included: `STORE_FAILED` for a non-fatal one in a store access, else
     * `INTERNAL_ERROR` (§6.5: "every loader task catches `Throwable`"). A body, record count or response above half its
     * `RevoktLimits` constant is a `CAP_NEAR_LIMIT` warning on whatever result the sync ends with (§4), and the sync
     * goes on.
     *
     * `UNCHANGED`-by-timestamp against a generation the snapshot holds live but the pointer does not name as `live` (an
     * install whose flip or `updater.json` failed after `activate`, #184, or a pointer that does not read) is not the
     * end: spec §6.5's re-flip points `current` at the served file, once it and its blobs pass Load's steps 1 to 3, and
     * writes `updater.json` as the install of that `<ts>` would, with no fetch, no `prepare` and no prune ([reflip]).
     * When the served file does not pass, the heal-install installs the collection as served, every stored blob that
     * re-hashes reused. Both are store repairs: the sync stays `UNCHANGED`, as the served generation does not change,
     * and neither is pruned after (#137's notes from #184 and #190).
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

        /** A `_since` changeset whose changes do not merge with the stored records ([ContentSignature.merge] is null). */
        object Unmergeable : Fetched

        class Ended(
            val result: SyncResult,
        ) : Fetched
    }

    /** One sync's state: what it read, what it fetched and what the failure path writes. */
    @OptIn(RevoktInternalApi::class)
    private inner class Attempt(
        private val now: Long,
    ) {
        private val source = client.source
        private val channel = store.channel

        /** Whether a throw now is in a store access, `STORE_FAILED` unless fatal ([thrown]); else `INTERNAL_ERROR`. */
        private var storing = true

        /**
         * The `updater.json` this sync read; null until the read returns, and while it is null nothing writes
         * `updater.json`, so a read that throws never has an empty record written over the real file (#209: that would
         * drop the watermark, `seedInstalledAtMillis` and every source's cursor, `lastVerified*` and backoff).
         */
        private var read: UpdaterRecord? = null

        /** The record read, for every step after the read. */
        private val record: UpdaterRecord get() = checkNotNull(read) { "updater.json is read first" }
        private var storeFailures = 0
        private var backoff: Long? = null
        private var lastStatus: Int? = null

        private val reads = Reads()
        private val gates = Gates()

        /** Set once the first body fetch starts: from there on the sync is an *install* (§6.5's order). */
        private var installing = false

        /** The result once [install] activated, flipped and wrote `updater.json`: nothing after may undo it. */
        private var done: SyncResult? = null

        /** The `updater.json` record this sync wrote, once a write of it returned ([SyncRun.updater]). */
        private var written: UpdaterRecord? = null

        @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError too.
        fun run(): SyncRun {
            val result =
                try {
                    steps()
                } catch (t: Throwable) {
                    restoreInterrupt(t)
                    thrown(t)
                }
            return SyncRun(result, storeFailures, written)
        }

        /**
         * The sync after [t] escaped a step. Once the install has flipped ([done]) it stays `INSTALLED` and its
         * `updater.json` stands: the throw is a store failure. Otherwise, as in [install]: a non-fatal throw in a store
         * access is `STORE_FAILED`, anything else `INTERNAL_ERROR`; either counts a store failure from the first body
         * fetch on (§6.5: "an `OutOfMemoryError` during an install is `SyncOutcome.FAILED` for that sync,
         * `storeFailures++`").
         */
        private fun thrown(t: Throwable): SyncResult {
            done?.let {
                storeFailures++
                logger.safeLog(LogLevel.WARN, "${source.sourceId} ${store.root}: threw after the install", t)
                return it
            }
            val storeFailure = storing && !isFatal(t)
            if (storeFailure || installing) storeFailures++
            val failure = if (storeFailure) SyncFailure.STORE_FAILED else SyncFailure.INTERNAL_ERROR
            return end(Ended(failure, "the sync threw", cause = t))
        }

        /**
         * [access] as a store access, so a store that throws is `STORE_FAILED` ([thrown]); [storing] is restored after
         * it returns, never on a throw.
         */
        private inline fun <T> stored(access: () -> T): T {
            val before = storing
            storing = true
            val value = access()
            storing = before
            return value
        }

        private fun steps(): SyncResult {
            val loaded = LoadedUpdater.of(store.updater(now))
            read = loaded.record
            storeFailures += loaded.storeFailures
            val nextAttempt = UpdaterTransitions.nextAttemptAtMillis(record, source.sourceId, now)
            if (nextAttempt != null && nextAttempt > now) return end(Ended(SyncFailure.BACKOFF, "backoff"))
            val base = stored { reads.deltaBase() }
            storing = false
            val polled = client.pollChanges()
            val expected = ok(polled) { return it }
            gates.nearCap(polled, "monitor/changes", RevoktLimits.MAX_JSON_BYTES)
            // _since is the served file's own <ts>, from the same read as the merge base, as Firefox's `_since` is its
            // local data's own timestamp (§7.1): never the updater.json cursor, so after a fallback (the seed, or
            // `previous`, live while the cursor names a newer generation) a 304 speaks for the generation served. It is
            // sent only while that <ts> is the live generation's and the pointer names the file: beside a pointer that
            // does not (a flip that failed or a malformed pointer) the whole collection is fetched, and its UNCHANGED
            // re-flips or heal-installs. The whole collection merges over nothing (#236).
            val since = base?.lastModified?.takeIf { it == reads.liveTimestamp() && reads.pointed() }
            val merged = if (since != null) base.records else emptyList()
            // If-None-Match only while updater.json is not behind: behind it, the changeset since <ts> verifies and the
            // UNCHANGED writes the repair (§6.5), which an unsigned 304 must never stand in for.
            val conditional = since != null && !reads.behind(since)
            val verified =
                when (val fetched = Changesets().verified(expected, since, conditional, merged)) {
                    is Fetched.Verified -> fetched.verified
                    is Fetched.Unverified -> return unverified(fetched.failure)
                    is Fetched.Ended -> return fetched.result
                    Fetched.Unmergeable -> error("only a _since changeset is unmergeable, and it is fetched again")
                }
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
             * The changeset at [expected], verified: from [since] over [base] (the served generation's records) when
             * [since] is set, with `If-None-Match` when [conditional], and the whole collection when it is null. A `_since`
             * changeset is fetched once more as the
             * whole collection when its changes do not merge with [base] or its signature fails with a failure that
             * [SignatureFailure.resets] (§7.1, Firefox's retry of an `InvalidSignatureError`); never on an x5u failure,
             * which the shared [ChangesetVerifier] would reuse (one x5u result per URL per sync, §7.1).
             */
            fun verified(
                expected: Long,
                since: Long?,
                conditional: Boolean,
                base: List<JsonObject>,
            ): Fetched {
                val signatures = ChangesetVerifier(client, verifier, now)
                val first = changeset(signatures, expected, since, conditional, base)
                val why =
                    when {
                        since == null -> {
                            return first
                        }

                        first == Fetched.Unmergeable -> {
                            "its changes do not merge with the stored records"
                        }

                        first is Fetched.Unverified && first.failure.failure.resets -> {
                            // Only an x5u fetch failure carries an HTTP status, and it never resets.
                            backoff(first.failure.backoffMillis)
                            "it did not verify (${first.failure})"
                        }

                        else -> {
                            return first
                        }
                    }
                logger.safeLog(
                    LogLevel.WARN,
                    "${source.sourceId} ${store.root}: the changeset since $since: $why; fetching the whole collection",
                )
                return changeset(signatures, expected, null, conditional = false, base = emptyList())
            }

            /**
             * One changeset at [expected] from [since] (null: the whole collection), `If-None-Match` when [conditional],
             * verified over [base] merged with it;
             * [Fetched.Unmergeable] when [since] is set and its changes do not merge. The whole collection merges over
             * nothing, and when even that is null (a record with no string `id`), its changes are verified as served.
             */
            private fun changeset(
                signatures: ChangesetVerifier,
                expected: Long,
                since: Long?,
                conditional: Boolean,
                base: List<JsonObject>,
            ): Fetched {
                val fetched = client.fetchChangeset(expected, since, ifNoneMatch = conditional)
                if (fetched is ClientResult.Unchanged) {
                    backoff(fetched.backoffMillis)
                    lastStatus = fetched.httpStatus
                    return Fetched.Ended(
                        end(Ended(null, "304: the collection is at $since")),
                    )
                }
                val changeset = ok(fetched) { return Fetched.Ended(it) }
                gates.nearCap(fetched, "the changeset", RevoktLimits.MAX_JSON_BYTES)
                val merged = ContentSignature.merge(base, changeset.changes)
                if (merged == null && since != null) return Fetched.Unmergeable
                return when (val verification = signatures.verify(changeset, merged ?: changeset.changes)) {
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
            val records = crlite.map { it.toFilterRecord() }
            val placed =
                when (val placement = placeFilters(records, channel)) {
                    is Placement.Placed -> placement.filters
                    is IndexBuild.Refused -> return refused(placement)
                }
            val live = reads.liveTimestamp()
            val decision = SyncRules.decide(ts, record.watermarkMillis, live)
            // The live generation's install activated but its flip did not land: retry it, never stop (#190).
            // Never back: a pointer whose live is newer than the served generation and reads is left alone (#335 review).
            val reflip = decision == SyncDecision.UNCHANGED && !reads.pointed() && !reads.newerLive(ts)
            if (!reflip) decided(decision, ts)?.let { return it }
            if (reflip) reflipped(ts)?.let { return it }
            return fetched(verified, crlite, records, placed, noneLoaded = live == null, repair = reflip)
        }

        /**
         * Spec §6.5's re-flip of the served generation at [ts], or null when its file or a blob does not pass Load's
         * steps 1 to 3, so the collection is installed instead (the heal-install). A file that fails steps 1 and 2 was
         * counted by [Reads.deltaBase]; a failed step 3 is counted here: each once.
         */
        private fun reflipped(ts: Long): SyncResult? {
            val served = snapshot.servedFile() ?: return null
            val stored = (stored { store.stored(served) } as? StoreRead.Found)?.value ?: return null
            val generationId = snapshot.snapshot.datasets[Dataset.CRLITE]?.generationId
            if (stored.generationId != generationId || stored.timestampMillis != ts) return null
            if (!stored { store.blobsMatch(stored) }) {
                // Step 3 failed: a failed load, counted once, here; the heal-install's rewrite of its blobs is not
                // counted again, and neither is its read of the served file as a candidate (#335 review).
                reads.count(served)
                reads.countedBlobs += stored.blobNames
                return null
            }
            return installed(ts, noneLoaded = false, repair = true) { publication, updated ->
                reflip(stored, store, snapshot, publication, updated)
            }
        }

        /**
         * Steps 7 to 9 for the [placed] filters of [records] (the channel's [crlite] records); [noneLoaded] when no
         * generation was live at the decision, so the install sets the watermark to `<ts>` (§7.1); [repair] for the
         * heal-install of the served generation (spec §6.5), which stays `UNCHANGED` and is never pruned after.
         */
        private fun fetched(
            verified: ChangesetVerification.Verified,
            crlite: List<CrliteRecord>,
            records: List<FilterRecord>,
            placed: List<PlacedFilter>,
            noneLoaded: Boolean,
            repair: Boolean,
        ): SyncResult {
            val ts = verified.timestamp
            val byId = crlite.associateBy { it.id }
            val attachments = placed.map { byId.getValue(it.record.id) }
            gates.cap(attachments)?.let { return it }
            installing = true
            val bodies = Bodies()
            for (r in attachments) bodies.fetch(r)?.let { return it }
            val built =
                when (val build = buildIndex(records, channel) { bodies.bytes(byId.getValue(it.id)) }) {
                    is IndexBuild.Built -> build
                    is IndexBuild.Refused -> return refused(build)
                }
            bodies.unlisted(placed)?.let { filter ->
                val detail = "${filter.record.id} is in an encoding the engine does not list (${engine.formats})"
                return end(Ended(SyncFailure.FORMAT_UNSUPPORTED, detail))
            }
            val pending = pending(verified, built, bodies.format(placed))
            return installed(pending, noneLoaded, repair)
        }

        /**
         * The generation to install: its generation file (spec §6.5), the verified payload's records and `<ts>` with the
         * signature that verified them and its leaf's SHA-256, and [built]'s index and placed filters. Its id,
         * `"<ts>/<last placed record id>"` (spec §4 `DataState.generationId`), is derived from them.
         */
        private fun pending(
            verified: ChangesetVerification.Verified,
            built: IndexBuild.Built,
            format: FilterFormat,
        ): PendingGeneration {
            val raw = checkNotNull(verified.entry.signature?.let(RawSignature::decode)) { "a verified signature" }
            val records = checkNotNull(ContentSignature.payloadRecords(verified.records)) { "verified records" }
            val file =
                GenerationFile(
                    dataset = Dataset.CRLITE,
                    channel = channel,
                    freshness = Freshness.RECORD_LAST_MODIFIED,
                    seedFormat = null,
                    signature = raw.toByteString(),
                    signerLeafSha256 =
                        verified.path.links[0]
                            .der
                            .toByteString()
                            .sha256(),
                    records = records,
                    lastModified = verified.timestamp,
                )
            return PendingGeneration(file, built.filters, built.index, format)
        }

        /** Runs [install] for [pending] and ends the sync with its outcome; a successful install is then pruned to. */
        private fun installed(
            pending: PendingGeneration,
            noneLoaded: Boolean,
            repair: Boolean,
        ): SyncResult =
            installed(pending.file.lastModified, noneLoaded, repair) { publication, updated ->
                install(pending, engine, store, snapshot, publication, updated, logger)
            }

        /**
         * Ends the sync with the outcome of [flip] (an install, or the re-flip) of a generation at [ts], given its
         * publication and the `updater.json` to write: `INSTALLED`, pruned to when [InstallResult.Installed.prunable];
         * for a [repair] of the served generation (the re-flip or the heal-install, spec §6.5), `UNCHANGED` and never
         * pruned to.
         */
        private inline fun installed(
            ts: Long,
            noneLoaded: Boolean,
            repair: Boolean,
            flip: (Publication, UpdaterRecord) -> InstallResult,
        ): SyncResult {
            val updated =
                UpdaterTransitions.after(
                    record,
                    source.sourceId,
                    null,
                    now,
                    ts,
                    serverBackoffMillis = backoff,
                    noneLoaded = noneLoaded,
                )
            val publication =
                Publication(
                    fromSeed = false,
                    seedFormat = null,
                    staleGateOpen = true,
                    nowMillis = now,
                    counted = reads.counted.toSet(),
                )
            return when (val result = flip(publication, updated)) {
                is InstallResult.Installed -> {
                    written = updated
                    storeFailures += result.storeFailures
                    val outcome = if (repair) SyncOutcome.UNCHANGED else SyncOutcome.INSTALLED
                    val generations = if (repair) emptyMap() else mapOf(Dataset.CRLITE to result.generationId)
                    val installed = result(outcome, null, emptyList(), generations)
                    done = installed
                    // Only over a pointer that read, every generation it named reading: never after a heal (#256) or a
                    // repair, and never beside a pointed generation that did not read (§6.5, fail closed).
                    if (result.prunable && !repair) store.pruneAfter(result.name, logger) { storeFailures++ }
                    installed
                }

                is InstallResult.Failed -> {
                    storeFailures += result.storeFailures
                    end(Ended(result.failure, "the install failed", cause = result.cause))
                }
            }
        }

        /** The sync for a changeset at [ts] that [decision] does not install, or null. */
        private fun decided(
            decision: SyncDecision,
            ts: Long,
        ): SyncResult? =
            when (decision) {
                SyncDecision.INSTALL -> null
                SyncDecision.UNCHANGED -> end(Ended(null, "$ts is live", verifiedAt = ts.takeIf(reads::behind)))
                SyncDecision.ROLLBACK_REFUSED -> end(Ended(SyncFailure.ROLLBACK_REFUSED, "$ts rolls back"))
            }

        /** The checks on sizes before and around the bodies: the cap and the half-cap warnings (§4, §5.1 limits). */
        private inner class Gates {
            /** The `CAP_NEAR_LIMIT` warnings of this sync (§4), on whatever result it ends with. */
            val nearCaps = ArrayList<RevoktWarning>()

            /** The items [nearCaps] warns about. */
            private val warned = HashSet<String>()

            /**
             * Spec §5.1's cap over [attachments], every placed record's, before any body is fetched: a signed record
             * declaring more than `MAX_FILTER_BYTES` is `ATTACHMENT_OVER_CAP`, or null. Otherwise each declared size
             * above half of `MAX_FILTER_BYTES` is a `CAP_NEAR_LIMIT` warning (§4: "the signed size notwithstanding"), a
             * reused full's included.
             */
            fun cap(attachments: List<CrliteRecord>): SyncResult? {
                val max = client.limits.maxFilterBytes
                attachments.firstOrNull { it.attachment.size > max }?.let { over ->
                    val detail = "${over.id}: ${over.attachment.size} bytes declared, cap $max"
                    return end(Ended(SyncFailure.ATTACHMENT_OVER_CAP, detail))
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
                    nearCaps += warning(WarningCode.CAP_NEAR_LIMIT, "${what()}, above half of $cap")
                }
            }
        }

        /**
         * The bodies of one generation, fetched one at a time and each written as its blob as it arrives (§6.5: "write …,
         * drop the body"); none stays here. A body whose blob is stored and re-hashes is not fetched.
         */
        private inner class Bodies {
            private val encodings = HashMap<String, Encoding?>()

            /**
             * [r]'s blob: kept without a fetch when it is stored and re-hashes (#201: every stored filter is re-hashed
             * before it is reused), else fetched and written, a rewrite of one that did not re-hash counting a store
             * failure. The failure that ends the sync, or null.
             */
            fun fetch(r: CrliteRecord): SyncResult? {
                if (stored { store.blob(r.attachment.sha256) } == BlobState.MATCH) return null
                val bytes = attachment(r) { return it }
                val write = stored { store.putBlob(bytes) }
                if (write == BlobWrite.REWRITTEN && r.attachment.sha256.hex() !in reads.countedBlobs) storeFailures++
                return null
            }

            /** [r]'s body for [buildIndex], which reads each once, from its blob, re-hashed. Its encoding is noted. */
            fun bytes(r: CrliteRecord): ByteArray {
                val bytes =
                    stored { checkNotNull(store.readBlob(r.attachment.sha256)) { "the blob of ${r.id} is gone" } }
                encodings[r.id] = encoding(bytes)
                return bytes
            }

            /**
             * The first of [placed] whose encoding [engine] does not list (spec §3.2 `FORMAT_UNSUPPORTED`; the lead's
             * decision on #137: the check covers every placed filter, a full or a delta), or null. Called after
             * [buildIndex] decoded every placed filter, so each encoding is known.
             */
            fun unlisted(placed: List<PlacedFilter>): PlacedFilter? =
                placed.firstOrNull {
                    checkNotNull(encodings[it.record.id]) { "decoded" }.toFilterFormat() !in engine.formats
                }

            /**
             * The generation's format: the full's encoding. A delta may be in another one the engine lists, and each is
             * read as served (the maintainer's decision on #137, as Firefox's `cert_storage` and upki read each filter).
             * Called after [buildIndex] decoded every placed filter.
             */
            fun format(placed: List<PlacedFilter>): FilterFormat =
                checkNotNull(encodings[placed.first { it.full }.record.id]) { "decoded" }.toFilterFormat()

            private fun encoding(bytes: ByteArray): Encoding? =
                try {
                    ClubcardFilters.encodingOf(bytes)
                } catch (ignored: ClubcardFormatException) {
                    null // buildIndex decodes every placed filter and refuses this one (FILTER_UNREADABLE).
                }
        }

        /** What this sync reads of the store and the snapshot beyond `updater.json`, and the prune after an install. */
        private inner class Reads {
            /** The generation files whose failure this sync counted, for the install ([Publication.counted]). */
            val counted = HashSet<String>()

            /** The blobs of a served generation whose step 3 failed and was counted: rewriting one counts nothing more. */
            val countedBlobs = HashSet<String>()

            /** Counts [name]'s failure, once. */
            fun count(name: String) {
                if (counted.add(name)) storeFailures++
            }

            /**
             * Whether the pointer's `live` is newer than [ts], the served generation's, and passes Load's steps 1 and 2
             * (an adopt the start task could not serve): the re-flip then leaves the pointer alone, so it never moves a
             * generation back (spec §6.5). A `live` that does not read is counted by the re-flip's own read.
             */
            fun newerLive(ts: Long): Boolean {
                val live = (stored { store.pointer() } as? StoreRead.Found)?.value?.live ?: return false
                val read = stored { store.stored(live) } as? StoreRead.Found ?: return false
                return read.value.timestampMillis > ts
            }

            /**
             * Whether `updater.json`'s cursor or watermark is behind [ts], the live generation's: an `UNCHANGED` sync then
             * writes it as the install of [ts] does (spec §6.5, the repair of a crash between a flip and its write).
             */
            fun behind(ts: Long): Boolean {
                val cursor = record.sources[source.sourceId]?.lastVerifiedLastModified
                val watermark = record.watermarkMillis
                return cursor == null || cursor < ts || watermark == null || watermark < ts
            }

            /**
             * The served generation's file, whose verified records a `_since` changeset is merged with (spec §6.5: "a
             * `_since` changeset is merged over the served generation's `records`") and whose `<ts>` is the `_since`
             * (§7.1), or null when there is none to merge with: no
             * generation served, or its file does not load through Load's steps 1 and 2. The served file is the one the
             * engine holds, which may not be the pointer's `live` after a flip that failed after activation, so the merge is
             * always over what is served, as Firefox merges over its local data.
             *
             * A served file that does not read means the sync fetches the whole collection. It counts a store failure
             * here, whatever the sync then does, and is noted in [counted] so the install's reads of the pointer's
             * generations and of its `previous` candidates do not count it again (#335 review): each fault once.
             */
            fun deltaBase(): GenerationFile? {
                val served = snapshot.servedFile() ?: return null
                val read = store.stored(served)
                if (read is StoreRead.Found) return read.value.file
                count(served)
                logger.safeLog(
                    LogLevel.WARN,
                    "${store.root}: the served generation $served does not load; fetching in full",
                )
                return null
            }

            /**
             * The `sourceTimestampMillis` of the dataset's live generation as the snapshot publishes it, for [SyncRules];
             * null when it has none (no generation loaded, §7.1: the stored watermark is then not read).
             */
            fun liveTimestamp(): Long? {
                val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
                live.generationId ?: return null
                return live.sourceTimestampMillis
            }

            /**
             * Whether the pointer names the served generation's file ([servedFile]) as `live`. Asked only for an
             * `UNCHANGED` decision, which needs a live generation; one with no stored file (none was ever written for it)
             * is never pointed to, and its install is retried.
             */
            fun pointed(): Boolean {
                val served = snapshot.servedFile() ?: return false
                return (stored { store.pointer() } as? StoreRead.Found)?.value?.live == served
            }
        }

        /** This sync's attachment base, read before its first attachment fetch ([RemoteSettingsClient.attachmentBase]). */
        private var attachmentBase: String? = null

        /** [r]'s attachment under this sync's base, which is read once; a failure of either ends the sync ([ok]). */
        private inline fun attachment(
            r: CrliteRecord,
            failed: (SyncResult) -> Nothing,
        ): ByteArray {
            val base = attachmentBase ?: ok(client.attachmentBase(), failed).also { attachmentBase = it }
            return ok(client.fetchAttachment(r, base), failed).toByteArray()
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
                    failed(end(Ended(result.failure, result.detail, cause = result.cause)))
                }

                // Only the conditional changeset fetch answers Unchanged, and [changeset] reads that one itself.
                is ClientResult.Unchanged -> {
                    failed(end(Ended(SyncFailure.INTERNAL_ERROR, "304 to an unconditional request")))
                }
            }
        }

        private fun unverified(failure: ChangesetVerification.Failed): SyncResult {
            backoff(failure.backoffMillis)
            failure.httpStatus?.let { lastStatus = it }
            return end(Ended(failure.failure, failure.detail, failure.cause))
        }

        private fun refused(refusal: IndexBuild.Refused): SyncResult =
            end(Ended(refusal.failure, refusal.detail, refusal.cause))

        private fun backoff(millis: Long?) {
            if (millis != null) backoff = maxOf(backoff ?: millis, millis)
        }

        /**
         * Ends the sync as [ended] without an install, deleting nothing: writes `updater.json`
         * ([UpdaterTransitions.after]; a write that fails is a store failure and leaves the outcome) unless its read
         * never returned (#209), then the result.
         */
        @Suppress("TooGenericExceptionCaught") // §6.5: the failure path catches every throwable too.
        private fun end(ended: Ended): SyncResult {
            try {
                // #209: a sync whose read of updater.json did not return writes nothing, leaving the file as it is.
                read?.let {
                    val next =
                        UpdaterTransitions.after(
                            it,
                            source.sourceId,
                            ended.failure,
                            now,
                            signedTimestampMillis = ended.verifiedAt,
                            serverBackoffMillis = backoff,
                        )
                    store.writeUpdater(next, now)
                    written = next
                }
            } catch (t: Throwable) {
                restoreInterrupt(t)
                storeFailures++
                logger.safeLog(LogLevel.WARN, "writing ${store.root}/updater.json failed", t)
            }
            if (ended.outcome == SyncOutcome.FAILED) {
                val message = "${ended.failure}: ${ended.detail}"
                logger.safeLog(LogLevel.WARN, "${source.sourceId} ${store.root}: $message", ended.cause)
            }
            return result(ended.outcome, ended.failure, emptyList(), emptyMap(), ended.cause)
        }

        private fun result(
            outcome: SyncOutcome,
            failure: SyncFailure?,
            warnings: List<RevoktWarning>,
            installed: Map<Dataset, String>,
            cause: Throwable? = null,
        ): SyncResult =
            SyncResult
                .Builder()
                .outcome(outcome)
                .atMillis(now)
                .installed(installed)
                .sourceId(source.sourceId)
                .failure(failure)
                .httpStatus(if (failure == SyncFailure.BACKOFF) null else lastStatus)
                .cause(cause)
                .warnings(warnings + gates.nearCaps)
                .build()
    }

    private fun warning(
        code: WarningCode,
        message: String,
    ): RevoktWarning =
        RevoktWarning
            .Builder()
            .code(code)
            .dataset(Dataset.CRLITE)
            .message("${client.source.sourceId}: $message")
            .build()

    /**
     * How a sync that installs nothing ended: `UNCHANGED` when [failure] is null, else its outcome, `SKIPPED` or
     * `FAILED`. [verifiedAt] is the `<ts>` an `UNCHANGED` sync writes `updater.json` at as its install would, when the
     * file's cursor or watermark was behind it (spec §6.5); null writes the attempt fields only.
     */
    private class Ended(
        val failure: SyncFailure?,
        val detail: String,
        val cause: Throwable? = null,
        val verifiedAt: Long? = null,
    ) {
        val outcome: SyncOutcome get() = if (failure != null) failure.outcome else SyncOutcome.UNCHANGED
    }
}
