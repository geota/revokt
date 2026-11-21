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
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.clubcard.port.Encoding
import dev.revokt.engine.fetch.ChangesetVerification
import dev.revokt.engine.fetch.ChangesetVerifier
import dev.revokt.engine.fetch.ClientResult
import dev.revokt.engine.fetch.CrliteRecord
import dev.revokt.engine.fetch.RemoteSettingsClient
import dev.revokt.engine.fetch.SignatureFailure
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
 * updater record over `RevoktStorage.inMemory()`"): [syncOnce] syncs one generation, from the cursor when the store holds
 * one (#141) and the whole collection otherwise (#137). The schedule is the loader's (#147), which runs [syncOnce] on its
 * dispatcher, never two at once.
 *
 * [client] is the source's client for `CRLITE`, [store] the dataset and channel's layout over the store, [snapshot] the
 * published snapshot this sync reads the live generation from and publishes to, and [verifier] the content-signature
 * and x5u-chain verifier. No step reads a policy value: the sync rules compare signed timestamps only (§7.1).
 */
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
     * 1. Under the source's persisted backoff (`backoffUntilMillis` after now) → `BACKOFF`, the attempt fields written.
     * 2. Poll `monitor/changes`, then fetch the collection's changeset at its `_expected`: from the cursor
     *    (`_since=<cursor>` and `If-None-Match: "<cursor>"`) when `updater.json` holds one and the pointed generation's
     *    `records.json` reads, else the whole collection. A 304 is `UNCHANGED`.
     * 3. Verify it ([ChangesetVerifier]) over the stored records with its changes merged, tombstones first
     *    ([ContentSignature.merge]); everything after reads only the verified records and `<ts>`
     *    ([ChangesetVerification.Verified]), never the changeset's `changes`. A `_since` changeset whose changes do not
     *    merge, or whose signature fails as Firefox's `InvalidSignatureError` does ([SignatureFailure.resets]), is
     *    fetched once more as the whole collection, which must verify (§7.1 "reset-and-retry once"); any other failure
     *    ends the sync.
     * 4. The schema check and the channel filter ([RemoteSettingsClient.checkRecords]): `SYNC_SCHEMA_REJECTED`.
     * 5. The generation's records and names ([placeFilters]): not exactly one full, or two attachments that map to one
     *    name, is `FAILED` with `INDEX_INCONSISTENT` at `INDEX` before any body is fetched.
     * 6. The rollback guard before any body ([SyncRules.decide]): `UNCHANGED`, `ROLLBACK_REFUSED`, or on.
     * 7. The cap before any body: a signed record over `MAX_FILTER_BYTES` is `FAILED` with `CAP_NEAR_LIMIT` at
     *    `ATTACHMENT`, and nothing is fetched. There is no per-sync total, as neither Firefox nor upki has one (the
     *    maintainer's decision on #137; `MAX_SYNC_BYTES` is dropped).
     * 8. Each body, one at a time, checked against its signed size and hash and written: a full as a blob, reused without
     *    a fetch when its blob is stored and re-hashes (§6.5; a mismatch is fetched and rewritten, `storeFailures++`); a
     *    delta staged as a file of the generation directory, copied without a fetch from a pointed generation whose file
     *    of that name re-hashes to it, as Firefox and upki reuse a filter on disk whose hash matches.
     * 9. [buildIndex], then [install] in §6.5's order, which writes `updater.json` after the pointer flip; on success
     *    the store is pruned to what the pointer names, unless the flip healed a malformed pointer (#256).
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

        /** A `_since` changeset whose changes do not merge with the stored records ([ContentSignature.merge] is null). */
        object Unmergeable : Fetched

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
        private var stage = SyncStage.STORE

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
         * [access] at stage `STORE`, so a store that throws is `STORE_FAILED` ([thrown]); the stage before is restored
         * after it returns, never on a throw.
         */
        private inline fun <T> stored(access: () -> T): T {
            val before = stage
            stage = SyncStage.STORE
            val value = access()
            stage = before
            return value
        }

        private fun steps(): SyncResult {
            stage = SyncStage.STORE
            val loaded = LoadedUpdater.of(store.updater(now))
            read = loaded.record
            storeFailures += loaded.storeFailures
            val nextAttempt = UpdaterTransitions.nextAttemptAtMillis(record, source.sourceId, now)
            if (nextAttempt != null && nextAttempt > now) return end(Ended(SyncOutcome.BACKOFF, null, null, "backoff"))
            val base = stored { reads.deltaBase() }
            stage = SyncStage.CHANGESET
            val polled = client.pollChanges()
            val expected = ok(polled) { return it }
            gates.nearCap(polled, "monitor/changes", RevoktLimits.MAX_JSON_BYTES)
            val cursor = record.sources[source.sourceId]?.lastVerifiedLastModified
            // The stored records are the merge base of a _since changeset only: the whole collection, fetched when there is
            // no cursor (an absent or malformed updater.json) or no stored records to merge with, merges over nothing (#236).
            val since = cursor?.takeIf { base != null }
            val merged = if (since != null) base.orEmpty() else emptyList()
            val verified =
                when (val fetched = Changesets().verified(expected, since, merged)) {
                    is Fetched.Verified -> fetched.verified
                    is Fetched.Unverified -> return unverified(fetched.failure)
                    is Fetched.Ended -> return fetched.result
                    Fetched.Unmergeable -> error("only a _since changeset is unmergeable, and it is fetched again")
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
             * [since] is set, and the whole collection when it is null. A `_since` changeset is fetched once more as the
             * whole collection when its changes do not merge with [base] or its signature fails with a failure that
             * [SignatureFailure.resets] (§7.1, Firefox's retry of an `InvalidSignatureError`); never on an x5u failure,
             * which the shared [ChangesetVerifier] would reuse (one x5u result per URL per sync, §7.1).
             */
            fun verified(
                expected: Long,
                since: Long?,
                base: List<JsonObject>,
            ): Fetched {
                val signatures = ChangesetVerifier(client, verifier, now)
                val first = changeset(signatures, expected, since, base)
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
                return changeset(signatures, expected, null, emptyList())
            }

            /**
             * One changeset at [expected] from [since] (null: the whole collection), verified over [base] merged with it;
             * [Fetched.Unmergeable] when [since] is set and its changes do not merge. The whole collection merges over
             * nothing, and when even that is null (a record with no string `id`), its changes are verified as served.
             */
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
            val live = reads.liveTimestamp()
            val decision = SyncRules.decide(ts, record.watermarkMillis, live)
            // The live generation's install activated but its flip did not land: retry it, never stop (#190).
            val reflip = decision == SyncDecision.UNCHANGED && !reads.pointed()
            if (!reflip) decided(decision, ts)?.let { return it }
            return fetched(verified, crlite, records, placed, noneLoaded = live == null)
        }

        /**
         * Steps 7 to 9 for the [placed] filters of [records] (the channel's [crlite] records); [noneLoaded] when no
         * generation was live at the decision, so the install sets the watermark to `<ts>` (§7.1).
         */
        private fun fetched(
            verified: ChangesetVerification.Verified,
            crlite: List<CrliteRecord>,
            records: List<FilterRecord>,
            placed: List<PlacedFilter>,
            noneLoaded: Boolean,
        ): SyncResult {
            val ts = verified.timestamp
            stage = SyncStage.ATTACHMENT
            val byId = crlite.associateBy { it.id }
            val attachments = placed.map { byId.getValue(it.record.id) }
            val full = attachments.single { !it.incremental }
            val reuse = stored { store.blob(full.attachment.sha256) } == BlobState.MATCH
            gates.cap(attachments)?.let { return it }
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
            stage = SyncStage.PREPARE
            bodies.unlisted(placed)?.let { filter ->
                val detail = "${filter.record.id} is in an encoding the engine does not list (${engine.formats})"
                return end(Ended(SyncOutcome.FAILED, SyncStage.PREPARE, DiagnosticCode.FORMAT_UNSUPPORTED, detail))
            }
            val pending = pending(verified, generationId, built, bodies, bodies.format(placed))
            return installed(pending, noneLoaded)
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
            noneLoaded: Boolean,
        ): SyncResult {
            val ts = pending.meta.sourceTimestampMillis
            val updated =
                UpdaterTransitions.after(
                    record,
                    source.sourceId,
                    SyncOutcome.INSTALLED,
                    now,
                    ts,
                    serverBackoffMillis = backoff,
                    noneLoaded = noneLoaded,
                )
            val publication = Publication(fromSeed = false, seedFormat = null, staleGateOpen = true, nowMillis = now)
            return when (val result = install(pending, engine, store, snapshot, publication, updated, logger)) {
                is InstallResult.Installed -> {
                    staged = null
                    storeFailures += result.storeFailures
                    val installed =
                        result(SyncOutcome.INSTALLED, null, emptyList(), mapOf(Dataset.CRLITE to result.generationId))
                    done = installed
                    // A heal is never pruned: the malformed pointer it replaced may have named any directory (#256).
                    if (!result.healed) reads.prune(result.directory)
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

        /** The sync for a changeset at [ts] that [decision] does not install, or null. */
        private fun decided(
            decision: SyncDecision,
            ts: Long,
        ): SyncResult? =
            when (decision) {
                SyncDecision.INSTALL -> null
                SyncDecision.UNCHANGED -> end(Ended(SyncOutcome.UNCHANGED, null, null, "$ts is live"))
                SyncDecision.ROLLBACK_REFUSED -> end(Ended(SyncOutcome.ROLLBACK_REFUSED, null, null, "$ts rolls back"))
            }

        /** The checks on sizes before and around the bodies: the cap and the half-cap warnings (§4, §5.1 limits). */
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

            /**
             * Whether [directory] is held and complete, read as it stands: the engine holds it live, the pointer names it,
             * or it sits beside a malformed pointer, which may name it (#236).
             */
            private var held = false

            /** The live and pointed generations' directories, which a delta of the same name and hash is copied from. */
            private var pointed: List<String> = emptyList()

            /**
             * Readies [directory]. A held one is never written. It is held when the engine holds it live or the pointer
             * names it, or when the pointer is malformed (it may name any directory) and [directory]'s `meta.json` is
             * present (#236, fail closed). A held directory that is complete is read as it stands, and [install] then
             * compares it with this generation. One whose `meta.json` is malformed or (when live or pointed) missing
             * fails the sync as [install] would, `STORE_FAILED`, and a new `<ts>` heals it.
             *
             * Any other directory is referenced by nothing. Beside a malformed pointer, that means one with no `meta.json`
             * at all. It is completed afresh: a complete orphan's `meta.json` is deleted ([StoreLayout.reopen]), each of
             * its files is reused only when it re-hashes to a placed delta, and [install] deletes the rest. So neither a
             * corrupted delta nor another generation's `meta.json` or `index.bin` there fails every sync of this `<ts>`
             * (the #205 review). The failure that ends the sync, or null.
             */
            fun open(): SyncResult? {
                val pointerRead = stored { store.pointer() }
                val pointer = (pointerRead as? StoreRead.Found)?.value
                val live = reads.liveDirectory()
                val holders = listOfNotNull(live, pointer?.live, pointer?.previous).distinct()
                pointed = holders.filter { it != directory }
                val metaRead = stored { store.readMeta(directory) }
                val complete = metaRead is StoreRead.Found
                // #236, fail closed: a malformed pointer may name a directory whose meta.json is present (complete, or
                // malformed as a torn write or a newer binary leaves it), so it is held, never reopened, rewritten or
                // deleted; only one with no meta.json is staged.
                if (directory in holders || (pointerRead is StoreRead.Malformed && metaRead !is StoreRead.Absent)) {
                    held = complete
                    if (held) return null
                    return storeFailed("$directory is held, and its meta.json is not readable")
                }
                // A complete orphan is reopened; an incomplete one needs nothing before its deltas are staged.
                if (complete) stored { store.reopen(directory) }
                // Only once reopen accepted it: a directory the pointer names is never deleted on a failure.
                staged = directory
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
                        val bytes = attachment(r) { return it }
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
                        ?: attachment(r) { return it }
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
             * to merge with: no pointer, no complete generation, or a `records.json` that does not read.
             *
             * Only the last counts a store failure here: it is the one store fault no other step of the sync reads. A
             * malformed pointer, or a pointed `meta.json` that is malformed, is counted by the install when it reads the
             * pointer for its new `previous` (`Install.previous`), so counting it here too would count it twice.
             */
            fun deltaBase(): List<JsonObject>? {
                val live = (store.pointer() as? StoreRead.Found)?.value?.live ?: return null
                store.meta(live) ?: return null
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

            /**
             * The `sourceTimestampMillis` of the dataset's live generation as the snapshot publishes it, for [SyncRules];
             * null when it has none (no generation loaded, §7.1: the stored watermark is then not read).
             */
            fun liveTimestamp(): Long? {
                val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
                live.generationId ?: return null
                return live.sourceTimestampMillis
            }

            /** The directory of the generation the snapshot publishes live, or null. */
            fun liveDirectory(): String? {
                val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
                val id = live.generationId ?: return null
                return live.sourceTimestampMillis?.let { GenerationNames.directory(it, id) }
            }

            /**
             * Whether the pointer names the live generation's directory ([liveDirectory]) as `live`. Asked only for an
             * `UNCHANGED` decision, which needs a live generation, so [liveDirectory] is never null here.
             */
            fun pointed(): Boolean = (stored { store.pointer() } as? StoreRead.Found)?.value?.live == liveDirectory()

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
         * outcome) unless its read never returned (#209), then the result.
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
                // #209: a sync whose read of updater.json did not return writes nothing, leaving the file as it is.
                read?.let {
                    val next =
                        UpdaterTransitions.after(
                            it,
                            source.sourceId,
                            ended.outcome,
                            now,
                            serverBackoffMillis = backoff,
                        )
                    store.writeUpdater(next, now)
                }
            } catch (t: Throwable) {
                restoreInterrupt(t)
                storeFailures++
                logger.safeLog(LogLevel.WARN, "writing ${store.root}/updater.json failed", t)
            }
            val warnings = ArrayList<PolicyDiagnostic>()
            // CLOCK_SKEW is an x5u link outside its validity window at stage X5U (§7.1), the one clock check.
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
