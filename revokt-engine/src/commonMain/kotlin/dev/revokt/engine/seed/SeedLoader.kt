// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
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
import dev.revokt.SeedSource
import dev.revokt.Severity
import dev.revokt.SignatureVerifier
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.clubcard.port.Encoding
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.fetch.CrliteRecord
import dev.revokt.engine.fetch.CrliteSchema
import dev.revokt.engine.fetch.RecordCheck
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonParseException
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.parse.X5uPem
import dev.revokt.engine.parse.X5uPemRead
import dev.revokt.engine.seed.parse.SeedArchive
import dev.revokt.engine.seed.parse.SeedFormatException
import dev.revokt.engine.seed.parse.SeedHeader
import dev.revokt.engine.store.BlobWrite
import dev.revokt.engine.store.GenerationMeta
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.SignedMeta
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.FilterRecord
import dev.revokt.engine.update.IndexBuild
import dev.revokt.engine.update.InstallResult
import dev.revokt.engine.update.PendingGeneration
import dev.revokt.engine.update.PlacedFilter
import dev.revokt.engine.update.Placement
import dev.revokt.engine.update.Publication
import dev.revokt.engine.update.SnapshotRef
import dev.revokt.engine.update.SyncClock
import dev.revokt.engine.update.SyncRules
import dev.revokt.engine.update.buildIndex
import dev.revokt.engine.update.install
import dev.revokt.engine.update.placeFilters
import dev.revokt.engine.update.saturatingAdd
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.engine.verify.RawSignature
import dev.revokt.engine.verify.X5uChainResult
import dev.revokt.engine.verify.X5uPath
import dev.revokt.engine.verify.X5uValidity
import dev.revokt.engine.verify.checkValidity
import dev.revokt.engine.verify.validateX5uChain
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * How one seed load ended (spec §6.5 "Seed archive", §4 S bullet, §5.1): typed, so the start task (#143, #147) maps it
 * to its diagnostics and lifecycle. [storeFailures] is what the load adds to `storeFailures`; [warnings] are the
 * diagnostics it raised (`SEED_UNREADABLE`, `SEED_CHANNEL_MISMATCH`, `CLOCK_BEHIND`).
 */
internal sealed interface SeedLoad {
    val storeFailures: Int
    val warnings: List<PolicyDiagnostic>

    /** The source opened no archive: there is no seed. */
    class Absent(
        override val storeFailures: Int = 0,
    ) : SeedLoad {
        override val warnings: List<PolicyDiagnostic> get() = emptyList()

        override fun toString(): String = "Absent"
    }

    /** `seed.json` names [seedChannel], not the configured channel: `SEED_CHANNEL_MISMATCH`, which `start()` throws. */
    class ChannelMismatch(
        val seedChannel: String,
        override val warnings: List<PolicyDiagnostic>,
    ) : SeedLoad {
        override val storeFailures: Int get() = 0

        override fun toString(): String = "ChannelMismatch($seedChannel)"
    }

    /** The seed is not one this engine loads: `SEED_UNREADABLE`, and the seed is ignored. Nothing was installed. */
    class Unreadable(
        val detail: String,
        val cause: Throwable?,
        override val storeFailures: Int,
        override val warnings: List<PolicyDiagnostic>,
    ) : SeedLoad {
        override fun toString(): String = "Unreadable($detail)"
    }

    /**
     * The live or a stored generation is not older than the seed (§5.1 "unless the stored generation is `SIGNED` and not
     * older than the seed"; every generation is signed, #218): nothing was written or installed. [storedTimestampMillis]
     * is its timestamp.
     */
    class Skipped(
        val seedTimestampMillis: Long,
        val storedTimestampMillis: Long,
        override val storeFailures: Int,
    ) : SeedLoad {
        override val warnings: List<PolicyDiagnostic> get() = emptyList()

        override fun toString(): String = "Skipped(seed $seedTimestampMillis, stored $storedTimestampMillis)"
    }

    /**
     * The seed is live: activated, published at [generationEpoch] as [generationId], pointed to, and `updater.json`
     * written with the watermark at `max(watermark, `[timestampMillis]`)` and `seedInstalledAtMillis`. [clockBehind]
     * when its signed timestamp is beyond local now + `clockSkew` (§6.5: it installs, loudly).
     */
    class Installed(
        val directory: String,
        val generationId: String,
        val generationEpoch: Long,
        val timestampMillis: Long,
        val clockBehind: Boolean,
        override val storeFailures: Int,
        override val warnings: List<PolicyDiagnostic>,
    ) : SeedLoad {
        override fun toString(): String = "Installed($generationId at epoch $generationEpoch, clockBehind=$clockBehind)"
    }

    /**
     * A store read or write failed, at [stage], or the install failed after `activate` ([activated]: the engine holds
     * the seed and its directory stays, as [InstallResult.Failed] says). A store read that throws fails the load before
     * anything is written, so `updater.json` is never written from a record that was not read (#209).
     */
    class Failed(
        val outcome: SyncOutcome,
        val stage: SyncStage,
        val detail: String,
        val cause: Throwable?,
        val activated: Boolean,
        override val storeFailures: Int,
    ) : SeedLoad {
        override val warnings: List<PolicyDiagnostic> get() = emptyList()

        override fun toString(): String = "Failed($outcome at $stage: $detail, activated=$activated)"
    }
}

/**
 * The inputs of a [SeedLoader] beside its collaborators: the pinned content-signature root SPKI SHA-256s the x5u chain
 * must end in, the Remote Settings [collection] `meta.json` records, `clockSkew`, and whether a fetching source is
 * configured, which opens the §8 `STALE` gate at once when none is.
 */
internal class SeedPolicy(
    val pinnedRootSpkis: Set<ByteString>,
    val collection: String?,
    val clockSkewMillis: Long,
    val fetchingSource: Boolean,
) {
    init {
        require(clockSkewMillis >= 0) { "clockSkew is negative" }
    }
}

/**
 * Reads, verifies and installs the seed archive [source] opens, for the dataset and channel of [store] (spec §6.5 "Seed
 * archive", issue #138). Blocking: the loader runs it on its dispatcher, or the `start()` caller in the sole-seed
 * `ENFORCE` path (§4 S bullet), never two at once. Every throwable is caught, an `OutOfMemoryError` included.
 */
internal class SeedLoader(
    private val source: SeedSource,
    private val store: StoreLayout,
    private val engine: RevocationEngine,
    private val snapshot: SnapshotRef,
    private val verifier: SignatureVerifier,
    private val policy: SeedPolicy,
    private val logger: RevoktLogger,
) {
    private val channel: CrliteChannel = store.channel

    init {
        require(store.dataset == Dataset.CRLITE) { "a seed is CRLITE, not ${store.dataset}" }
    }

    /**
     * The header read alone (§5.1 `start()`): the archive's end record and central directory, the fixed entries
     * ([SeedArchive.requireFixed]), then `seed.json` and its checks; nothing else is inflated. Null when the header
     * passes; otherwise the load's end: [SeedLoad.Absent], [SeedLoad.Unreadable] or [SeedLoad.ChannelMismatch].
     */
    @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable.
    fun checkHeader(): SeedLoad? =
        try {
            when (val read = header()) {
                is HeaderRead.Ended -> read.load
                is HeaderRead.Read -> null
            }
        } catch (t: Throwable) {
            restoreInterrupt(t)
            unreadable(t.message ?: t.toString(), t, 0)
        }

    /**
     * One load at [nowMillis], in the order of #138 (spec §6.5, §7.2):
     * 1. The header ([checkHeader]): `seedFormat`, `engineFloor`, `dataset`, `filterFormat` and `channel`.
     * 2. The fixed entries inflated under their caps; then **raw verification** before any JSON is decoded: `x5u.pem`
     *    read as PEM and validated to the pinned root ([validateX5uChain], every check but validity), and `signature`
     *    over `records.json`'s bytes unchanged ([ContentSignature.verifyRawPayload]).
     * 3. `records.json` decoded; it must be the canonical payload of its own records and `<ts>`, so what is decoded is
     *    what was signed; `<ts>` is the seed's timestamp for every rule below (never `seed.json`'s).
     * 4. The x5u validity periods at `<ts>` ([checkValidity]): an expired leaf loads.
     * 5. The schema check, then the channel's records and names ([placeFilters]: one full, distinct derived names),
     *    each placed record's signed size within `MAX_FILTER_BYTES`, and the `attachments/` entries exactly the placed
     *    records' filenames ([SeedArchive.attachments]), before any attachment is inflated.
     * 6. The store read: a read that throws is [SeedLoad.Failed], nothing written; a malformed `updater.json` reads
     *    as absent; a malformed pointer or pointed `meta.json` leaves the generations unknown, so every complete
     *    directory is read and none is pruned. Then the seed-vs-stored rule ([SeedLoad.Skipped]).
     * 7. Each attachment inflated under `min(signed size, MAX_FILTER_BYTES)`, checked against its signed size and
     *    SHA-256, and written as the sync writes it: a full as its blob, a delta staged in the generation directory.
     * 8. `index.bin` rebuilt ([buildIndex]) and byte-compared with the archive's; the `SIGNED` coverage bound
     *    ([SyncRules.coverageWithinBound]) at `<ts>`; every placed filter's encoding listed by the engine.
     * 9. The install ([install]): `SIGNED`, `fromSeed`, [Freshness.SEED_SIGNED_TIME], generation id `"<ts>/<last placed
     *    record id>"`, `updater.json` with the watermark at `max(watermark, <ts>)` and `seedInstalledAtMillis` = now;
     *    then the prune, as after a sync's install, unless the stored generations were unknown.
     *
     * Any seed fault is [SeedLoad.Unreadable]; a failed `prepare`, self-check or `activate` is too (§6.5: "the
     * corresponding load failure, `SEED_UNREADABLE` for the seed"). Any directory this load staged is deleted on a
     * failure before the install.
     */
    fun load(nowMillis: Long): SeedLoad = Attempt(nowMillis).run()

    /** What the header read gave: the archive and its header, or the load's end. */
    private sealed interface HeaderRead {
        class Read(
            val archive: SeedArchive,
            val header: SeedHeader,
        ) : HeaderRead

        class Ended(
            val load: SeedLoad,
        ) : HeaderRead
    }

    /** The header read; seed faults throw [SeedFormatException]. */
    private fun header(): HeaderRead {
        val archive = SeedArchive.open(source::open) ?: return HeaderRead.Ended(SeedLoad.Absent())
        archive.requireFixed()
        var bytes: ByteArray? = null
        val entry = checkNotNull(archive.entry(SeedArchive.SEED_JSON))
        archive.read(listOf(entry to SeedHeader.MAX_BYTES)) { _, b -> bytes = b }
        val header = SeedHeader.read(checkNotNull(bytes))
        if (header.seedFormat != SEED_FORMAT) fail("seedFormat ${header.seedFormat}; this engine reads $SEED_FORMAT")
        if (header.engineFloor > ENGINE_LEVEL) fail("engineFloor ${header.engineFloor} is above this engine's level")
        if (header.dataset != Dataset.CRLITE.name) fail("dataset ${header.dataset}, not ${Dataset.CRLITE.name}")
        val format =
            FilterFormat.entries.firstOrNull { it.name == header.filterFormat }
                ?: fail("filterFormat ${header.filterFormat} is not a filter format")
        if (format !in engine.formats) fail("filterFormat $format is not in the engine's ${engine.formats}")
        if (header.channel != channel.name) {
            val message = "the seed is for ${header.channel}, the configured channel is ${channel.name}"
            return HeaderRead.Ended(SeedLoad.ChannelMismatch(header.channel, listOf(diagnostic(MISMATCH, message))))
        }
        return HeaderRead.Read(archive, header)
    }

    /** A store state the load does not write over: it ends as [SeedLoad.Failed] at `STORE`, nothing written. */
    private class StoreFault(
        message: String,
    ) : Exception(message)

    private fun fault(message: String): Nothing = throw StoreFault(message)

    /** The verified fixed entries: the records, `<ts>`, the x5u path, the signature, and the bytes kept. */
    private class Verified(
        val records: List<JsonObject>,
        val timestamp: Long,
        val path: X5uPath,
        val signature: ByteArray,
        val recordsJson: ByteArray,
        val index: ByteArray,
    )

    /**
     * What the store holds for this dataset and channel: the [updater] record, the [pointer] when it read
     * ([pointerMalformed] when it did not), and every complete generation directory with its timestamp ([complete]),
     * pointed or not, which the seed must not displace when one is not older (the decision on #235's review: a seed never
     * prunes a newer complete generation). [known] when the pointer and every directory it names read; otherwise the
     * generations are unknown and the load never prunes (the decisions on #138: heal, never brick, never delete).
     */
    private class Stored(
        val updater: UpdaterRecord,
        val pointer: Pointer?,
        val pointerMalformed: Boolean,
        val complete: Map<String, Long>,
        val known: Boolean,
    )

    /** One load's state: what it staged and what its failure path undoes. */
    @OptIn(RevoktInternalApi::class)
    private inner class Attempt(
        private val now: Long,
    ) {
        private var storeFailures = 0

        /** Whether the current step reads or writes the store, so a throw there is a store failure. */
        private var inStore = false

        /** The generation directory this load staged files in, until the install takes it over. */
        private var staged: String? = null

        private var installing = false

        @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError too.
        fun run(): SeedLoad =
            try {
                steps()
            } catch (t: Throwable) {
                restoreInterrupt(t)
                thrown(t)
            }

        /**
         * The load after [t] escaped a step: a seed fault is [SeedLoad.Unreadable]; a [StoreFault], and any other
         * non-fatal throw while reading or writing the store, is [SeedLoad.Failed] at `STORE` with a store failure;
         * anything else is unreadable, with a store failure once the install began (§6.5: an `OutOfMemoryError` during an
         * install counts one). Any staged directory is deleted first.
         */
        private fun thrown(t: Throwable): SeedLoad {
            discard()
            val storeFault = t is StoreFault || (inStore && t !is SeedFormatException && !isFatal(t))
            if (storeFault) {
                storeFailures++
                logger.safeLog(LogLevel.WARN, "${store.root}: the seed load failed at STORE", t)
                val detail = t.message ?: t.toString()
                return SeedLoad.Failed(SyncOutcome.STORE_FAILED, SyncStage.STORE, detail, t, false, storeFailures)
            }
            // An archive over its total cap is a source fault, not a store fault, so it is not counted (#138).
            val fatalInStore = inStore && isFatal(t)
            if (installing || fatalInStore) storeFailures++
            val detail = if (t is SeedFormatException) t.message.orEmpty() else "the load threw: $t"
            return unreadable(detail, t, storeFailures)
        }

        /** [block] as a store step: a throw from it is a store failure ([thrown]). */
        private inline fun <T> stored(block: () -> T): T {
            val before = inStore
            inStore = true
            val value = block()
            inStore = before
            return value
        }

        /** Deletes the directory this load staged, if any; a failure is a store failure, never the load's. */
        @Suppress("TooGenericExceptionCaught") // §6.5: the failure path catches every throwable too.
        private fun discard() {
            val directory = staged ?: return
            staged = null
            try {
                store.deleteGeneration(directory)
            } catch (t: Throwable) {
                restoreInterrupt(t)
                storeFailures++
                logger.safeLog(LogLevel.WARN, "deleting ${store.root}/$directory failed", t)
            }
        }

        private fun steps(): SeedLoad {
            val archive =
                when (val read = header()) {
                    is HeaderRead.Ended -> return read.load
                    is HeaderRead.Read -> read.archive
                }
            val verified = verify(archive)
            val ts = verified.timestamp
            val crlite =
                when (val check = CrliteSchema.check(verified.records, channel, RevoktLimits.MAX_CHANGESET_RECORDS)) {
                    is RecordCheck.Passed -> check.records
                    is RecordCheck.Rejected -> fail("records.json fails the schema: ${check.detail}")
                }
            val records =
                crlite.map {
                    FilterRecord(it.id, it.channel, it.incremental, it.effectiveTimestamp, it.attachment.filename)
                }
            val placed =
                when (val placement = placeFilters(records, channel)) {
                    is Placement.Placed -> placement.filters
                    is IndexBuild.Refused -> fail("records.json builds no generation: $placement")
                }
            val byId = crlite.associateBy { it.id }
            val signed = placed.map { byId.getValue(it.record.id) }
            signed.firstOrNull { it.attachment.size > RevoktLimits.MAX_FILTER_BYTES }?.let {
                fail("${it.id} declares ${it.attachment.size} bytes, over MAX_FILTER_BYTES")
            }
            val entries = archive.attachments(placed.map { it.record.filename })
            val stored = stored { read() }
            val generationId = "$ts/${placed.last().record.id}"
            val directory = GenerationNames.directory(ts, generationId)
            newer(stored, ts, directory)?.let { return SeedLoad.Skipped(ts, it, storeFailures) }
            val held = stored { open(directory, stored) }
            val bodies = Bodies(directory, held)
            val bySeedEntry = entries.zip(signed).toMap()
            val caps = entries.zip(signed) { e, r -> e to minOf(r.attachment.size, RevoktLimits.MAX_FILTER_BYTES) }
            archive.read(caps) { entry, bytes -> bodies.write(bySeedEntry.getValue(entry), bytes) }
            val built =
                when (val build = buildIndex(records, channel) { bodies.read(byId.getValue(it.id)) }) {
                    is IndexBuild.Built -> build
                    is IndexBuild.Refused -> fail("index.bin cannot be rebuilt: $build")
                }
            if (!built.index.contentEquals(verified.index)) fail("the shipped index.bin differs from the rebuilt one")
            val clock = SyncClock(now, policy.clockSkewMillis, 0)
            if (!SyncRules.coverageWithinBound(TrustClass.SIGNED, built.coverageHighs, ts, clock)) {
                fail("a filter's coverage ends beyond $ts + clockSkew")
            }
            bodies.unlisted(placed)?.let { fail("${it.record.id} is in an encoding the engine does not list") }
            val meta = meta(verified, generationId, bodies.format(placed), bodies.blobs)
            val pending = PendingGeneration(meta, built.index, bodies.deltas, verified.recordsJson)
            return installed(pending, stored.updater, stored.known)
        }

        /**
         * Steps 2 to 4: the fixed entries read in one pass, verified as raw bytes, then decoded and checked at `<ts>`.
         * Every failure is a seed fault.
         */
        private fun verify(archive: SeedArchive): Verified {
            val fixed = HashMap<String, ByteArray>()
            val caps =
                listOf(
                    SeedArchive.RECORDS to RevoktLimits.MAX_JSON_BYTES,
                    SeedArchive.SIGNATURE to MAX_SIGNATURE_BYTES,
                    SeedArchive.X5U to RevoktLimits.MAX_X5U_BYTES,
                    SeedArchive.INDEX to C2spIndex.MAX_BYTES.toLong(),
                )
            val wanted = caps.map { (name, cap) -> checkNotNull(archive.entry(name)) to cap }
            archive.read(wanted) { e, b -> fixed[e.name] = b }
            val recordsJson = fixed.getValue(SeedArchive.RECORDS)
            val ders =
                when (val pem = X5uPem.read(fixed.getValue(SeedArchive.X5U), RevoktLimits.MAX_X5U_BYTES)) {
                    is X5uPemRead.Certificates -> pem.ders
                    is X5uPemRead.Failed -> fail("x5u.pem is not a PEM chain: ${pem.reason}")
                }
            val path =
                when (val chain = validateX5uChain(ders, policy.pinnedRootSpkis, verifier)) {
                    is X5uChainResult.Valid -> chain.path
                    is X5uChainResult.Failed -> fail("the x5u chain fails: $chain")
                }
            val signature = fixed.getValue(SeedArchive.SIGNATURE)
            val text = signature.decodeToString()
            val checked =
                ContentSignature.verifyRawPayload(
                    verifier,
                    recordsJson,
                    text,
                    ContentSignature.MODE,
                    path.leafSpki,
                )
            if (!checked.verified) fail("the signature over records.json does not verify: $checked")
            val (records, ts) = decode(recordsJson)
            when (val validity = checkValidity(path, ts)) {
                is X5uValidity.Valid -> Unit
                is X5uValidity.ClockSkew -> fail("x5u link ${validity.certIndex} is outside its validity at $ts")
            }
            return Verified(records, ts, path, signature, recordsJson, fixed.getValue(SeedArchive.INDEX))
        }

        /** The records and `<ts>` of the verified [bytes], which must be the canonical payload of both. */
        private fun decode(bytes: ByteArray): Pair<List<JsonObject>, Long> {
            val root =
                try {
                    Json.parse(bytes, RevoktLimits.MAX_JSON_BYTES)
                } catch (e: JsonParseException) {
                    fail("records.json is not JSON: ${e.message}")
                }
            val data = ((root as? JsonObject)?.get("data") as? JsonArray) ?: fail("records.json has no data array")
            val records =
                data.items.map {
                    it as? JsonObject
                        ?: fail("records.json holds a record that is not an object")
                }
            val ts =
                ((root["last_modified"] as? JsonString)?.value?.toLongOrNull())?.takeIf { it in 0..MAX_TIMESTAMP }
                    ?: fail("records.json's last_modified is not a 13-digit timestamp")
            val canonical = ContentSignature.recordsJson(records, ts)
            if (canonical == null || !canonical.contentEquals(bytes)) fail("records.json is not the canonical payload")
            return records to ts
        }

        /**
         * `updater.json`, the pointer, every directory it names, and every complete directory (the decisions on #138 and
         * #235's review). A read that throws fails the load as a store failure, nothing written ([thrown]). Each fault is
         * counted here, once, where it is found, and the install is told so ([Publication.pointerCounted]):
         * - a malformed `updater.json` reads as absent (§6.5), and the install writes a fresh one;
         * - a malformed pointer, or a pointed directory whose `meta.json` does not read, leaves the stored generations
         *   unknown, so nothing is pruned in this load.
         */
        private fun read(): Stored {
            val updater =
                when (val read = store.updater(now)) {
                    StoreRead.Absent -> {
                        UpdaterRecord()
                    }

                    StoreRead.Malformed -> {
                        storeFailures++
                        logger.safeLog(LogLevel.WARN, "${store.root}: updater.json is malformed; read as absent")
                        UpdaterRecord()
                    }

                    is StoreRead.Found -> {
                        // A dropped source entry was malformed alone; the rest, the watermark included, was read.
                        storeFailures += read.value.storeFailures
                        read.value.record
                    }
                }
            val complete =
                store.directories
                    .mapNotNull { d ->
                        store.meta(d)?.let { d to it.sourceTimestampMillis }
                    }.toMap()
            val pointer =
                when (val read = store.pointer()) {
                    StoreRead.Absent -> return Stored(updater, null, false, complete, known = true)
                    StoreRead.Malformed -> return unknown(Stored(updater, null, true, complete, known = false), 1)
                    is StoreRead.Found -> read.value
                }
            val unread = listOfNotNull(pointer.live, pointer.previous).count { store.readMeta(it) !is StoreRead.Found }
            if (unread > 0) return unknown(Stored(updater, pointer, false, complete, known = false), unread)
            return Stored(updater, pointer, false, complete, known = true)
        }

        /** [stored], whose generations are unknown for [faults] store faults, each counted. */
        private fun unknown(
            stored: Stored,
            faults: Int,
        ): Stored {
            storeFailures += faults
            val why = if (stored.pointerMalformed) "the pointer is malformed" else "a pointed meta.json does not read"
            logger.safeLog(LogLevel.WARN, "${store.root}: $why; the seed load does not prune")
            return stored
        }

        /**
         * The timestamp of the live generation or of a complete stored one that is not older than [ts] (the seed is then
         * skipped), or null. Every generation is Mozilla-signed (#218), so no trust class is compared. The seed's own
         * [directory] counts only when the pointer names it as `live` (the start task loads it); otherwise it is this
         * generation, which the load installs as it stands or completes afresh (#235's review: never brick).
         */
        private fun newer(
            stored: Stored,
            ts: Long,
            directory: String,
        ): Long? {
            val live = snapshot.snapshot.datasets[Dataset.CRLITE]?.takeIf { it.generationId != null }
            val others = stored.complete.filterKeys { it != directory || it == stored.pointer?.live }.values
            val candidates = listOfNotNull(live?.sourceTimestampMillis) + others
            return candidates.maxOrNull()?.takeIf { it >= ts }
        }

        /**
         * Readies [directory] as the sync does (#242's held rule). It is held when the engine holds it live or the pointer
         * names it, or when the pointer is malformed and its `meta.json` reads complete: a held directory is never written,
         * and the install compares it with this generation and installs it as it stands, or fails `STORE_FAILED`; one
         * live or pointed whose `meta.json` does not read is a [StoreFault]. Beside a malformed pointer, a directory of the
         * seed's name whose `meta.json` is present but malformed is not a generation anyone can load, and is rewritten
         * from the verified seed (the coordinator's note on #235: holding it would brick a sole-seed configuration). Any
         * other directory is this load's, a complete orphan reopened first. Whether it is held.
         */
        private fun open(
            directory: String,
            stored: Stored,
        ): Boolean {
            val pointer = stored.pointer
            val holders = listOfNotNull(liveDirectory(), pointer?.live, pointer?.previous)
            val read = store.readMeta(directory)
            if (directory in holders) {
                if (read is StoreRead.Found) return true
                fault("$directory is live or pointed to, and its meta.json is not readable")
            }
            when {
                stored.pointerMalformed && read is StoreRead.Found -> return true
                stored.pointerMalformed && read is StoreRead.Malformed -> store.deleteGeneration(directory)
                read is StoreRead.Found -> store.reopen(directory)
            }
            staged = directory
            return false
        }

        private fun liveDirectory(): String? {
            val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
            val id = live.generationId ?: return null
            return live.sourceTimestampMillis?.let { GenerationNames.directory(it, id) }
        }

        /** The bodies of the generation in [directory] ([held] when the engine or the pointer holds it). */
        private inner class Bodies(
            private val directory: String,
            private val held: Boolean,
        ) {
            val blobs = LinkedHashMap<String, ByteString>()
            val deltas = LinkedHashMap<String, ByteString>()
            private val encodings = HashMap<String, Encoding?>()

            /** [bytes], [r]'s attachment as inflated: checked against its signed size and hash, then written. */
            fun write(
                r: CrliteRecord,
                bytes: ByteArray,
            ) {
                val sha256 = r.attachment.sha256
                if (bytes.size.toLong() != r.attachment.size || bytes.toByteString().sha256() != sha256) {
                    fail("attachments/${r.attachment.filename} does not match its signed size and hash")
                }
                val name = GenerationNames.derive(r.attachment.filename)
                stored {
                    if (!r.incremental) {
                        if (store.putBlob(bytes) == BlobWrite.REWRITTEN) storeFailures++
                        blobs[name] = sha256
                    } else {
                        deltas[name] = sha256
                        if (store.file(directory, name, sha256) == null) {
                            if (held) fault("$directory holds another generation: $name does not re-hash")
                            store.stageFile(directory, name, bytes)
                        }
                    }
                }
            }

            /** [r]'s body as written, re-hashed, for [buildIndex]; its encoding is noted. */
            fun read(r: CrliteRecord): ByteArray {
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
                encodings[r.id] =
                    try {
                        ClubcardFilters.encodingOf(bytes)
                    } catch (ignored: ClubcardFormatException) {
                        null // buildIndex decodes every placed filter and refuses this one.
                    }
                return bytes
            }

            /** The first of [placed] whose encoding the engine does not list (§3.2, as the sync checks), or null. */
            fun unlisted(placed: List<PlacedFilter>): PlacedFilter? =
                placed.firstOrNull { format(checkNotNull(encodings[it.record.id])) !in engine.formats }

            /** The full's encoding, `meta.format`. */
            fun format(placed: List<PlacedFilter>): FilterFormat =
                format(checkNotNull(encodings[placed.first { it.full }.record.id]))

            private fun format(encoding: Encoding): FilterFormat =
                when (encoding) {
                    Encoding.V3 -> FilterFormat.V3
                    Encoding.V4 -> FilterFormat.V4
                }
        }

        private fun meta(
            verified: Verified,
            generationId: String,
            format: FilterFormat,
            blobs: Map<String, ByteString>,
        ): GenerationMeta {
            val raw =
                RawSignature.decode(verified.signature.decodeToString()) ?: fail("the signature is not raw r || s")
            val leaf =
                verified.path.links[0]
                    .der
                    .toByteString()
                    .sha256()
            return GenerationMeta(
                dataset = Dataset.CRLITE,
                channel = channel,
                trustClass = TrustClass.SIGNED,
                generationId = generationId,
                format = format,
                freshness = Freshness.SEED_SIGNED_TIME,
                sourceTimestampMillis = verified.timestamp,
                collection = policy.collection,
                blobs = blobs,
                signed = SignedMeta(verified.timestamp, leaf, raw.toByteString()),
            )
        }

        /** Step 9: [install] of [pending] over the [read] record, then the prune. */
        private fun installed(
            pending: PendingGeneration,
            read: UpdaterRecord,
            known: Boolean,
        ): SeedLoad {
            val ts = pending.meta.sourceTimestampMillis
            val updated =
                read.copy(
                    watermarkMillis = maxOf(read.watermarkMillis ?: Long.MIN_VALUE, ts),
                    seedInstalledAtMillis = now,
                )
            // §8: the gate opens once a sync attempt completes after the seed's install, or at once with no fetching source.
            val gateOpen = !policy.fetchingSource || (read.datasetLastAttemptAtMillis ?: Long.MIN_VALUE) >= now
            val publication =
                Publication(true, SEED_FORMAT.toInt(), gateOpen, now, policy.clockSkewMillis, pointerCounted = true)
            installing = true
            val result = install(pending, engine, store, snapshot, publication, updated, logger)
            // The install deleted its directory on a failure before activation, and keeps it after one.
            staged = null
            storeFailures += result.storeFailures
            return when (result) {
                is InstallResult.Installed -> {
                    // With the stored generations unknown, the flip heals the pointer and nothing is pruned: the next
                    // install over a valid pointer prunes.
                    if (known) prune(result.directory)
                    val clockBehind = ts > saturatingAdd(now, policy.clockSkewMillis)
                    val warnings =
                        if (clockBehind) {
                            listOf(
                                diagnostic(
                                    DiagnosticCode.CLOCK_BEHIND,
                                    "the seed's $ts is beyond now $now + clockSkew",
                                ),
                            )
                        } else {
                            emptyList()
                        }
                    SeedLoad.Installed(
                        result.directory,
                        result.generationId,
                        result.generationEpoch,
                        ts,
                        clockBehind,
                        storeFailures,
                        warnings,
                    )
                }

                is InstallResult.Failed -> {
                    val detail = "the install failed: $result"
                    if (!result.activated && result.outcome == SyncOutcome.FAILED) {
                        unreadable(detail, result.cause, storeFailures)
                    } else {
                        SeedLoad.Failed(
                            result.outcome,
                            result.stage,
                            detail,
                            result.cause,
                            result.activated,
                            storeFailures,
                        )
                    }
                }
            }
        }

        /** Prunes to what the pointer names after the install of [installed], as the sync does; never fails the load. */
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
    }

    private fun unreadable(
        detail: String,
        cause: Throwable?,
        storeFailures: Int,
    ): SeedLoad.Unreadable {
        logger.safeLog(LogLevel.WARN, "${store.root}: the seed is unreadable: $detail", cause)
        return SeedLoad.Unreadable(
            detail,
            cause,
            storeFailures,
            listOf(diagnostic(DiagnosticCode.SEED_UNREADABLE, detail)),
        )
    }

    @OptIn(RevoktTestingApi::class)
    private fun diagnostic(
        code: DiagnosticCode,
        message: String,
    ): PolicyDiagnostic =
        PolicyDiagnostic
            .Builder()
            .code(code)
            .severity(if (code == MISMATCH) Severity.ERROR else Severity.WARNING)
            .dataset(Dataset.CRLITE)
            .message("seed: $message")
            .build()

    companion object {
        /** The `seedFormat` this engine reads and [buildIndex] writes (spec §6.5: its output is frozen per format). */
        const val SEED_FORMAT: Long = 1

        /** The level `engineFloor` is compared with: a seed whose floor is above it is `SEED_UNREADABLE` (§6.5). */
        const val ENGINE_LEVEL: Long = 1

        /** The cap on the `signature` entry, which §6.5 does not name: `seed.json`'s, far above any raw pair's text. */
        const val MAX_SIGNATURE_BYTES: Long = 64L shl 10

        /** The latest timestamp a generation directory name holds (13 digits, §6.5). */
        private const val MAX_TIMESTAMP = 9_999_999_999_999L

        private val MISMATCH = DiagnosticCode.SEED_CHANNEL_MISMATCH
    }
}

private fun fail(message: String): Nothing = throw SeedFormatException(message)
