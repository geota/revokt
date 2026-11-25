// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// detekt 1.23 resolves types with a Kotlin 2.0 compiler that cannot read the 2.4 stdlib's metadata, so it reports the code
// after an inline lambda's non-local return or `Nothing` call as unreachable; kotlinc's own unreachable-code check holds.
@file:Suppress("UnreachableCode")

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.Freshness
import dev.revokt.LogLevel
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktWarning
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.SyncFailure
import dev.revokt.WarningCode
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
import dev.revokt.engine.store.GenerationFile
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.IndexBuild
import dev.revokt.engine.update.InstallResult
import dev.revokt.engine.update.PendingGeneration
import dev.revokt.engine.update.PlacedFilter
import dev.revokt.engine.update.Placement
import dev.revokt.engine.update.Publication
import dev.revokt.engine.update.SnapshotRef
import dev.revokt.engine.update.StoredGeneration
import dev.revokt.engine.update.buildIndex
import dev.revokt.engine.update.install
import dev.revokt.engine.update.loadFiles
import dev.revokt.engine.update.place
import dev.revokt.engine.update.placeFilters
import dev.revokt.engine.update.stored
import dev.revokt.engine.update.toFilterFormat
import dev.revokt.engine.update.toFilterRecord
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
 * runtime warnings it raised (`SEED_UNREADABLE`, `SEED_CHANNEL_MISMATCH`).
 */
internal sealed interface SeedLoad {
    val storeFailures: Int
    val warnings: List<RevoktWarning>

    /** The source opened no archive: there is no seed. */
    class Absent(
        override val storeFailures: Int = 0,
    ) : SeedLoad {
        override val warnings: List<RevoktWarning> get() = emptyList()

        override fun toString(): String = "Absent"
    }

    /** `seed.json` names [seedChannel], not the configured channel: `SEED_CHANNEL_MISMATCH`, which `start()` throws. */
    class ChannelMismatch(
        val seedChannel: String,
        override val warnings: List<RevoktWarning>,
    ) : SeedLoad {
        override val storeFailures: Int get() = 0

        override fun toString(): String = "ChannelMismatch($seedChannel)"
    }

    /** The seed is not one this engine loads: `SEED_UNREADABLE`, and the seed is ignored. Nothing was installed. */
    class Unreadable(
        val detail: String,
        val cause: Throwable?,
        override val storeFailures: Int,
        override val warnings: List<RevoktWarning>,
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
        override val warnings: List<RevoktWarning> get() = emptyList()

        override fun toString(): String = "Skipped(seed $seedTimestampMillis, stored $storedTimestampMillis)"
    }

    /**
     * Rule (b) of the seed-load rule (spec §6.5): no pointer could be trusted, and a stored generation newer than the
     * seed, which re-verifies, was adopted instead: the pointer now names the generation file [name] (at
     * [timestampMillis]) alone and the seed was not installed. The loader loads that generation, as it loads a pointed
     * one. Nothing was deleted.
     */
    class Adopted(
        val name: String,
        val timestampMillis: Long,
        override val storeFailures: Int,
    ) : SeedLoad {
        override val warnings: List<RevoktWarning> get() = emptyList()

        override fun toString(): String = "Adopted($name at $timestampMillis)"
    }

    /**
     * The seed is live: activated, published at [generationEpoch] as [generationId], pointed to, and `updater.json`
     * written with `seedInstalledAtMillis` and the watermark at `max(watermark, `[timestampMillis]`)` beside a loaded
     * generation, or at [timestampMillis] when none loaded (§7.1, as Firefox's floor after a dump import is the dump's
     * timestamp). A signed
     * timestamp ahead of the local clock installs like any other (§7.1: no rule on signed data reads local time).
     */
    class Installed(
        val name: String,
        val generationId: String,
        val generationEpoch: Long,
        val timestampMillis: Long,
        override val storeFailures: Int,
    ) : SeedLoad {
        override val warnings: List<RevoktWarning> get() = emptyList()

        override fun toString(): String = "Installed($generationId at epoch $generationEpoch)"
    }

    /**
     * A store read or write failed ([failure] `STORE_FAILED`), or the install failed after `activate` ([activated]: the
     * engine holds the seed, as [InstallResult.Failed] says). A store read that throws fails
     * the load before anything is written, so `updater.json` is never written from a record that was not read (#209).
     */
    class Failed(
        val failure: SyncFailure,
        val detail: String,
        val cause: Throwable?,
        val activated: Boolean,
        override val storeFailures: Int,
    ) : SeedLoad {
        override val warnings: List<RevoktWarning> get() = emptyList()

        override fun toString(): String = "Failed($failure: $detail, activated=$activated)"
    }
}

/**
 * The inputs of a [SeedLoader] beside its collaborators: the pinned content-signature root SPKI SHA-256s the x5u chain
 * must end in, and whether a fetching source is configured, which opens the §8 `STALE` gate at once when none is.
 */
internal class SeedPolicy(
    val pinnedRootSpkis: Set<ByteString>,
    val fetchingSource: Boolean,
)

/**
 * Reads, verifies and installs the seed archive [source] opens, for the dataset and channel of [store] (spec §6.5 "Seed
 * archive", issue #138). Blocking: the loader runs it on its dispatcher, or the `start()` caller in the sole-seed
 * `ENFORCE` path (§4 S bullet), never two at once. Every throwable is caught, an `OutOfMemoryError` included.
 */
@OptIn(dev.revokt.RevoktInternalApi::class)
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
     * 6. The store read (a throw is [SeedLoad.Failed], nothing written; a malformed `updater.json` reads as absent),
     *    then the seed-load rule ([decide]): (a) a trustworthy pointer whose `live` is not older skips the seed; (b)
     *    with none, the adopt scan adopts a newer stored generation that re-verifies, else the seed installs.
     * 7. Each attachment inflated under `min(signed size, MAX_FILTER_BYTES)`, checked against its signed size and
     *    SHA-256, and written as the sync writes it, as its blob (a stored one that re-hashes is reused).
     * 8. `index.bin` rebuilt ([buildIndex]) and byte-compared with the archive's; every placed filter's encoding listed
     *    by the engine, and `seed.json`'s `filterFormat` the full filter's decoded encoding.
     * 9. The install ([install]): `SIGNED`, `fromSeed`, [Freshness.SEED_SIGNED_TIME], generation id `"<ts>/<last placed
     *    record id>"`, `updater.json` with `seedInstalledAtMillis` = now and the watermark at `max(watermark, <ts>)`, or
     *    at `<ts>` when no generation loaded (§7.1). A seed load never prunes and never deletes (§6.5).
     *
     * Any seed fault is [SeedLoad.Unreadable]; a failed `prepare` or `activate` is too (§6.5: "the corresponding load
     * failure, `SEED_UNREADABLE` for the seed"). A read interrupted by the thread's interrupt (okio's `InterruptedIOException`) is `SEED_UNREADABLE` as
     * well, with the interrupt kept.
     */
    fun load(nowMillis: Long): SeedLoad = Attempt(nowMillis).run()

    /** What the header read gave: the archive and its header's `filterFormat`, or the load's end. */
    private sealed interface HeaderRead {
        class Read(
            val archive: SeedArchive,
            val filterFormat: FilterFormat,
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
            return HeaderRead.Ended(
                SeedLoad.ChannelMismatch(header.channel, listOf(warning(WarningCode.SEED_CHANNEL_MISMATCH, message))),
            )
        }
        return HeaderRead.Read(archive, format)
    }

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
     * What the store holds for this dataset and channel when the load reads it: the [updater] record, the [pointer]
     * when it read, and its `live` generation through Load's steps 1 and 2 ([live]) when that read too, which makes the
     * pointer trustworthy (rule (a) of the seed-load rule, spec §6.5). [counted] names each generation file whose
     * failure this read counted, so the adopt scan does not count it again.
     */
    private class Stored(
        val updater: UpdaterRecord,
        val pointer: Pointer?,
        val live: StoredGeneration?,
        val counted: Set<String>,
    ) {
        val trusted: Boolean get() = live != null
    }

    /** One load's state. A seed load never deletes anything (§6.5), so it has nothing to undo. */
    @OptIn(RevoktInternalApi::class)
    private inner class Attempt(
        private val now: Long,
    ) {
        private var storeFailures = 0

        /** Whether the current step reads or writes the store, so a throw there is a store failure. */
        private var inStore = false

        private var installing = false

        /** Whether this load counted a stored generation as rejected ([adoptable]), whose rotted blobs it then rewrites. */
        private var rejected = false

        /** The generation files whose failure this load counted, so each is counted once. */
        private val counted = HashSet<String>()

        @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable, an OutOfMemoryError too.
        fun run(): SeedLoad =
            try {
                steps()
            } catch (t: Throwable) {
                restoreInterrupt(t)
                thrown(t)
            }

        /**
         * The load after [t] escaped a step: a seed fault is [SeedLoad.Unreadable]; any non-fatal throw while reading
         * or writing the store is [SeedLoad.Failed] at `STORE` with a store failure;
         * anything else is unreadable, with a store failure once the install began (§6.5: an `OutOfMemoryError` during an
         * install counts one). Nothing is deleted.
         */
        private fun thrown(t: Throwable): SeedLoad {
            val storeFault = inStore && t !is SeedFormatException && !isFatal(t)
            if (storeFault) {
                storeFailures++
                logger.safeLog(LogLevel.WARN, "${store.root}: the seed load failed at STORE", t)
                val detail = t.message ?: t.toString()
                return SeedLoad.Failed(SyncFailure.STORE_FAILED, detail, t, false, storeFailures)
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

        private fun steps(): SeedLoad {
            val opened =
                when (val read = header()) {
                    is HeaderRead.Ended -> return read.load
                    is HeaderRead.Read -> read
                }
            val archive = opened.archive
            val verified = verify(archive)
            val ts = verified.timestamp
            val crlite =
                when (val check = CrliteSchema.check(verified.records, channel, RevoktLimits.MAX_CHANGESET_RECORDS)) {
                    is RecordCheck.Passed -> check.records
                    is RecordCheck.Rejected -> fail("records.json fails the schema: ${check.detail}")
                }
            val records = crlite.map { it.toFilterRecord() }
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
            decide(stored, ts, verified.path)?.let { return it }
            val bodies = Bodies()
            val bySeedEntry = entries.zip(signed).toMap()
            val caps = entries.zip(signed) { e, r -> e to minOf(r.attachment.size, RevoktLimits.MAX_FILTER_BYTES) }
            archive.read(caps) { entry, bytes -> bodies.write(bySeedEntry.getValue(entry), bytes) }
            val built =
                when (val build = buildIndex(records, channel) { bodies.read(byId.getValue(it.id)) }) {
                    is IndexBuild.Built -> build
                    is IndexBuild.Refused -> fail("index.bin cannot be rebuilt: $build")
                }
            if (!built.index.contentEquals(verified.index)) fail("the shipped index.bin differs from the rebuilt one")
            bodies.unlisted(placed)?.let { fail("${it.record.id} is in an encoding the engine does not list") }
            val pending =
                PendingGeneration(
                    file(verified),
                    built.filters,
                    built.index,
                    bodies.format(placed, opened.filterFormat),
                )
            // §7.1: a seed that installs because no generation loaded (no trustworthy pointer, nothing live in the
            // engine) sets the watermark to its <ts>, as the sync's install does; beside a loaded generation it keeps the
            // max.
            val engineLive = snapshot.snapshot.datasets[Dataset.CRLITE]?.generationId
            val noneLoaded = !stored.trusted && engineLive == null
            return installed(pending, stored.updater, noneLoaded = noneLoaded)
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
            val signature = fixed.getValue(SeedArchive.SIGNATURE)
            val x5u = fixed.getValue(SeedArchive.X5U)
            val signed = verifySignedRecords(recordsJson, signature, x5u, policy.pinnedRootSpkis, verifier)
            val index = fixed.getValue(SeedArchive.INDEX)
            return Verified(signed.records, signed.timestamp, signed.path, signature, recordsJson, index)
        }

        /**
         * `updater.json`, the pointer, and each generation it names through Load's steps 1 and 2 (the decisions on #138
         * and the seed-load rule). A read that throws fails the load as a store failure, nothing written ([thrown]). Each
         * fault is counted here, once, where it is found, and the install is told so ([Publication.pointerCounted]): a
         * malformed `updater.json` (read as absent, §6.5; the install writes a fresh one), a malformed pointer, and each
         * pointed generation that does not read.
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
            val pointer =
                when (val read = store.pointer()) {
                    StoreRead.Absent -> {
                        return Stored(updater, null, null, counted)
                    }

                    StoreRead.Malformed -> {
                        storeFailures++
                        logger.safeLog(LogLevel.WARN, "${store.root}: the pointer is malformed")
                        return Stored(updater, null, null, counted)
                    }

                    is StoreRead.Found -> {
                        read.value
                    }
                }
            var live: StoredGeneration? = null
            for (name in listOfNotNull(pointer.live, pointer.previous)) {
                when (val read = store.stored(name)) {
                    is StoreRead.Found -> {
                        if (name == pointer.live) live = read.value
                    }

                    else -> {
                        storeFailures++
                        counted += name
                        logger.safeLog(
                            LogLevel.WARN,
                            "${store.root}: the pointed generation $name does not read ($read)",
                        )
                    }
                }
            }
            return Stored(updater, pointer, live, counted)
        }

        /**
         * The seed-load rule (spec §6.5), or null to install the seed. Every generation is Mozilla-signed (#218), so no
         * trust class is compared.
         * - (a) A trustworthy pointer: its `live` reads. The seed is [SeedLoad.Skipped] when that generation, or the one
         *   the engine holds live, is not older than it; the loader loads it.
         * - (b) Anything else (no pointer, a malformed one, or a `live` that does not read): the adopt scan. Every
         *   generation file through Load's step 1 (one that fails counts a store failure); the candidates newer than the
         *   seed and not older than the generation the engine serves, newest first and ties by name, each through steps 2
         *   to 4 and the signature check ([adoptable]); the first that passes is [SeedLoad.Adopted]: `updater.json` is
         *   written from the record read with the watermark raised to its `<ts>`, then the pointer is flipped to it alone.
         *   With none, a generation the engine holds live that is newer than the seed is [SeedLoad.Skipped] (never rolled
         *   back); otherwise the seed installs.
         */
        private fun decide(
            stored: Stored,
            ts: Long,
            seed: X5uPath,
        ): SeedLoad? {
            val engineLive =
                snapshot.snapshot.datasets[Dataset.CRLITE]
                    ?.takeIf { it.generationId != null }
                    ?.sourceTimestampMillis
            if (stored.trusted) {
                val liveTs = checkNotNull(stored.live).timestampMillis
                val notOlder = listOfNotNull(engineLive, liveTs).maxOrNull()?.takeIf { it >= ts }
                return notOlder?.let { SeedLoad.Skipped(ts, it, storeFailures) }
            }
            // Never adopt below the generation the engine serves: that would roll it back (#235's review).
            val floor = maxOf(ts + 1, engineLive ?: Long.MIN_VALUE)
            val candidates = stored { scan(floor) }
            val adopted = candidates.firstOrNull { (name, file) -> stored { adoptable(name, file, seed) } }
            if (adopted != null) {
                val (name, file) = adopted
                stored {
                    // The record read (an absent or malformed one replaced), its watermark raised to the adopted <ts>,
                    // before the flip: a failed flip then leaves an honest failure, and the next load adopts again.
                    val watermark = maxOf(stored.updater.watermarkMillis ?: Long.MIN_VALUE, file.lastModified)
                    store.writeUpdater(stored.updater.copy(watermarkMillis = watermark), now)
                    store.point(Pointer(name, null))
                }
                logger.safeLog(LogLevel.INFO, "${store.root}: adopted $name, newer than the seed's $ts")
                return SeedLoad.Adopted(name, file.lastModified, storeFailures)
            }
            return engineLive?.takeIf { it > ts }?.let { SeedLoad.Skipped(ts, it, storeFailures) }
        }

        /**
         * The adopt scan's candidates (spec §6.5 rule (b)): every generation file through Load's step 1 whose `<ts>` is at
         * least [floor], newest first, ties broken by name. A file that fails step 1 counts one store failure, unless
         * [read] counted it already; a file below the floor is not counted.
         */
        private fun scan(floor: Long): List<Pair<String, GenerationFile>> {
            val found = ArrayList<Pair<String, GenerationFile>>()
            for (name in store.generationNames().sorted()) {
                when (val read = store.readGeneration(name)) {
                    is StoreRead.Found -> {
                        if (read.value.lastModified >= floor) found += name to read.value
                    }

                    else -> {
                        if (counted.add(name)) {
                            storeFailures++
                            logger.safeLog(LogLevel.WARN, "${store.root}: the generation file $name does not read")
                        }
                    }
                }
            }
            return found.sortedWith(compareByDescending<Pair<String, GenerationFile>> { it.second.lastModified })
        }

        /**
         * Whether the stored generation [name] ([file], through step 1) re-verifies for adoption: Load's steps 2 to 4
         * pass (its records place, every blob re-hashes, the index rebuilds) and, when its signer leaf is the [seed]'s
         * verified leaf, its signature verifies over the canonical serialisation of its records
         * ([ContentSignature.verifyRawPayload]); a generation signed by another leaf is trusted at the OS level (§6.5).
         * One that does not counts one store failure, once.
         */
        private fun adoptable(
            name: String,
            file: GenerationFile,
            seed: X5uPath,
        ): Boolean {
            val ok = reVerifies(name, file, seed)
            if (!ok) {
                rejected = true
                if (counted.add(name)) storeFailures++
                logger.safeLog(LogLevel.WARN, "${store.root}: $name is newer than the seed but does not re-verify")
            }
            return ok
        }

        private fun reVerifies(
            name: String,
            file: GenerationFile,
            seed: X5uPath,
        ): Boolean {
            val generation = store.place(name, file) ?: return false
            store.loadFiles(generation) ?: return false
            val seedLeaf =
                seed.links[0]
                    .der
                    .toByteString()
                    .sha256()
            if (file.signerLeafSha256 != seedLeaf) return true
            val text = file.signature.base64Url().trimEnd('=')
            return ContentSignature
                .verifyRawPayload(verifier, file.payload, text, ContentSignature.MODE, seed.leafSpki)
                .verified
        }

        /** The bodies of the seed's generation, each written as its blob as it is inflated. */
        private inner class Bodies {
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
                stored {
                    // A blob of a generation this load counted as rejected is that fault, counted once (#235).
                    if (store.putBlob(bytes) == BlobWrite.REWRITTEN && !rejected) storeFailures++
                }
            }

            /** [r]'s body as written, re-hashed, for [buildIndex]; its encoding is noted. */
            fun read(r: CrliteRecord): ByteArray {
                val bytes =
                    stored { checkNotNull(store.readBlob(r.attachment.sha256)) { "the blob of ${r.id} is gone" } }
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
                placed.firstOrNull { checkNotNull(encodings[it.record.id]).toFilterFormat() !in engine.formats }

            /** The full's encoding, the generation's format, which `seed.json`'s [filterFormat] must name (§6.5). */
            fun format(
                placed: List<PlacedFilter>,
                filterFormat: FilterFormat,
            ): FilterFormat {
                val format = checkNotNull(encodings[placed.first { it.full }.record.id]).toFilterFormat()
                if (format != filterFormat) {
                    fail("filterFormat $filterFormat is not the full filter's encoding, $format")
                }
                return format
            }
        }

        /**
         * The seed's generation file (spec §6.5): its verified records and `<ts>`, the signature that verified them and its
         * leaf's SHA-256, [Freshness.SEED_SIGNED_TIME] and `seedFormat`.
         */
        private fun file(verified: Verified): GenerationFile {
            val raw =
                RawSignature.decode(verified.signature.decodeToString()) ?: fail("the signature is not raw r || s")
            val records = ContentSignature.payloadRecords(verified.records) ?: fail("records.json is not a payload")
            return GenerationFile(
                dataset = Dataset.CRLITE,
                channel = channel,
                freshness = Freshness.SEED_SIGNED_TIME,
                seedFormat = SEED_FORMAT.toInt(),
                signature = raw.toByteString(),
                signerLeafSha256 =
                    verified.path.links[0]
                        .der
                        .toByteString()
                        .sha256(),
                records = records,
                lastModified = verified.timestamp,
            )
        }

        /**
         * Step 9: [install] of [pending] over the [read] record; a seed load never prunes (§6.5). The watermark, written in
         * the install's own `updater.json` write, is [pending]'s `<ts>` when [noneLoaded], else the higher of it and the
         * stored one.
         */
        private fun installed(
            pending: PendingGeneration,
            read: UpdaterRecord,
            noneLoaded: Boolean,
        ): SeedLoad {
            val ts = pending.file.lastModified
            val raised = maxOf(read.watermarkMillis ?: Long.MIN_VALUE, ts)
            val updated =
                read.copy(
                    watermarkMillis = if (noneLoaded) ts else raised,
                    seedInstalledAtMillis = now,
                )
            // §8: the gate opens once a sync attempt completes after the seed's install, or at once with no fetching source.
            val gateOpen = !policy.fetchingSource || (read.datasetLastAttemptAtMillis ?: Long.MIN_VALUE) >= now
            val publication = Publication(true, SEED_FORMAT.toInt(), gateOpen, now, pointerCounted = true)
            installing = true
            val result = install(pending, engine, store, snapshot, publication, updated, logger)
            storeFailures += result.storeFailures
            return when (result) {
                is InstallResult.Installed -> {
                    SeedLoad.Installed(result.name, result.generationId, result.generationEpoch, ts, storeFailures)
                }

                is InstallResult.Failed -> {
                    val detail = "the install failed: $result"
                    if (!result.activated && result.failure != SyncFailure.STORE_FAILED) {
                        unreadable(detail, result.cause, storeFailures)
                    } else {
                        SeedLoad.Failed(
                            result.failure,
                            detail,
                            result.cause,
                            result.activated,
                            storeFailures,
                        )
                    }
                }
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
            listOf(warning(WarningCode.SEED_UNREADABLE, detail)),
        )
    }

    private fun warning(
        code: WarningCode,
        message: String,
    ): RevoktWarning =
        RevoktWarning
            .Builder()
            .code(code)
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
    }
}

private fun fail(message: String): Nothing = throw SeedFormatException(message)

/** A seed's `records.json` once [verifySignedRecords] verified it: its records, its signed `<ts>` and the x5u path. */
internal class SignedRecords(
    val records: List<JsonObject>,
    val timestamp: Long,
    val path: X5uPath,
)

/**
 * Steps 2 to 4 of [SeedLoader.load], over a seed's raw entries: [x5uPem] read as PEM and validated to [pins]
 * ([validateX5uChain], every check but validity); [signature] over [recordsJson]'s bytes unchanged
 * ([ContentSignature.verifyRawPayload]); `records.json` decoded, which must be the canonical payload of its own records
 * and `<ts>`; then the x5u validity periods at that `<ts>` ([checkValidity]). Nothing here depends on the seed format:
 * it is what Firefox re-verifies of its local data (`RemoteSettingsClient`'s `validateCollectionSignature`), and the
 * weekly job's floor check runs it alone ([verifySeedSignature]). Every failure is a [SeedFormatException].
 */
internal fun verifySignedRecords(
    recordsJson: ByteArray,
    signature: ByteArray,
    x5uPem: ByteArray,
    pins: Set<ByteString>,
    verifier: SignatureVerifier,
): SignedRecords {
    val ders =
        when (val pem = X5uPem.read(x5uPem, RevoktLimits.MAX_X5U_BYTES)) {
            is X5uPemRead.Certificates -> pem.ders
            is X5uPemRead.Failed -> fail("x5u.pem is not a PEM chain: ${pem.reason}")
        }
    val path =
        when (val chain = validateX5uChain(ders, pins, verifier)) {
            is X5uChainResult.Valid -> chain.path
            is X5uChainResult.Failed -> fail("the x5u chain fails: $chain")
        }
    val checked =
        ContentSignature.verifyRawPayload(
            verifier,
            recordsJson,
            signature.decodeToString(),
            ContentSignature.MODE,
            path.leafSpki,
        )
    if (!checked.verified) fail("the signature over records.json does not verify: $checked")
    val (records, ts) = decodeSigned(recordsJson)
    when (val validity = checkValidity(path, ts)) {
        is X5uValidity.Valid -> Unit
        is X5uValidity.ClockSkew -> fail("x5u link ${validity.certIndex} is outside its validity at $ts")
    }
    return SignedRecords(records, ts, path)
}

/** The latest `<ts>` a seed's `records.json` may hold: 13 digits, the width every millisecond timestamp has had since 2001. */
private const val MAX_TIMESTAMP = 9_999_999_999_999L

/** The records and `<ts>` of the verified [bytes], which must be the canonical payload of both. */
private fun decodeSigned(bytes: ByteArray): Pair<List<JsonObject>, Long> {
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
