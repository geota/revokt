// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// detekt 1.23 resolves types with a Kotlin 2.0 compiler that cannot read the 2.4 stdlib's metadata, so it reports the code
// after an inline lambda's non-local return or `Nothing` call as unreachable; kotlinc's own unreachable-code check holds.
@file:Suppress("UnreachableCode")
@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.GenerationFiles
import dev.revokt.RevoktStorage
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.VerifyResult
import dev.revokt.engine.fetch.client
import dev.revokt.engine.fetch.json
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.runtime.CrliteRuntime
import dev.revokt.engine.seed.SeedFixture
import dev.revokt.engine.seed.SeedLoader
import dev.revokt.engine.store.GenerationFileJson
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.PointerJson
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.log
import dev.revokt.engine.verify.RawSignature
import dev.revokt.testing.SplitMix64
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayInputStream

/**
 * Where a [StoreModel] run draws its choices: a seed ([seeded]) for the fixed-seed test, or a fuzzer's bytes ([bytes])
 * for the Jazzer target, so one model serves both (#214).
 */
internal fun interface Choices {
    /** A value in `[0, bound)`. */
    fun int(bound: Int): Int

    companion object {
        fun seeded(seed: Long): Choices {
            val rng = SplitMix64(seed)
            return Choices { rng.nextInt(it) }
        }

        /** One byte per choice, then zeros once [data] runs out. */
        fun bytes(data: ByteArray): Choices {
            var i = 0
            return Choices { bound -> if (i < data.size) (data[i++].toInt() and 0xFF) % bound else 0 }
        }
    }
}

/**
 * An in-memory storage whose [names] keep the order keys were first written in, never a hash order: a run's choices
 * and the code's own iteration over the store then replay for one seed whatever the keys' names are (a generation file
 * is named by its bytes, which hold the x5u leaf's hash, and the fixture signs a fresh leaf in every JVM).
 */
internal class OrderedStorage : RevoktStorage {
    private val files = LinkedHashMap<String, ByteArray>()

    @Synchronized
    override fun read(name: String): ByteArray? = files[name]?.copyOf()

    @Synchronized
    override fun write(
        name: String,
        bytes: ByteArray,
    ) {
        files[name] = bytes.copyOf()
    }

    @Synchronized
    override fun delete(name: String) {
        files.remove(name)
    }

    @Synchronized
    override fun names(): Set<String> = LinkedHashSet(files.keys)

    override fun lock(): AutoCloseable = AutoCloseable {}
}

/** What the start task should serve (spec §6.5 crash recovery), as [StoreModel] reads the store. */
private sealed interface ExpectedStart {
    /** The stored generation [name], [adopted] under rule (b) or the pointer's. */
    data class Stored(
        val name: String,
        val adopted: Boolean,
    ) : ExpectedStart

    /** The seed, installed with [noneLoaded] (its watermark set, not raised). */
    data class Seed(
        val noneLoaded: Boolean,
    ) : ExpectedStart

    /** Nothing. */
    data object None : ExpectedStart
}

/** An invariant of [StoreModel] that a run broke; the message names the run's steps. */
internal class ModelViolation(
    message: String,
    cause: Throwable? = null,
) : AssertionError(message, cause)

/**
 * The model-based fault-injection test of #214 (the 2026-11-16 design audit, C-F1) over the content-addressed store
 * (#287, design note section 14): [StoreLayout], Load, [install], prune, [CrliteSync] and [SeedLoader] on an in-memory
 * storage with an operation hook. One [run] draws a sequence of actions from [Choices]:
 * - a sync of a scripted Remote Settings: a new `<ts>` (some deltas, sometimes a re-parented full), the same changeset
 *   again, an earlier publication (inside or beyond the rollback window), or the same records re-signed;
 * - a sync whose n-th storage operation throws, or whose engine `prepare` throws;
 * - a process stop at the n-th operation (every later write and delete is lost), or a stop that also loses an arbitrary
 *   subset of the deletes before it (deletes need no durability, section 8), then a fresh loader;
 * - a restart: a fresh loader (an empty snapshot and engine over the same store), whose start task loads a seed half
 *   the time, a publication's own records signed as a seed, older or newer than what is stored;
 * - a fault, a `prepare` that throws or a stop lands, half the time, on the sync of a new publication, so that it hits an
 *   install, a flip or a prune rather than a sync with nothing to do;
 * - damage: a flipped byte or a truncation in any key, a flip inside a generation file's records that keeps it
 *   parseable (only the re-hash catches it), a flipped hex digit in the pointer's `live` or `previous`, damage to a blob
 *   `live` and `previous` share, a deleted `current`, and a `generationVersion` too new.
 *
 * After every operation and every step it checks the invariants of design note section 14 (each failure names the
 * steps so far):
 * - **I1** what the pointer names as `live` or `previous`, and the generation the snapshot holds live, loads, unless
 *   damage or a lost delete hit its file or a blob it names; damage is forgotten once the code rewrites or deletes the key;
 *   at a restart, the real start task (seed and chain) serves what §6.5's chain names, and decodes nothing older than
 *   the seed;
 * - **I2** no generation file the last written pointer names, nor the served one, and no blob such a file names, is
 *   deleted or overwritten with other bytes; beside a pointer that did not read before the sync, or that named a
 *   generation failing Load's steps 1 and 2 then, nothing under `generations/` or `blobs/` is deleted at all, and a seed
 *   load deletes nothing either; and the generation served when a sync began survives it, as `live` or `previous` when
 *   the sync's flip landed (#242, #249). "Pointed to" is the last pointer the code wrote, and #246's exception is gone: a
 *   damaged but readable `current` names a key no stored file hashes to;
 * - **I3** `updater.json` is written only by a sync whose read of it returned (#209), and its watermark never goes
 *   backwards, unless damage hit the file or an install made with no generation live set it to that install's `<ts>`;
 * - **I4** every sync returns; once the faults stop, the last publication settles and a new one installs within
 *   [RECOVERY] clean syncs, and a sync over a store that holds every blob it needs fetches no attachment;
 * - **I5** while the snapshot holds a generation live, no publication below the floor installs but the live one's own;
 * - **I6** every write under `blobs/` or `generations/` writes bytes whose SHA-256 is the key's name;
 * - **I7** after a clean `INSTALLED` sync over a pointer that read, every generation it named reading, the store holds
 *   exactly `current`, `updater.json`, the generation files the pointer names, every newer one that passes Load's steps
 *   1 and 2, and their blobs; a re-flip (§6.5: `INSTALLED` with no publish) is a heal flip that prunes nothing, which
 *   I2 judges;
 * - **I8** a generation file on disk that reads names only blobs on disk, unless damage or a lost delete hit them;
 * - **I9** whatever the engine is given to `prepare` is the publication's own filters, byte for byte, under their derived
 *   names, with the index [buildIndex] builds from them: damaged bytes make the load fail, never yield something else;
 * - **I10** a seed load with no trustworthy pointer adopts exactly the newest undamaged stored generation newer than the
 *   seed and not older than the served one, ties by name, or none, and writes nothing but the pointer and `updater.json`
 *   when it adopts.
 */
internal class StoreModel : SeedFixture() {
    /** The storage of one run: every operation counted, faults injected on cue, and the I2, I3 and I6 checks. */
    inner class ModelStorage : RevoktStorage {
        val inner: RevoktStorage = OrderedStorage()
        private var ops = 0

        /** The operation of this step that throws, or -1. */
        var throwAt = -1

        /** The operation of this step from which every write and delete is lost (a process stop), or -1. */
        var stopAt = -1

        /** Whether this step's read of `updater.json` returned. */
        var updaterRead = false

        /** The last pointer the code wrote, whatever damage did to `current` since. */
        var pointer: Pointer? = null

        /** The keys damage hit, and the keys a lost delete brought back; exempt from I1 and I8. */
        val damaged = HashSet<String>()

        /** Every generation file the code wrote, by name: the ledger I2's blob protection and I9 read. */
        val ledger = HashMap<String, ByteArray>()

        /** The generation file the snapshot serves, protected like a pointed one while the loader lives. */
        var served: () -> String? = { null }

        /** Whether this step may delete under `generations/` or `blobs/` at all (I2's fail-closed clause). */
        var deletesAllowed = false

        /** This step's deletes that landed, each with the bytes it removed, for a stop that loses some of them. */
        val deleted = ArrayList<Pair<String, ByteArray>>()

        /** Every key written under `blobs/` or `generations/` this step, for I10. */
        val contentWrites = ArrayList<String>()

        val violations = ArrayList<String>()

        /** The operation and key the armed throw or stop hit, for the trail. */
        var fault: String? = null

        /** Whether this step's write of `current` landed (not lost to a stop, not thrown). */
        var pointerWritten = false

        /** Starts a step's operation count, with its faults. */
        fun arm(
            throwAt: Int,
            stopAt: Int,
            deletes: Boolean,
        ) {
            ops = 0
            this.throwAt = throwAt
            this.stopAt = stopAt
            updaterRead = false
            fault = null
            pointerWritten = false
            deletesAllowed = deletes
            deleted.clear()
            contentWrites.clear()
        }

        val stopped: Boolean get() = stopAt in 0..<ops

        /** The operations this step has made. */
        val count: Int get() = ops

        private fun op(key: String) {
            val n = ops++
            if (n == throwAt || n == stopAt) fault = "op $n ${key.removePrefix("$root/")}"
            check(n != throwAt) { "injected fault at operation $n" }
        }

        override fun read(name: String): ByteArray? {
            op(name)
            val bytes = inner.read(name)
            if (name == "$root/updater.json") updaterRead = true
            return bytes
        }

        override fun write(
            name: String,
            bytes: ByteArray,
        ) {
            op(name)
            if (stopped) return
            if (name == "$root/updater.json" &&
                !updaterRead
            ) {
                violations += "I3: updater.json written from an unread record"
            }
            if (isContent(name)) {
                contentWrites += name
                // I6: a content-addressed key holds only the bytes its name promises; a protected key is never given
                // other bytes, which this check already rules out.
                if (bytes.toByteString().sha256().hex() != name.substringAfterLast('/')) {
                    violations += "I6: ${short(name)} written with bytes of another hash"
                }
                if (name.startsWith("$root/generations/")) ledger[name.substringAfterLast('/')] = bytes.copyOf()
            }
            inner.write(name, bytes)
            damaged -= name
            if (name == "$root/current") {
                pointerWritten = true
                PointerJson.read(bytes)?.let { pointer = it }
            }
        }

        override fun delete(name: String) {
            op(name)
            if (stopped) return
            if (isContent(name)) {
                if (!deletesAllowed) {
                    violations +=
                        "I2: ${short(name)} deleted where nothing may be (B2, seed load, heal)"
                }
                protectedBy(name)?.let { violations += "I2: ${short(name)} deleted while $it is pointed to or served" }
                inner.read(name)?.let { deleted += name to it }
            }
            inner.delete(name)
            damaged -= name
        }

        override fun names(): Set<String> {
            op("names")
            return inner.names()
        }

        override fun lock(): AutoCloseable = AutoCloseable {}

        private fun isContent(name: String): Boolean =
            name.startsWith("$root/blobs/") || name.startsWith("$root/generations/")

        /** The pointed or served generation file that is [name] or names the blob [name], or null. */
        private fun protectedBy(name: String): String? {
            val held = listOfNotNull(pointer?.live, pointer?.previous, served()).distinct()
            val last = name.substringAfterLast('/')
            if (name.startsWith("$root/generations/")) return last.takeIf { it in held }
            return held.firstOrNull { last in trueBlobs(it) }
        }

        /** The blobs the generation file [name] names, from the bytes the code wrote under it. */
        fun trueBlobs(name: String): Set<String> {
            val bytes = ledger[name] ?: return emptySet()
            val file = GenerationFileJson.readUnhashed(bytes, Long.MAX_VALUE) ?: return emptySet()
            return truth.place(name, file)?.blobNames.orEmpty()
        }

        /** Whether damage or a lost delete hit the generation file [name] or a blob it names. */
        fun hit(name: String): Boolean =
            "$root/generations/$name" in damaged || trueBlobs(name).any { "$root/blobs/$it" in damaged }

        private fun short(name: String): String = name.removePrefix("$root/")
    }

    /** One publication of the scripted collection: its `<ts>` and records, and the bodies they name. */
    private class Publication(
        val ts: Long,
        val records: List<Rec>,
    ) {
        val generationId: String = "$ts/${records
            .filter { it.incremental }
            .maxWithOrNull(
                order,
            )?.id ?: records.first().id}"

        private companion object {
            val order = compareBy<Rec>({ it.effectiveTimestamp }, { it.id })
        }
    }

    /**
     * Content signatures the model can replay: valid exactly when they are [fakeSignature] of the payload, variant 0 or
     * 1 (a re-sign), and every other signature (the x5u chain's) checked by the fixture's real verifier. ECDSA signs with
     * fresh randomness, and a generation file's name is the hash of its bytes, signature included: with real signatures
     * one seed's run would name its files differently every time, and its choices would not replay.
     */
    private val modelVerifier =
        object : SignatureVerifier {
            override fun verify(
                sigAlg: ByteArray,
                spki: ByteArray,
                message: ByteArray,
                signature: ByteArray,
            ): VerifyResult {
                val prefix = "Content-Signature:\u0000".encodeToByteArray()
                if (message.size < prefix.size || !message.copyOf(prefix.size).contentEquals(prefix)) {
                    return verifier.verify(sigAlg, spki, message, signature)
                }
                val payload = message.copyOfRange(prefix.size, message.size)
                val valid = (0..1).any { RawSignature.toDer(fakeRaw(payload, it)).contentEquals(signature) }
                return if (valid) VerifyResult.VERIFIED else VerifyResult.INVALID
            }

            override fun unsupportedOids(): Set<String> = verifier.unsupportedOids()
        }

    /** A 96-byte raw r ‖ s pair derived from [payload] and [variant] alone. */
    private fun fakeRaw(
        payload: ByteArray,
        variant: Int,
    ): ByteArray {
        val a = (payload + variant.toByte()).toByteString().sha256().toByteArray()
        val b =
            (payload + (variant + 2).toByte())
                .toByteString()
                .sha512()
                .toByteArray()
                .copyOf(64)
        return (a + b).copyOf(96).also {
            it[0] = (it[0].toInt() or 1).toByte()
            it[48] = (it[48].toInt() or 1).toByte()
        }
    }

    /** [fakeRaw] as the changeset's `signature` text: unpadded base64url. */
    private fun fakeSignature(
        payload: ByteArray,
        variant: Int,
    ): String =
        java.util.Base64
            .getUrlEncoder()
            .withoutPadding()
            .encodeToString(fakeRaw(payload, variant))

    /** A layout over the model storage's inner store: the model's own reads, uncounted and never faulted. */
    private lateinit var truth: StoreLayout

    /** One run's world: its storage, store, loader, server and clock. */
    @Suppress("LargeClass") // The model's one world: its steps, damage and invariants read the same state.
    private inner class World(
        private val choices: Choices,
    ) {
        val storage = ModelStorage()
        val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
        var snapshot = freshSnapshot()
        var engine = engine()
        val server = Server()
        val trail = ArrayList<String>()
        var now = ts + hour
        val published = ArrayList<Publication>()
        val pool = (1..DELTAS).map { delta(it) }
        var full = filter("full-1", false, ts - day, 1)
        var watermark: Long? = null

        /** The newest `<ts>` a sync installed, the model's own; null once damage hit `updater.json`. */
        var highWater: Long? = null

        /** The attachment fetches of the last sync. */
        var lastFetches = 0

        init {
            truth = StoreLayout(storage.inner, Dataset.CRLITE, CrliteChannel.COMPAT)
            storage.served = ::served
            publish(newPublication())
        }

        fun served(): String? =
            snapshot.snapshot.datasets[Dataset.CRLITE]
                ?.takeIf { it.generationId != null }
                ?.generationFile

        private fun freshSnapshot(): SnapshotRef =
            SnapshotRef(
                GenerationSnapshot(
                    0,
                    mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false)),
                    null,
                ),
            )

        /** The test engine with I9's check on every `prepare`. */
        private fun engine(): UpdateFixtures.TestEngine =
            UpdateFixtures.TestEngine().apply { onPrepare = ::checkPrepared }

        /** Whether the next `prepare` throws (an injected engine fault). */
        var prepareThrows = false

        /** I9: what `prepare` is given is the publication's own filters under their derived names, and their index. */
        private fun checkPrepared(files: GenerationFiles) {
            require(!prepareThrows) { "injected prepare fault" }
            val p =
                published.firstOrNull { it.generationId == files.generationId }
                    ?: fail("I9: prepare was given ${files.generationId}, no publication's generation")
            val records =
                p.records.map {
                    FilterRecord(
                        it.id,
                        it.channel,
                        it.incremental,
                        it.effectiveTimestamp,
                        it.filename,
                    )
                }
            val built = UpdateFixtures.built(records, p.records.associate { it.filename to it.body })
            val names = built.filters.map { it.name }.toSet() + StoreLayout.INDEX
            if (files.names != names) fail("I9: prepare was given ${files.names}, not $names")
            if (!files.bytes(StoreLayout.INDEX).contentEquals(built.index)) fail("I9: prepare was given another index")
            for (placed in built.filters) {
                val body = p.records.single { it.id == placed.record.id }.body
                if (!files
                        .bytes(
                            placed.name,
                        ).contentEquals(body)
                ) {
                    fail("I9: prepare was given other bytes for ${placed.name}")
                }
            }
        }

        private fun filter(
            id: String,
            incremental: Boolean,
            effective: Long,
            logIndex: Int,
        ): Rec =
            Rec(
                id,
                incremental,
                effective,
                "$id.filter" + if (incremental) ".delta" else "",
                UpdateFixtures.v4(listOf(log(logIndex) to (1_000L to 2_000L))),
                parent = if (incremental) "full" else null,
            )

        private fun delta(i: Int): Rec = filter("delta-$i", true, ts - day + i, 10 + i)

        private fun newPublication(): Publication {
            if (choices.int(6) == 0) {
                full = filter("full-${published.size + 2}", false, now - 2 * hour, 2 + published.size)
            }
            val deltas = pool.filter { choices.int(2) == 0 }
            return Publication(now - hour, listOf(full) + deltas)
        }

        /** Serves [p]; a re-sign draws a fresh ECDSA signature over the same payload. */
        fun publish(
            p: Publication,
            resign: Boolean = false,
        ) {
            if (p !in published) published += p
            server.ts = p.ts
            server.records = p.records.map { it.json() }
            server.bodies = (published.flatMap { it.records } + full).associate { it.location to it.body }
            val payload =
                checkNotNull(
                    dev.revokt.engine.verify.ContentSignature
                        .recordsJson(server.records.map(::json), p.ts),
                )
            server.signature = fakeSignature(payload, if (resign) 1 else 0)
            val ids = p.records.map { it.id }.toSet()
            val gone =
                published
                    .flatMap { it.records }
                    .map { it.id }
                    .filter { it !in ids }
                    .distinct()
            // Every record and a tombstone for every record gone: a superset of the changes after any cursor, which
            // merges over any earlier generation's records to this one's.
            server.since = { _ ->
                p.records.map { it.json() } + gone.map { """{"id":"$it","last_modified":${p.ts},"deleted":true}""" }
            }
        }

        /**
         * Whether a sync may delete under `generations/` and `blobs/` (I2's fail-closed clause, B2): the pointer reads
         * before it, and every generation it names passes Load's steps 1 and 2.
         */
        private fun mayPrune(): Boolean {
            val pointer = (truth.pointer() as? StoreRead.Found)?.value ?: return false
            return listOfNotNull(pointer.live, pointer.previous).all { truth.stored(it) is StoreRead.Found }
        }

        fun sync(
            throwAt: Int = -1,
            stopAt: Int = -1,
            prepareThrows: Boolean = false,
            loseDeletes: Boolean = false,
        ): SyncOutcome? {
            // I2: the generation served when the sync began survives it, if it loaded undamaged.
            val servedAtStart = served()?.takeIf { !storage.hit(it) && truth.load(it) is GenerationLoad.Loaded }
            val floor = rollbackFloor()
            val prunable = mayPrune()
            val readable = readableGenerations()
            val epoch = snapshot.snapshot.generationEpoch
            storage.arm(throwAt, stopAt, deletes = prunable)
            this.prepareThrows = prepareThrows
            val fetchesBefore = server.attachmentRequests().size
            val run =
                try {
                    CrliteSync(
                        client(server.fetcher, source),
                        store,
                        engine,
                        snapshot,
                        modelVerifier,
                        UpdateFixtures.Recording(),
                    ).syncOnce(now)
                } catch (t: Throwable) {
                    fail("I4: syncOnce threw $t")
                }
            this.prepareThrows = false
            lastFetches = server.attachmentRequests().size - fetchesBefore
            val stopped = storage.stopped
            val fault = storage.fault
            val pointerWritten = storage.pointerWritten
            if (stopped && loseDeletes) loseSomeDeletes()
            storage.arm(-1, -1, deletes = false)
            afterSync(run.result, servedAtStart, stopped, pointerWritten)
            rollback(run.result, floor, stopped)
            val clean = throwAt < 0 && stopAt < 0 && !prepareThrows
            // A re-flip publishes nothing, and never prunes (spec §6.5): I7 is an install's.
            val installed = run.result.outcome == SyncOutcome.INSTALLED && snapshot.snapshot.generationEpoch != epoch
            if (clean && prunable && installed) checkBoundedGarbage(readable)
            now += 7 * hour
            if (stopped) restart()
            last =
                fault?.let { " ($it)" }.orEmpty() +
                run.result.failure
                    ?.let { failure -> " $failure: ${run.result.cause}" }
                    .orEmpty()
            lastFailure = run.result.failure
            return run.result.outcome.takeUnless { stopped }
        }

        /** Every generation file passing Load's steps 1 and 2, with its `<ts>`. */
        private fun readableGenerations(): Map<String, Long> =
            truth
                .generationNames()
                .mapNotNull { n ->
                    (truth.stored(n) as? StoreRead.Found)?.value?.let {
                        n to
                            it.timestampMillis
                    }
                }.toMap()

        /** A stop that also loses an arbitrary subset of the step's deletes: each lost one's key comes back. */
        private fun loseSomeDeletes() {
            for ((key, bytes) in storage.deleted.toList()) {
                if (choices.int(2) == 0) {
                    storage.inner.write(key, bytes)
                    storage.damaged += key
                    trail += "  lost delete ${key.removePrefix("$root/")}"
                }
            }
        }

        /** I5's floor for a sync starting now, and the live timestamp it was raised to; null with nothing live. */
        private fun rollbackFloor(): Pair<Long, Long>? {
            val generation = snapshot.snapshot.datasets[Dataset.CRLITE]?.takeIf { it.generationId != null }
            val live = generation?.sourceTimestampMillis
            return live?.let { maxOf(highWater ?: it, it) to it }
        }

        /** I5 after a sync that ended as [result] from [floor], then the high-water mark an install raises. */
        private fun rollback(
            result: dev.revokt.SyncResult,
            floor: Pair<Long, Long>?,
            stopped: Boolean,
        ) {
            if (result.outcome != SyncOutcome.INSTALLED) return
            if (floor != null && server.ts < floor.first && server.ts != floor.second) {
                fail("I5: ${server.ts} installed, ${floor.first - server.ts} ms below the floor ${floor.first}")
            }
            if (floor == null) {
                // §7.1: an install with no generation loaded sets the watermark to its <ts>, lowered if it was higher. A
                // stopped one may or may not have written it, so either value is allowed then.
                highWater = if (stopped) highWater?.let { minOf(it, server.ts) } else server.ts
                watermark = if (stopped) watermark?.let { minOf(it, server.ts) } else server.ts
            } else if (!stopped) {
                highWater = maxOf(highWater ?: Long.MIN_VALUE, server.ts)
            }
        }

        /** I2's survival rule after a sync that ended as [result], when it was not [stopped]. */
        private fun afterSync(
            result: dev.revokt.SyncResult,
            servedAtStart: String?,
            stopped: Boolean,
            pointerWritten: Boolean,
        ) {
            if (stopped || servedAtStart == null) return
            // A sync whose write of `current` landed keeps it as the pointer's live or previous, whatever its outcome; one
            // that wrote none leaves it on disk.
            val flipped = result.outcome == SyncOutcome.INSTALLED || pointerWritten
            val kept = !flipped || servedAtStart == storage.pointer?.live || servedAtStart == storage.pointer?.previous
            if (truth.load(servedAtStart) !is GenerationLoad.Loaded || !kept) {
                fail(
                    "I2: the sync lost $servedAtStart, the generation the engine served when it began " +
                        "(loads: ${truth.load(servedAtStart)}, pointer ${storage.pointer})",
                )
            }
        }

        /**
         * I7 after a clean `INSTALLED` sync that pruned: exactly `current`, `updater.json`, the generation files the
         * pointer names, every newer one that passes Load's steps 1 and 2, and their blobs (damaged ones are kept by name).
         */
        private fun checkBoundedGarbage(before: Map<String, Long>) {
            val pointer = (truth.pointer() as? StoreRead.Found)?.value ?: fail("I7: no pointer after an install")
            val named = listOfNotNull(pointer.live, pointer.previous)
            val liveTs = (truth.stored(pointer.live) as? StoreRead.Found)?.value?.timestampMillis ?: return
            // Prune never deletes newer verified data: every file that passed Load's steps 1 and 2 before the sync and is
            // newer than the new live is still there.
            for ((n, at) in before) {
                if (at > liveTs &&
                    truth.stored(n) !is StoreRead.Found
                ) {
                    fail("I7: prune deleted $n, newer than the live one")
                }
            }
            val newer =
                truth.generationNames().filter { n ->
                    n !in named &&
                        (truth.stored(n) as? StoreRead.Found)?.value?.timestampMillis?.let { it > liveTs } == true
                }
            val kept = named + newer
            val blobs = kept.flatMap { n -> (truth.stored(n) as? StoreRead.Found)?.value?.blobNames.orEmpty() }
            val expected =
                setOf("$root/current", "$root/updater.json") + kept.map { "$root/generations/$it" } +
                    blobs.map { "$root/blobs/$it" }
            // Prune only deletes, so a key missing is no prune's (I1 and I8 judge it); a key beyond is garbage it kept.
            val beyond = storage.inner.names() - expected
            if (beyond.isNotEmpty()) fail("I7: after a prune the store still holds $beyond")
        }

        fun restart(seed: Boolean = false) {
            snapshot = freshSnapshot()
            storage.served = ::served
            engine = engine()
            trail += "restart"
            startTask(if (seed || choices.int(2) == 0) published[choices.int(published.size)] else null)
        }

        /**
         * The start task as [CrliteRuntime] runs it (§5.1, §6.5 crash recovery), the seed a publication's records signed
         * as one, or none: it deletes nothing (I2), it serves what §6.5's chain names from the model's own reads (I1 at
         * start), and an adopt writes no blob or generation file (I10).
         */
        @Suppress("CyclomaticComplexMethod") // One arm per way the start ends, each with its invariant.
        private fun startTask(p: Publication?) {
            val expected = expectedStart(p?.ts)
            val source =
                p?.let {
                    val seed = Seed(records = it.records, ts = it.ts)
                    seed.header = seed.header + ("filterFormat" to "V4")
                    seed.signature = fakeSignature(seed.payload(), 0)
                    val bytes = seed.bytes()
                    SeedSource.of { ByteArrayInputStream(bytes) }
                }
            val runtime =
                CrliteRuntime(
                    seed = source,
                    channel = CrliteChannel.COMPAT,
                    crlite = true,
                    fetchingSource = true,
                    engine = engine,
                    verifier = modelVerifier,
                    policy = dev.revokt.RevoktPolicy.DEFAULT,
                    pinnedRootSpkis = pinned,
                    storage = storage,
                    logger = UpdateFixtures.Recording(),
                )
            storage.arm(-1, -1, deletes = false)
            val loadSeed = runtime.startSeed(soleSeed = false, now)
            runtime.startTask(loadSeed) { now }
            val writes = storage.contentWrites.toList()
            storage.arm(-1, -1, deletes = false)
            snapshot = runtime.snapshot
            storage.served = ::served
            trail += "  start ${p?.ts ?: "with no seed"}: served ${served()}, expected $expected"
            storage.violations.firstOrNull()?.let { fail(it) }
            // §6.5: the chain decides on Load's step 1, so a stored generation older than the seed is not decoded.
            p?.let { seed ->
                engine.prepared.firstOrNull { it.substringBefore('/').toLong() < seed.ts }?.let {
                    fail("I1: the start task decoded $it, older than the seed at ${seed.ts}")
                }
            }
            val live = snapshot.snapshot.datasets[Dataset.CRLITE]?.takeIf { it.generationId != null }
            when (expected) {
                is ExpectedStart.Stored -> {
                    if (served() != expected.name) fail("I1: the start task served ${served()}, not ${expected.name}")
                    if (expected.adopted) {
                        if (writes.isNotEmpty()) fail("I10: the adopt wrote $writes")
                        val at = checkNotNull(live?.sourceTimestampMillis)
                        watermark = maxOf(watermark ?: Long.MIN_VALUE, at)
                        highWater = maxOf(highWater ?: Long.MIN_VALUE, at)
                    }
                }

                is ExpectedStart.Seed -> {
                    val seedTs = checkNotNull(p).ts
                    if (live?.fromSeed != true || live.sourceTimestampMillis != seedTs) {
                        fail("I10: the start task served ${served()}, not the seed at $seedTs")
                    }
                    // With nothing loaded the seed sets the watermark to its <ts> (§7.1); beside a trusted pointer, max.
                    if (expected.noneLoaded) {
                        watermark = seedTs
                        highWater = seedTs
                    } else {
                        watermark = maxOf(watermark ?: Long.MIN_VALUE, seedTs)
                        highWater = maxOf(highWater ?: Long.MIN_VALUE, seedTs)
                    }
                }

                ExpectedStart.None -> {
                    if (served() != null) fail("I1: the start task served ${served()}, not nothing")
                }
            }
        }

        /**
         * Rule (a) of [expectedStart] over [pointer]: what it serves, the seed beside an older trusted `live`, or null
         * to go on to rule (b), with the generations the chain failed added to [failed].
         */
        private fun ruleA(
            pointer: Pointer,
            seedTs: Long,
            failed: MutableSet<String>,
        ): ExpectedStart? {
            val live = (truth.stored(pointer.live) as? StoreRead.Found)?.value ?: return null
            if (live.timestampMillis < seedTs) return ExpectedStart.Seed(noneLoaded = false)
            if (serves(live.name)) return ExpectedStart.Stored(live.name, adopted = false)
            failed += live.name
            val previous = pointer.previous ?: return null
            val at = (truth.readGeneration(previous) as? StoreRead.Found)?.value?.lastModified
            if (at != null && at < seedTs) return null
            if (serves(previous)) return ExpectedStart.Stored(previous, adopted = false)
            failed += previous
            return null
        }

        /** Whether the model finds [name] intact and loading in full (Load's steps 1 to 4). */
        private fun serves(name: String): Boolean = intact(name) && truth.load(name) is GenerationLoad.Loaded

        /**
         * What §6.5's chain serves at start for a seed at [seedTs] (or none), from the model's own reads: without a seed,
         * the pointer's `live`, else its `previous`. With one, rule (a): a `live` that passes Load's steps 1 and 2 and is
         * older than the seed lets the seed install beside it; one not older is served, else its `previous` when that is
         * not older than the seed. Otherwise rule (b): the newest adoptable generation, not one the chain failed, else the
         * seed with nothing loaded.
         */
        private fun expectedStart(seedTs: Long?): ExpectedStart {
            val pointer = (truth.pointer() as? StoreRead.Found)?.value
            if (seedTs == null) {
                val name = listOfNotNull(pointer?.live, pointer?.previous).firstOrNull(::serves)
                return name?.let { ExpectedStart.Stored(it, adopted = false) } ?: ExpectedStart.None
            }
            val failed = HashSet<String>()
            val pointed = pointer?.let { ruleA(it, seedTs, failed) }
            if (pointed is ExpectedStart.Stored && failed.isNotEmpty()) {
                // The previous the chain fell back to: rule (b) still runs for the live that did not load, its floor
                // that previous, which stays served when nothing newer loads (#336).
                val at = checkNotNull((truth.stored(pointed.name) as? StoreRead.Found)?.value).timestampMillis
                return adopt(seedTs, failed + pointed.name, maxOf(seedTs + 1, at)) ?: pointed
            }
            return pointed ?: adopt(seedTs, failed, seedTs + 1) ?: ExpectedStart.Seed(noneLoaded = true)
        }

        /** Rule (b)'s adopt for a seed at [seedTs]: the newest adoptable generation from [floor] that loads, none of [failed]. */
        private fun adopt(
            seedTs: Long,
            failed: Set<String>,
            floor: Long,
        ): ExpectedStart? {
            val passed = failed.toMutableSet()
            while (true) {
                val adoptee = expectedAdoptee(seedTs, passed, floor) ?: return null
                if (serves(adoptee)) return ExpectedStart.Stored(adoptee, adopted = true)
                passed += adoptee
            }
        }

        /**
         * I10's expected adoptee for a seed at [seedTs]: the newest undamaged stored generation above it, ties by name,
         * none of [failed].
         */
        private fun expectedAdoptee(
            seedTs: Long,
            failed: Set<String> = emptySet(),
            atLeast: Long? = null,
        ): String? {
            val floor =
                atLeast ?: maxOf(
                    seedTs + 1,
                    served()?.let { (truth.stored(it) as? StoreRead.Found)?.value?.timestampMillis } ?: Long.MIN_VALUE,
                )
            return truth
                .generationNames()
                .sorted()
                .filter { it !in forgedNames && it !in failed && intact(it) }
                .mapNotNull { n ->
                    (truth.load(n) as? GenerationLoad.Loaded)?.value?.generation?.takeIf {
                        it.timestampMillis >=
                            floor
                    }
                }.sortedWith(compareByDescending<StoredGeneration> { it.timestampMillis }.thenBy { it.name })
                .firstOrNull()
                ?.name
        }

        /**
         * The model's own check that the generation file [name] and every blob it names are the bytes their names promise,
         * hashed here rather than by the code under test, so a load that skips a re-hash cannot vouch for itself (I9, I10).
         */
        private fun intact(name: String): Boolean {
            val bytes = storage.inner.read("$root/generations/$name") ?: return false
            if (GenerationFileJson.name(bytes) != name) return false
            val file = GenerationFileJson.readUnhashed(bytes, Long.MAX_VALUE) ?: return false
            val g = truth.place(name, file) ?: return false
            return g.placed.all { p ->
                storage.inner
                    .read("$root/blobs/${g.sha256(p).hex()}")
                    ?.toByteString()
                    ?.sha256() == g.sha256(p)
            }
        }

        /** One drawn step: a steered one when the store is in a state worth pressing on, else [act]. */
        fun step() {
            if (!steered()) act(choices.int(11))
        }

        /**
         * The adversarial scheduler's step, or false when it takes none: an orphan generation file (written, never
         * flipped) is damaged, then its publication served again, half the time (#205); beside a malformed pointer, a
         * third of the time: a restart, damage to the generation the pointer named, or the last publication again.
         */
        private fun steered(): Boolean {
            // Adopt pressure: a lost current, then a restart whose seed load scans the store (I10), a quarter of the time.
            if (truth.pointer() is StoreRead.Found && truth.generationNames().size > 1 && choices.int(4) == 0) {
                // Half the time the newest file is damaged first, in a way that keeps it parseable (B2's case).
                if (choices.int(2) == 0) recordsDamage(newest())
                storage.inner.delete("$root/current")
                storage.damaged += "$root/current"
                trail += "damage deleted current"
                restart(seed = true)
                return true
            }
            val orphan = orphans().lastOrNull()
            if (orphan != null && choices.int(2) == 0) {
                val (p, name) = orphan
                if (storage.hit(name)) {
                    publish(p)
                    trail += "serve-orphan ${p.ts} ${outcome(sync())}"
                } else {
                    damage(listOf("$root/generations/$name") + storage.trueBlobs(name).map { "$root/blobs/$it" })
                }
                return true
            }
            if (truth.pointer() is StoreRead.Malformed && choices.int(3) == 0) {
                val named = storage.pointer?.live
                when (choices.int(3)) {
                    0 -> {
                        restart()
                    }

                    1 -> {
                        if (named != null) damage(listOf("$root/generations/$named"))
                    }

                    else -> {
                        publish(published.last())
                        trail += "serve-last ${server.ts} ${outcome(sync())}"
                    }
                }
                return true
            }
            return false
        }

        /** The drawn step [choice]: a sync of some publication, a fault, a stop, damage or a restart. */
        private fun act(choice: Int) {
            when (choice) {
                0, 1 -> {
                    publish(newPublication())
                    trail += "publish ${server.ts} ${outcome(sync())}"
                }

                2 -> {
                    trail += "same ${outcome(sync())}"
                }

                3 -> {
                    val p = published[choices.int(published.size)]
                    publish(p)
                    trail += "serve ${p.ts} ${outcome(sync())}"
                }

                4 -> {
                    publish(published.last(), resign = true)
                    trail += "resign ${server.ts} ${outcome(sync())}"
                }

                5 -> {
                    val fresh = fresh()
                    val at = choices.int(if (choices.int(3) == 0) 3 else OPERATIONS)
                    trail += "${fresh}throw@$at ${outcome(sync(throwAt = at))}"
                }

                6 -> {
                    val fresh = fresh()
                    trail += "${fresh}prepare-throws ${outcome(sync(prepareThrows = true))}"
                }

                7 -> {
                    val fresh = fresh()
                    val at = choices.int(OPERATIONS)
                    trail += "${fresh}stop@$at ${outcome(sync(stopAt = at))}"
                }

                8 -> {
                    val fresh = fresh()
                    val at = choices.int(OPERATIONS)
                    trail += "${fresh}stop-losing-deletes@$at ${outcome(sync(stopAt = at, loseDeletes = true))}"
                }

                9 -> {
                    damage()
                }

                else -> {
                    restart()
                }
            }
        }

        /** Half the time, serves a new publication for the fault action that follows; its trail prefix. */
        private fun fresh(): String {
            if (choices.int(2) != 0) return ""
            publish(newPublication())
            return "new ${server.ts} "
        }

        private fun outcome(o: SyncOutcome?): String = (o?.name ?: "stopped") + last

        /** The last sync's stage and warnings, for the trail. */
        private var last = ""

        /** The failure of the last sync, or null. */
        private var lastFailure: SyncFailure? = null

        /** Damage to one key of the store, recorded so I1, I3 and I8 exempt what it hit. */
        @Suppress("CyclomaticComplexMethod") // One arm per damage generator of design note section 14.
        private fun damage(only: List<String>? = null) {
            val keys = (only ?: storage.inner.names().toList()).filter { storage.inner.read(it) != null }
            if (keys.isEmpty()) return
            val pointer = storage.pointer
            if (only == null && choices.int(5) == 0) return if (choices.int(2) == 0) forge() else undecodablePrevious()
            val key =
                when (if (only != null) 9 else choices.int(9)) {
                    0 -> "$root/current"
                    1 -> "$root/updater.json"
                    2 -> keys.filter { "/generations/" in it }.ifEmpty { keys }.let { it[choices.int(it.size)] }
                    3 -> sharedBlob(pointer) ?: keys[choices.int(keys.size)]
                    else -> keys[choices.int(keys.size)]
                }
            val bytes = storage.inner.read(key) ?: return
            val (kind, written) = damaged(key, bytes)
            if (written == null) storage.inner.delete(key) else storage.inner.write(key, written)
            storage.damaged += key
            if (key == "$root/updater.json") {
                watermark = null
                highWater = null
            }
            trail += "damage $kind ${key.removePrefix("$root/")}"
        }

        /**
         * An outside write to the OS-trusted store: a generation file newer than anything published, of the newest
         * publication's records under a signature that does not verify, stored under its own name. Only the adopt scan's
         * signature check refuses it (I10); everything else takes it for a generation.
         */
        private fun forge() {
            val file =
                storage.ledger.values
                    .mapNotNull { GenerationFileJson.readUnhashed(it, Long.MAX_VALUE) }
                    .maxByOrNull { it.lastModified } ?: return
            val forged =
                dev.revokt.engine.store.GenerationFile(
                    file.dataset,
                    file.channel,
                    file.freshness,
                    file.seedFormat,
                    ByteArray(file.signature.size) { 1 }.toByteString(),
                    file.signerLeafSha256,
                    file.records,
                    now + day,
                )
            val bytes = GenerationFileJson.write(forged)
            val key = "$root/generations/${GenerationFileJson.name(bytes)}"
            storage.inner.write(key, bytes)
            storage.damaged += key
            forgedNames += GenerationFileJson.name(bytes)
            trail += "damage forged ${key.removePrefix("$root/")}"
        }

        /**
         * An outside write that leaves `current` readable: its `previous` replaced by a generation file that passes
         * Load's steps 1 to 3 and fails step 4, its one delta a blob whose bytes re-hash but do not decode (the residual of
         * a `previous` qualified through step 3: after a decoder change, it can no longer load). The recovery chain must
         * fall past it. Recorded as damage, and as the last pointer written, since the code did not write it.
         */
        private fun undecodablePrevious() {
            val pointer = (truth.pointer() as? StoreRead.Found)?.value ?: return
            val live = (truth.stored(pointer.live) as? StoreRead.Found)?.value ?: return
            val garbage = byteArrayOf(4, 0, 0, 0, 0, choices.int(100).toByte())
            val sha = garbage.toByteString().sha256().hex()
            val records =
                live.file.records.map { r ->
                    val text =
                        dev.revokt.engine.json.CanonicalJson
                            .write(r)
                            .decodeToString()
                    if ("\"incremental\":true" !in text) return@map r
                    val hash = Regex("\"hash\":\"[0-9a-f]{64}\"").replace(text, "\"hash\":\"$sha\"")
                    val sized = Regex("\"size\":[0-9]+").replace(hash, "\"size\":${garbage.size}")
                    dev.revokt.engine.json.Json
                        .parse(sized.encodeToByteArray()) as dev.revokt.engine.json.JsonObject
                }
            if (records == live.file.records) return
            val f = live.file
            val file =
                dev.revokt.engine.store.GenerationFile(
                    f.dataset,
                    f.channel,
                    f.freshness,
                    f.seedFormat,
                    f.signature,
                    f.signerLeafSha256,
                    records,
                    f.lastModified - 1,
                )
            val bytes = GenerationFileJson.write(file)
            val name = GenerationFileJson.name(bytes)
            storage.inner.write("$root/blobs/$sha", garbage)
            storage.inner.write("$root/generations/$name", bytes)
            val replaced = Pointer(pointer.live, name)
            storage.inner.write("$root/current", PointerJson.write(replaced))
            storage.pointer = replaced
            storage.damaged += listOf("$root/generations/$name", "$root/blobs/$sha", "$root/current")
            forgedNames += name
            trail += "damage undecodable-previous generations/$name"
        }

        /** The forged generation files ([forge]): never adoptable. */
        val forgedNames = HashSet<String>()

        /** A blob both the pointer's live and previous name, or null. */
        private fun sharedBlob(pointer: Pointer?): String? {
            val live = pointer?.live ?: return null
            val previous = pointer.previous ?: return null
            return (
                storage.trueBlobs(
                    live,
                ) intersect storage.trueBlobs(previous)
            ).firstOrNull()?.let { "$root/blobs/$it" }
        }

        /** [bytes] of [key] damaged, and its kind: null bytes delete it (a lost `current`). */
        @Suppress("CyclomaticComplexMethod") // One arm per damage generator of design note section 14.
        private fun damaged(
            key: String,
            bytes: ByteArray,
        ): Pair<String, ByteArray?> {
            val text = bytes.decodeToString()
            val generation = key.startsWith("$root/generations/")
            return when (choices.int(6)) {
                0 -> {
                    "flip" to
                        bytes.copyOf().also { if (it.isNotEmpty()) it[choices.int(it.size)] = (it[0] + 1).toByte() }
                }

                1 -> {
                    "truncate" to bytes.copyOf(bytes.size / 2)
                }

                2 -> {
                    when {
                        // A flip inside the records that keeps the file parseable: only the re-hash catches it.
                        // A delta's channel changed: the file still parses and places, without that delta (B2's case).
                        generation && "\"incremental\":true" in text -> {
                            "records" to
                                text
                                    .replaceFirst(
                                        "\"channel\":\"compat\"",
                                        "\"channel\":\"default\"",
                                    ).encodeToByteArray()
                        }

                        generation -> {
                            "version" to
                                text.replace("\"generationVersion\":1", "\"generationVersion\":2").encodeToByteArray()
                        }

                        else -> {
                            "malformed" to "{".encodeToByteArray()
                        }
                    }
                }

                3 -> {
                    when (key) {
                        // A flipped hex digit in a name: the pointer still parses, and names a key nothing hashes to.
                        "$root/current" -> "hex" to flipHex(text).encodeToByteArray()

                        // Another filter's valid bytes under this blob's key: they decode, so only the re-hash refuses them.
                        else -> if ("/blobs/" in key) "swap" to swapFor(key, bytes) else "empty" to byteArrayOf()
                    }
                }

                4 -> {
                    if (key ==
                        "$root/current"
                    ) {
                        "deleted" to null
                    } else {
                        "flip" to
                            bytes.copyOf().also { if (it.isNotEmpty()) it[0] = (it[0] + 1).toByte() }
                    }
                }

                else -> {
                    if (generation) {
                        "version" to
                            text.replace("\"generationVersion\":1", "\"generationVersion\":2").encodeToByteArray()
                    } else {
                        "truncate" to bytes.copyOf(maxOf(0, bytes.size - 1))
                    }
                }
            }
        }

        /** The newest generation file that reads, or null. */
        private fun newest(): String? = readableGenerations().maxByOrNull { it.value }?.key

        /** A delta's channel changed inside the generation file [name]: still parseable and placeable, only the re-hash refuses it. */
        private fun recordsDamage(name: String?) {
            val key = "$root/generations/${name ?: return}"
            val text = storage.inner.read(key)?.decodeToString() ?: return
            if ("\"incremental\":true" !in text) return
            storage.inner.write(
                key,
                text.replaceFirst("\"channel\":\"compat\"", "\"channel\":\"default\"").encodeToByteArray(),
            )
            storage.damaged += key
            trail += "damage records ${key.removePrefix("$root/")}"
        }

        /** The bytes of some other stored blob, or [bytes] flipped when there is none. */
        private fun swapFor(
            key: String,
            bytes: ByteArray,
        ): ByteArray {
            val other = storage.inner.names().firstOrNull { "/blobs/" in it && it != key }
            return other?.let { storage.inner.read(it) }
                ?: bytes.copyOf().also { if (it.isNotEmpty()) it[0] = (it[0] + 1).toByte() }
        }

        /** [text] with one hex digit of its first name flipped, a pointer that still parses. */
        private fun flipHex(text: String): String {
            val at = text.indexOf("\":\"") + 3 + choices.int(64)
            if (at >= text.length) return text
            val c = text[at]
            val flipped = if (c == '0') '1' else '0'
            return text.substring(0, at) + flipped + text.substring(at + 1)
        }

        /** I1, I3's watermark and I8 after a step, and the per-operation violations of I2, I3 and I6. */
        fun check() {
            storage.violations.firstOrNull()?.let { fail(it) }
            val pointer = truth.pointer()
            if (pointer is StoreRead.Found) {
                for (n in listOfNotNull(pointer.value.live, pointer.value.previous)) {
                    if (!storage.hit(n) && !damagedPointer() && truth.load(n) !is GenerationLoad.Loaded) {
                        fail("I1: the pointed $n does not load: ${truth.load(n)}")
                    }
                }
            }
            served()?.let { n ->
                if (!storage.hit(n) && truth.load(n) !is GenerationLoad.Loaded) fail("I1: the served $n does not load")
            }
            checkWatermark()
            checkDeleteOrder()
        }

        /** Whether damage hit `current` (a flipped hex digit names a key nothing hashes to: no I1 claim then). */
        private fun damagedPointer(): Boolean = "$root/current" in storage.damaged

        /** I8: a generation file on disk that reads names only blobs on disk, unless damage or a lost delete hit them. */
        private fun checkDeleteOrder() {
            for (n in truth.generationNames()) {
                val g = (truth.stored(n) as? StoreRead.Found)?.value ?: continue
                for (b in g.blobNames) {
                    val key = "$root/blobs/$b"
                    if (key !in storage.inner.names() && key !in storage.damaged &&
                        "$root/generations/$n" !in storage.damaged
                    ) {
                        fail("I8: $n names the blob $b, which is not on disk")
                    }
                }
            }
        }

        /** I3's watermark: never backwards, never below the model's high-water mark, unless damage hit the file. */
        private fun checkWatermark() {
            val read = truth.updater(now)
            val stored = (read as? StoreRead.Found)?.value?.record?.watermarkMillis
            val before = watermark
            if (before != null &&
                (stored == null || stored < before)
            ) {
                fail("I3: the watermark went from $before to $stored")
            }
            val high = highWater
            if (high != null &&
                (stored == null || stored < high)
            ) {
                fail("I3: the watermark $stored is below the high-water mark $high")
            }
            watermark = stored
        }

        /** I4: with the faults stopped, the store recovers, and a sync over every stored blob fetches none. */
        fun recover() {
            trail += "recover"
            val last = published.last()
            publish(last)
            var settled = false
            repeat(RECOVERY) {
                if (settled) return@repeat
                val blobsStored =
                    last.records.all {
                        truth.blob(it.body.toByteString().sha256()) ==
                            dev.revokt.engine.store.BlobState.MATCH
                    }
                val o = sync()
                trail += "  same ${last.ts} ${outcome(o)}"
                check()
                if (blobsStored &&
                    lastFetches > 0
                ) {
                    fail("I4: a sync over a store holding every blob fetched $lastFetches")
                }
                settled =
                    o == SyncOutcome.INSTALLED || o == SyncOutcome.UNCHANGED ||
                    (o == SyncOutcome.SKIPPED && lastFailure == SyncFailure.ROLLBACK_REFUSED)
            }
            if (!settled) fail("I4: the last publication ${last.ts} never settled")
            publish(newPublication())
            var installed = false
            repeat(RECOVERY) {
                if (installed) return@repeat
                val o = sync()
                trail += "  new ${server.ts} ${outcome(o)}"
                check()
                installed = o == SyncOutcome.INSTALLED
            }
            if (!installed) fail("I4: a new publication ${server.ts} never installed")
        }

        /** The generation files nobody names, each with its publication: what a stop between file and flip leaves. */
        fun orphans(): List<Pair<Publication, String>> {
            val named = (truth.pointer() as? StoreRead.Found)?.value.let { listOfNotNull(it?.live, it?.previous) }
            return truth.generationNames().filter { it !in named && it != served() }.mapNotNull { n ->
                val id = (truth.stored(n) as? StoreRead.Found)?.value?.generationId
                published.firstOrNull { it.generationId == id }?.let { it to n }
            }
        }

        fun fail(message: String): Nothing =
            throw ModelViolation("$message\n  steps: ${trail.joinToString("\n    ", "\n    ")}")
    }

    /** One run of [steps] drawn steps from [choices], then the recovery check. */
    fun run(
        choices: Choices,
        steps: Int,
    ) {
        val world = World(choices)
        world.trail += "publish ${world.server.ts} ${world.sync()}"
        world.check()
        repeat(steps) {
            world.step()
            world.check()
        }
        world.recover()
    }

    companion object {
        /** The deltas a publication draws from. */
        const val DELTAS = 4

        /** About the storage operations of an installing sync (12 to 50 measured), the range a fault or stop is drawn from. */
        const val OPERATIONS = 56

        /** The clean syncs within which the store must recover (I4). */
        const val RECOVERY = 3
    }
}
