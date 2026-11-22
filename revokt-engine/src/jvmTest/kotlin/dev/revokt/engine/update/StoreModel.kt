// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.RevoktStorage
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.engine.fetch.client
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.MetaJson
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.PointerJson
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.log
import dev.revokt.testing.SplitMix64
import okio.ByteString.Companion.toByteString

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

/** An invariant of [StoreModel] that a run broke; the message names the run's steps. */
internal class ModelViolation(
    message: String,
    cause: Throwable? = null,
) : AssertionError(message, cause)

/**
 * The model-based fault-injection test of #214 (the 2026-11-16 design audit, C-F1), over [StoreLayout], [install] and
 * [CrliteSync] on an in-memory storage with an operation hook. One [run] draws a sequence of actions from [Choices]:
 * - a sync of a scripted Remote Settings: a new `<ts>` (some deltas, sometimes a re-parented full), the same changeset
 *   again, a rollback to an earlier publication (inside or beyond the window), or the same records re-signed;
 * - a sync whose n-th storage operation (a read, write, delete or listing) throws, or whose engine `prepare` throws;
 * - a process stop at the n-th operation (every later write and delete is lost), then a fresh loader (an empty snapshot
 *   and engine over the same store);
 * - a fault, a `prepare` that throws or a stop lands, half the time, on the sync of a new publication, so that it hits an
 *   install, a flip or a prune rather than a sync with nothing to do (the #245 review, finding 1);
 * - damage: a flipped byte or a truncated file, a malformed `current`, `meta.json` or `updater.json`, or a `meta.json`
 *   with a `metaVersion` that is too new.
 *
 * After every operation and every step it checks the audit's invariants (each failure names the steps so far):
 * - **I1** whatever the pointer names as `live` or `previous` reads back as a generation, unless damage hit it; so does
 *   the generation the loader's snapshot holds live. Damage is forgotten once the code rewrites or deletes the key (a
 *   blob once its bytes re-hash), so a repaired generation is checked again;
 * - **I2** no key of a generation that is live or pointed to is deleted or overwritten while it is, damaged or not
 *   (#236: a damaged generation the store names is held, never rewritten or deleted), and no blob its `meta.json` names
 *   is deleted or rewritten with other bytes. "Pointed to" is the last pointer the code wrote ([ModelStorage.pointer]),
 *   not what a damaged `current` reads as: a malformed pointer must not make its generations fair game (the shape of
 *   #207's fail-open bootstrap). Damage that leaves `current` readable is the one exception: no reader can tell it from
 *   a write, so the pointer it reads as becomes the held one (#246; a checksum would close it, #229). And the generation
 *   the engine held when a sync began survives that sync, if it read back undamaged: on disk, and as the pointer's live
 *   or previous when the sync's write of `current` landed (#242's fallback, #249);
 * - **I3** `updater.json` is written only by a sync whose read of it returned (#209), and its watermark never goes
 *   backwards and never falls below the model's own high-water mark (the newest `<ts>` installed), unless damage hit
 *   the file or an install made with no generation live set it to that install's `<ts>` (§7.1);
 * - **I5** while the snapshot holds a generation live, no publication older than the floor installs, other than the
 *   live one's own (#190's retried flip). The floor is the model's high-water mark, lost only to damage to
 *   `updater.json`, raised to the live generation's timestamp (§7.1: a malformed `updater.json` keeps the live floor).
 *   With no generation live the stored watermark is not read, so anything may install (§7.1, as Firefox imports when
 *   its local data does not verify);
 * - **I4** every sync returns, and once the faults stop the store recovers: within [RECOVERY] clean syncs the last
 *   publication is installed, unchanged or refused as a rollback (an orphan never loops, #205's bug), unless its
 *   directory is held and damaged, and a new publication then installs.
 */
internal class StoreModel : CrliteSyncFixture() {
    /** The storage of one run: every operation counted, faults injected on cue, and the I2/I3 checks per operation. */
    inner class ModelStorage(
        private val root: String,
    ) : RevoktStorage {
        val inner: RevoktStorage = RevoktStorage.inMemory()
        private var ops = 0

        /** The operation of this sync that throws, or -1. */
        var throwAt = -1

        /** The operation of this sync from which every write and delete is lost (a process stop), or -1. */
        var stopAt = -1

        /** Whether this sync's read of `updater.json` returned. */
        var updaterRead = false

        /** The last pointer the code wrote, whatever damage did to `current` since. */
        var pointer: Pointer? = null

        /** The keys damage hit; a generation with one of them, or with a damaged blob, is exempt from I1 and I2. */
        val damaged = HashSet<String>()

        /** The directory the snapshot holds live, protected like a pointed one while the loader lives. */
        var snapshotLive: () -> String? = { null }

        val violations = ArrayList<String>()

        /** The operation and key the armed throw or stop hit, for the trail. */
        var fault: String? = null

        /** Whether this sync's write of `current` landed (not lost to a stop, not thrown). */
        var pointerWritten = false

        /** Starts a sync's operation count, with its faults. */
        fun arm(
            throwAt: Int,
            stopAt: Int,
        ) {
            ops = 0
            this.throwAt = throwAt
            this.stopAt = stopAt
            updaterRead = false
            fault = null
            pointerWritten = false
        }

        val stopped: Boolean get() = stopAt in 0..<ops

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
            val repair = isBlob(name) && bytes.toByteString().sha256().hex() == name.substringAfterLast('/')
            if (!repair) {
                protectedBy(
                    name,
                )?.let { violations += "I2: $name overwritten while $it is live or pointed to" }
            }
            inner.write(name, bytes)
            if (!isBlob(name) || repair) damaged -= name
            if (name == "$root/current") {
                pointerWritten = true
                PointerJson.read(bytes)?.let { pointer = it }
            }
        }

        override fun delete(name: String) {
            op(name)
            if (stopped) return
            protectedBy(name)?.let { violations += "I2: $name deleted while $it is live or pointed to" }
            inner.delete(name)
            damaged -= name
        }

        override fun names(): Set<String> {
            op("names")
            return inner.names()
        }

        override fun lock(): AutoCloseable = AutoCloseable {}

        private fun isBlob(name: String): Boolean = name.startsWith("$root/blobs/")

        /** The live or pointed directory that holds [name], or whose `meta.json` names the blob [name], or null. */
        private fun protectedBy(name: String): String? {
            val held = listOfNotNull(pointer?.live, pointer?.previous, snapshotLive())
            if (isBlob(name)) {
                val sha = name.substringAfterLast('/')
                return held.firstOrNull { d ->
                    inner
                        .read("$root/$d/meta.json")
                        ?.let(MetaJson::read)
                        ?.blobs
                        ?.values
                        ?.any { it.hex() == sha } ==
                        true
                }
            }
            val directory = name.removePrefix("$root/").substringBefore('/', "")
            if (!GenerationNames.isDirectory(directory)) return null
            // Damage exempts a generation from reading back (I1), never from being kept: a damaged generation the store
            // still names is held, never rewritten or deleted (#236, #242).
            return directory.takeIf { it in held }
        }

        /** Whether damage hit [directory] or a blob its `meta.json` names. */
        fun hit(directory: String): Boolean {
            if (damaged.any { it.startsWith("$root/$directory/") }) return true
            val bytes = inner.read("$root/$directory/meta.json") ?: return false
            val text = bytes.decodeToString()
            return damaged.any { it.startsWith("$root/blobs/") && it.substringAfterLast('/') in text }
        }
    }

    /** One publication of the scripted collection: its `<ts>` and records, and the bodies they name. */
    private class Publication(
        val ts: Long,
        val records: List<Rec>,
    )

    /** One run's world: its storage, store, loader, server and clock. */
    private inner class World(
        private val choices: Choices,
    ) {
        val storage = ModelStorage("crlite/compat")
        val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
        var snapshot = freshSnapshot()
        var engine = UpdateFixtures.TestEngine()
        val server = Server()
        val trail = ArrayList<String>()
        var now = ts + hour
        val published = ArrayList<Publication>()
        val pool = (1..DELTAS).map { delta(it) }
        var full = filter("full-1", false, ts - day, 1)
        var watermark: Long? = null

        /** The newest `<ts>` a sync installed, the model's own; null once damage hit `updater.json`. */
        var highWater: Long? = null

        init {
            storage.snapshotLive = ::liveDirectory
            publish(newPublication())
        }

        fun liveDirectory(): String? {
            val live = snapshot.snapshot.datasets[Dataset.CRLITE] ?: return null
            val id = live.generationId ?: return null
            return live.sourceTimestampMillis?.let { GenerationNames.directory(it, id) }
        }

        private fun freshSnapshot(): SnapshotRef =
            SnapshotRef(
                GenerationSnapshot(
                    0,
                    mapOf(
                        Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false),
                    ),
                    null,
                ),
            )

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
            if (choices.int(6) ==
                0
            ) {
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
            server.signature = if (resign) Server(ts = p.ts, records = server.records).sign() else null
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

        fun sync(
            throwAt: Int = -1,
            stopAt: Int = -1,
            prepareThrows: Boolean = false,
        ): SyncOutcome? {
            val target = servedDirectory()
            // I2: the generation the engine held when the sync began survives it, if it read back undamaged: as the
            // pointer's live or its previous (#242's fallback beside a malformed pointer included).
            val liveAtStart = liveDirectory()?.takeIf { !storage.hit(it) && store.readGeneration(it) != null }
            val floor = rollbackFloor()
            storage.arm(throwAt, stopAt)
            engine.onPrepare = { require(!prepareThrows) { "injected prepare fault" } }
            val run =
                try {
                    CrliteSync(
                        client(server.fetcher, source),
                        store,
                        engine,
                        snapshot,
                        verifier,
                        UpdateFixtures.Recording(),
                    ).syncOnce(now)
                } catch (t: Throwable) {
                    fail("I4: syncOnce threw $t")
                }
            val stopped = storage.stopped
            val fault = storage.fault
            val pointerWritten = storage.pointerWritten
            storage.arm(-1, -1)
            afterSync(
                run.result,
                target,
                liveAtStart,
                clean = throwAt < 0 && stopAt < 0 && !prepareThrows,
                stopped,
                pointerWritten,
            )
            rollback(run.result, floor, stopped)
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

        /**
         * I5's floor for a sync starting now, and the live timestamp it was raised to: the model's high-water mark
         * ([highWater], null once damage hit `updater.json`) raised to the snapshot's live timestamp; null with no
         * generation live, when the stored watermark is not read (§7.1).
         */
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

        /** The directory of the publication the server serves now. */
        private fun servedDirectory(): String =
            directoryOf(published.first { it.ts == server.ts && it.records.map { r -> r.json() } == server.records })

        /**
         * I4's clean-sync rule and I2's survival rule after a sync of [target] that ended as [result]: a [clean] sync of a
         * directory nothing holds is never `STORE_FAILED`, and [liveAtStart] survives a sync that was not [stopped].
         */
        private fun afterSync(
            result: dev.revokt.SyncResult,
            target: String,
            liveAtStart: String?,
            clean: Boolean,
            stopped: Boolean,
            pointerWritten: Boolean,
        ) {
            if (clean && result.failure == SyncFailure.STORE_FAILED && !held(target)) {
                fail("I4: a clean sync of the unheld $target is STORE_FAILED: ${result.cause}")
            }
            if (stopped || liveAtStart == null) return
            // A sync whose write of `current` landed keeps it as the pointer's live or previous, whatever its outcome; one
            // that wrote none (it failed, perhaps after activating a generation whose flip then threw) leaves it on disk.
            val flipped = result.outcome == SyncOutcome.INSTALLED || pointerWritten
            val kept = !flipped || liveAtStart == storage.pointer?.live || liveAtStart == storage.pointer?.previous
            if (store.readGeneration(liveAtStart) == null || !kept) {
                fail(
                    "I2: the sync lost $liveAtStart, the generation the engine held when it began " +
                        "(reads back: ${store.readGeneration(liveAtStart) != null}, pointer ${storage.pointer})",
                )
            }
        }

        fun restart() {
            snapshot = freshSnapshot()
            engine = UpdateFixtures.TestEngine()
            trail += "restart"
        }

        /** One drawn step: a steered one when the store is in a state worth pressing on, else [act]. */
        fun step() {
            if (!steered()) act(choices.int(10))
        }

        /**
         * The adversarial scheduler's step, or false when it takes none: the states where this round's bugs lived are
         * pressed on rather than left to chance.
         */
        private fun steered(): Boolean {
            // An adversarial scheduler: an orphan is damaged, then its publication served again, half the time (#205).
            val orphan = orphans().lastOrNull()
            if (orphan != null && choices.int(2) == 0) {
                val directory = directoryOf(orphan)
                if (storage.hit(directory)) {
                    publish(orphan)
                    trail += "serve-orphan ${orphan.ts} ${outcome(sync())}"
                } else {
                    damage(storage.names().filter { "/$directory/" in it && !it.endsWith("/meta.json") })
                }
                return true
            }
            // And beside a malformed pointer, a third of the time: a restart, damage to the generation the pointer named,
            // or the last publication served again (#236, #242).
            if (store.pointer() is StoreRead.Malformed && choices.int(3) == 0) {
                val named = storage.pointer?.live
                when (choices.int(3)) {
                    0 -> {
                        restart()
                    }

                    1 -> {
                        if (named != null) damage(listOf("crlite/compat/$named/meta.json"))
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

        /** Damage to one key of the store, recorded so I1, I2 and I3 exempt what it hit. */
        private fun damage(only: List<String>? = null) {
            val keys = (only ?: storage.names()).sorted()
            if (keys.isEmpty()) return
            val root = "crlite/compat"
            val pointed = listOfNotNull(storage.pointer?.live, storage.pointer?.previous, liveDirectory())
            // A file of an orphan (a generation nothing holds, as a stop between meta.json and the flip leaves one),
            // its deltas first: the state #205's loop needs.
            val orphans =
                keys.filter { k ->
                    val d = k.removePrefix("$root/").substringBefore('/', "")
                    GenerationNames.isDirectory(d) && d !in pointed && !k.endsWith("/meta.json")
                }
            val key =
                when (if (only != null) 5 else choices.int(6)) {
                    0 -> "$root/current"
                    1 -> "$root/updater.json"
                    2, 3 -> orphans.ifEmpty { keys }.let { it[choices.int(it.size)] }
                    else -> keys[choices.int(keys.size)]
                }
            val bytes = storage.inner.read(key) ?: return
            val written = damaged(key, bytes)
            storage.inner.write(key, written)
            storage.damaged += key
            if (key == "$root/current") adoptPointer(written)
            if (key == "$root/updater.json") {
                watermark = null
                highWater = null
            }
            trail += "damage $key"
        }

        /**
         * Damage that leaves `current` a readable pointer (a member name flipped into one the reader ignores, a directory
         * name changed) is a pointer write no reader can tell from the code's own, so what it reads as is held (#246).
         */
        private fun adoptPointer(bytes: ByteArray) {
            val read = PointerJson.read(bytes) ?: return
            // Today only a damaged `previous` member name parses; a damage generator that changed `live` would excuse the
            // loss of a live generation, so that fails loudly instead.
            if (read.live != storage.pointer?.live) fail("model: damage to current changed live to ${read.live}")
            storage.pointer = read
        }

        /** [bytes] of [key] damaged: a flipped byte, a truncation, a malformed document, or a too-new `metaVersion`. */
        private fun damaged(
            key: String,
            bytes: ByteArray,
        ): ByteArray =
            when (choices.int(4)) {
                0 -> bytes.copyOf().also { if (it.isNotEmpty()) it[choices.int(it.size)] = (it[0] + 1).toByte() }
                1 -> bytes.copyOf(bytes.size / 2)
                2 -> "{".encodeToByteArray()
                else -> if (key.endsWith("/meta.json")) "{\"metaVersion\":2}".encodeToByteArray() else byteArrayOf()
            }

        /** I1 and I3's watermark after a step, and the per-operation violations of I2 and I3. */
        fun check() {
            storage.violations.firstOrNull()?.let { fail(it) }
            val pointer = store.pointer()
            if (pointer is StoreRead.Found) {
                for (d in listOfNotNull(pointer.value.live, pointer.value.previous)) {
                    if (!storage.hit(d) &&
                        store.readGeneration(d) == null
                    ) {
                        fail("I1: the pointed $d does not read back")
                    }
                }
            }
            liveDirectory()?.let { d ->
                if (!storage.hit(d) &&
                    store.readGeneration(d) == null
                ) {
                    fail("I1: the snapshot's live $d does not read back")
                }
            }
            checkWatermark()
        }

        /** I3's watermark: never backwards, never below the model's high-water mark, unless damage hit the file. */
        private fun checkWatermark() {
            val read = store.updater(now)
            val stored = (read as? StoreRead.Found)?.value?.record?.watermarkMillis
            val before = watermark
            if (before != null &&
                (stored == null || stored < before)
            ) {
                fail("I3: the watermark went from $before to $stored")
            }
            val high = highWater
            if (high != null && (stored == null || stored < high)) {
                fail("I3: the watermark $stored is below the high-water mark $high")
            }
            watermark = stored
        }

        /** I4: with the faults stopped, the store recovers. */
        fun recover() {
            trail += "recover"
            val last = published.last()

            publish(last)
            var settled = false
            repeat(RECOVERY) {
                if (settled) return@repeat
                val o = sync()
                trail += "  same ${last.ts} ${outcome(o)}"
                check()
                settled =
                    o == SyncOutcome.INSTALLED || o == SyncOutcome.UNCHANGED ||
                    (o == SyncOutcome.SKIPPED && lastFailure == SyncFailure.ROLLBACK_REFUSED)
            }
            val wedged = heldAndDamaged(last)

            if (!settled && !wedged) fail("I4: the last publication ${last.ts} never settled")
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

        /** [p]'s generation directory: `<ts>/<last placed record>`. */
        fun directoryOf(p: Publication): String = GenerationNames.directory(p.ts, "${p.ts}/${p.records.last().id}")

        /** Whether the loader may rightly hold [directory]: named by the pointer, live in the snapshot, or unknown. */
        fun held(directory: String): Boolean {
            val pointer = store.pointer()
            val named = (pointer as? StoreRead.Found)?.value.let { listOfNotNull(it?.live, it?.previous) }
            return directory in named || directory == liveDirectory() || pointer is StoreRead.Malformed
        }

        /** The complete generation directories nothing holds: what a stop between `meta.json` and the flip leaves. */
        fun orphans(): List<Publication> =
            published.filter {
                store.meta(directoryOf(it)) != null &&
                    !held(directoryOf(it))
            }

        /** Whether [p]'s directory is one the loader may rightly refuse to touch: held (or unknown) and damaged. */
        private fun heldAndDamaged(p: Publication): Boolean = held(directoryOf(p)) && storage.hit(directoryOf(p))

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

        /** About the storage operations of an installing sync (22 to 71 measured), the range a fault or stop is drawn from. */
        const val OPERATIONS = 80

        /** The clean syncs within which the store must recover (I4). */
        const val RECOVERY = 3
    }
}
