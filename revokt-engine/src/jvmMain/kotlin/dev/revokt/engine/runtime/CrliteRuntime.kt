// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.Evaluator
import dev.revokt.HttpFetcher
import dev.revokt.LogLevel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.PathBuilderFallback
import dev.revokt.PlatformTrust
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevocationEngine
import dev.revokt.RevoktEvaluator
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLifecycle
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktPolicy
import dev.revokt.RevoktStorage
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.SyncOutcome
import dev.revokt.WarningCode
import dev.revokt.engine.fetch.FetchLimits
import dev.revokt.engine.fetch.RemoteSettingsClient
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.policy.seedPastRejectThreshold
import dev.revokt.engine.policy.startDiagnostics
import dev.revokt.engine.seed.SeedLoad
import dev.revokt.engine.seed.SeedLoader
import dev.revokt.engine.seed.SeedPolicy
import dev.revokt.engine.store.OpenedStore
import dev.revokt.engine.store.StorageBackend
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreOpen
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.CrliteSync
import dev.revokt.engine.update.PollSchedule
import dev.revokt.engine.update.SnapshotRef
import dev.revokt.engine.update.StoredServe
import dev.revokt.engine.update.SyncRun
import dev.revokt.engine.update.serveStored
import dev.revokt.engine.update.servedFile
import dev.revokt.engine.update.stored
import dev.revokt.engine.walker.AnchorSnapshots
import dev.revokt.engine.walker.DecideInputs
import dev.revokt.engine.walker.IndexedSnapshot
import dev.revokt.engine.walker.absorb
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.lruMap
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import kotlinx.coroutines.CoroutineDispatcher
import okio.ByteString
import javax.net.ssl.X509TrustManager
import kotlin.random.Random

/**
 * The data side of one `Revokt` (spec §4, §5.1 "Lifecycle", §11's 0.2 row): the store over [storage], the one published
 * generation reference, the seed's start steps, the S diagnostics, the anchor index build and the [Evaluator]. The JVM
 * binding (revokt-jsse) keeps the lifecycle, the start lock, the loader thread and the join, and calls these in the order
 * §5.1 gives: [openStore] and [startSeed] under its lock on the `start()` caller, [startTask] and each scheduled [sync] on
 * the loader, [closeStore], [clear] and [closeEngine] from `close()`. Never two of them at once, so the reference has one writer at a time (spec
 * §3 "Purity gate"). `@RevoktInternalApi`: the binding's plumbing, outside the public API.
 *
 * - [seed] is the resolved seed (null: no local data source), [channel] the configured one (set whenever a CRLite
 *   source is, `Revokt.Builder.build()`'s `CHANNEL_UNSET`), [fetchingSource] whether a fetching source serves CRLite.
 * - The seed's x5u chain must end in [pinnedRootSpkis]: the configured Remote Settings source's pins, else
 *   `MozillaRemoteSettings.DEFAULT`'s ([of]); the seed is Mozilla's signed collection either way (spec §6.5).
 * - [client] is the Remote Settings client of the fetching source (null: none, so nothing syncs), and [random] the
 *   schedule's jitter source (#147).
 */
@RevoktInternalApi
// One parameter per configuration value the data side reads (`of` is the binding's entry), one function per step of
// spec §5.1 the binding drives.
@Suppress("LongParameterList", "TooManyFunctions")
public class CrliteRuntime internal constructor(
    private val seed: SeedSource?,
    channel: CrliteChannel?,
    private val crlite: Boolean,
    private val fetchingSource: Boolean,
    private val engine: RevocationEngine,
    private val verifier: SignatureVerifier,
    private val policy: RevoktPolicy,
    pinnedRootSpkis: Set<ByteString>,
    private val storage: StorageBackend,
    private val logger: RevoktLogger,
    client: RemoteSettingsClient? = null,
    private val random: Random = Random.Default,
) {
    /** What the store's layout reads and writes: [storage] until [openStore] falls back to a fresh in-memory store. */
    private val active = ActiveStorage(storage)

    private val store: StoreLayout? =
        channel?.let {
            val limits = client?.limits ?: FetchLimits()
            StoreLayout(active, Dataset.CRLITE, it, limits.maxJsonBytes, limits.maxChangesetRecords)
        }

    /** The store [openStore] opened, held until [closeStore]; a fallback is kept, so it is never retried. */
    @Volatile
    private var opened: OpenedStore? = null

    /** What handshakes and the evaluator read (spec §3): before the start task ends, every configured dataset pending. */
    internal val snapshot: SnapshotRef = SnapshotRef(initial(pending = true, epoch = 0))

    private val loader: SeedLoader? =
        if (seed != null && store != null) {
            SeedLoader(
                seed,
                store,
                engine,
                snapshot,
                verifier,
                SeedPolicy(pinnedRootSpkis, fetchingSource),
                logger,
            )
        } else {
            null
        }

    /** The CRLite updater over [client] (spec §11's 0.2 row), or null when no fetching source serves CRLite. */
    private val updater: CrliteSync? =
        if (client != null && store != null) CrliteSync(client, store, engine, snapshot, verifier, logger) else null

    /** The fetching source's id, for its entry in `updater.json`. */
    private val sourceId: String? = client?.source?.sourceId

    /** Whether a fetching source is configured, so the loader schedules a [sync] after the start task (#147). */
    public val polls: Boolean get() = updater != null

    /** The verifier's startup probe (spec §3 "Verifier contract"), read once, here, for the walk and the S diagnostics. */
    private val probe: Set<String> = verifier.unsupportedOids().toSet()

    /**
     * The signed `<ts>` of the seed generation this instance serves: one it installed, or one an earlier process stored
     * that the recovery chain loaded (a restart is a first start, spec §4 `SEED_PAST_REJECT_THRESHOLD`); null until one is.
     */
    @Volatile
    private var seedTimestampMillis: Long? = null

    /**
     * Whether the start task's store step did not resolve (the #273 review on #143, spec §7.1 "no sync runs after a
     * stored-generation read that threw until that read resolves"): a store read of the recovery chain threw, or the
     * seed's install failed before `activate`. No generation is live then, although the store may hold one, so a sync
     * would wrongly treat it as "none loaded" and ignore the watermark. While it is set, every sync re-runs the chain
     * first and syncs only once it resolves ([sync], #147). A chain that serves a stored generation, or installs the
     * seed, resolves it (#287).
     */
    @Volatile
    public var storeReadUnresolved: Boolean = false
        private set

    /**
     * The consecutive re-reads by [sync] that left [storeReadUnresolved] set, for the backoff before the next one
     * ([PollSchedule.unresolvedRetryAtMillis]); 0 once the read resolves. Held in memory only.
     */
    private var unresolvedReReads = 0

    /** Whether `start()` ran in the sole-seed `ENFORCE` configuration (spec §4 S bullet). */
    @Volatile
    private var soleSeed = false

    /** Whether `start()`'s sole-seed step left the seed live, so the start task's chain has nothing to load. */
    @Volatile
    private var seededSynchronously = false

    /**
     * The store failures the last run of the start task's store step counted, each once (spec §5.1, §6.5): its value
     * for `storeFailures`, which 0.2 only logs (§11's 0.2 row has no `state`).
     */
    @Volatile
    internal var startStoreFailures: Int = 0
        private set

    /** Whether `start()` found the seed's header absent or unreadable: the chain's re-runs then skip the seed. */
    @Volatile
    private var seedHeaderFailed = false

    /**
     * The anchor snapshot over [delegate] and its index (spec §5.1 "Anchor snapshot"), or null when it cannot be built:
     * an empty, null or throwing `getAcceptedIssuers()`, or no anchor that parses. In 0.2 `start()` then succeeds and
     * [Evaluator.evaluate] throws until an index exists (§11's 0.2 row); the failure is logged. A fatal error propagates.
     */
    @Suppress("TooGenericExceptionCaught") // §11's 0.2 row: any non-fatal failure of the build leaves no index.
    public fun anchorIndex(
        platformTrust: PlatformTrust,
        delegate: X509TrustManager,
        nowMillis: Long,
    ): IndexedSnapshot? =
        try {
            AnchorSnapshots.build(platformTrust, delegate, nowMillis)
        } catch (t: Throwable) {
            absorb(t)
            logger.safeLog(LogLevel.WARN, "no anchor snapshot: Evaluator.evaluate throws until one exists", t)
            null
        }

    /**
     * `start()`'s store step (spec §5.1, §6.5), on the caller's thread after the anchor snapshot and before [startSeed]:
     * the identity registered, the lock taken and held until [closeStore], then `store.version` read ([StoreOpen]). A
     * second instance on one store in this process throws [IllegalStateException], with nothing held. On
     * `STORE_LOCKED`, `STORE_UNREADABLE` or `STORE_NEWER_LAYOUT` under `IN_MEMORY` the instance runs on a fresh
     * in-memory store for the life of the process: the lock is released, the identity deregistered and the warning
     * logged (0.2 has no `state`), and a later call keeps that store, so the lock is never tried again.
     */
    public fun openStore() {
        val previous = opened
        if (previous != null) {
            check(previous.fallback) { "the store is already open" }
            return
        }
        val open = StoreOpen.open(storage, logger)
        active.target = open.storage
        opened = open
    }

    /**
     * Releases the store's lock, then deregisters its identity (spec §5.1 `close()`, and a `start()` that throws after
     * [openStore]); a no-op when nothing is held. A fallback stays in place.
     */
    public fun closeStore() {
        val open = opened ?: return
        if (open.fallback) return
        opened = null
        open.close()
    }

    /** Whether the instance runs in memory instead of on its storage (spec §4 `RevoktState.storageFallback`, in 0.3). */
    internal val storageFallback: Boolean get() = opened?.fallback == true

    /**
     * The synchronous seed steps of `start()` (spec §4 S bullet, §5.1), on the caller's thread, before the flip:
     * 1. the `seed.json` header, read in every configuration: a channel mismatch throws `IllegalStateException`
     *    (`SEED_CHANNEL_MISMATCH`);
     * 2. under [soleSeed] (`ENFORCE`, `NO_DATA` rejecting, the seed the only local data source) the whole load, which
     *    must leave the seed live: a seed that is absent, unreadable, or whose install failed before `activate` throws
     *    `IllegalStateException` (`SEED_UNREADABLE`), since every handshake would otherwise be rejected without a word
     *    (spec §2 goal 3).
     *
     * Elsewhere an absent or unreadable seed is a logged `SEED_UNREADABLE`, and the instance runs without it. Returns
     * whether the loader's start task still has the seed to load. The messages name the code and never the seed's
     * contents, a path or an exception's text: [SeedLoader] has logged the detail.
     */
    public fun startSeed(
        soleSeed: Boolean,
        nowMillis: Long,
    ): Boolean {
        this.soleSeed = soleSeed
        val loader = loader ?: return false
        val header = loader.checkHeader()
        check(header !is SeedLoad.ChannelMismatch) { CHANNEL_MISMATCH }
        if (header != null) {
            seedHeaderFailed = true
            check(!soleSeed) { unreadable(header) }
            if (header is SeedLoad.Absent) logAbsent()
            return false
        }
        if (!soleSeed) return true
        // §4 S bullet: a stored live generation that passes Load's steps 1 and 2 is the start task's to load, so the
        // common cold start never decodes on the calling thread, and a readable store masks a bad seed.
        if (storedLive(store)) return true
        val load = loader.load(nowMillis)
        when (load) {
            is SeedLoad.Installed -> seedTimestampMillis = load.timestampMillis

            // The engine holds the seed; the snapshot was published unless a fatal error interrupted it (§6.5).
            is SeedLoad.Failed -> check(load.activated) { unreadable(load) }

            else -> error(if (load is SeedLoad.ChannelMismatch) CHANNEL_MISMATCH else unreadable(load))
        }
        seededSynchronously = true
        return false
    }

    /**
     * The loader's start task (spec §5.1 "one loader task": the seed, then the first sync): the seed load when
     * [loadSeed], then, when a fetching source is configured ([polls]), the first sync, as [sync] runs it, then
     * `pending` cleared for every configured dataset (§8): a dataset the task left without a generation is published
     * with `pending = false` and `generationEpoch++`, so `NO_DATA` can fire. In the sole-seed configuration a store step
     * that leaves no generation served (a stored `live` that passes Load's steps 1 and 2 but not 3 or 4, beside a seed
     * that does not install: spec §4 S bullet) is logged at `ERROR`, naming `SEED_UNREADABLE` and `NO_DATA`, since
     * `start()` has already returned. Returns when the loader syncs next (a
     * wall-clock time on [nowMillis]'s clock, for [delayMillis]), or null when nothing polls. Never throws: a throwable
     * from any step is logged and the task still clears `pending`, as §5.1 has every loader task catch `Throwable`; a
     * fatal error is rethrown after that.
     */
    @Suppress("TooGenericExceptionCaught") // §5.1: every loader task catches Throwable.
    public fun startTask(
        loadSeed: Boolean,
        nowMillis: () -> Long,
    ): Long? {
        var fatal: Throwable? = null
        try {
            if (!seededSynchronously) storeReadUnresolved = recover(nowMillis, withSeed = loadSeed).unresolved
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t)) fatal = t
            logger.safeLog(LogLevel.ERROR, "the start task's store step threw", t)
        }
        reportNoData()
        var next: Long? = null
        if (polls && fatal == null) {
            var clockRead = false
            try {
                val now = nowMillis()
                clockRead = true
                next = sync(now)
            } catch (t: Throwable) {
                restoreInterrupt(t)
                if (isFatal(t)) fatal = t
                // sync() logs its own throwable and lets out only a fatal one; the clock's is logged here.
                if (!clockRead) logger.safeLog(LogLevel.ERROR, "the clock threw before the first sync", t)
            }
        }
        try {
            clearPending()
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t) && fatal == null) fatal = t
            logger.safeLog(LogLevel.ERROR, "the start task could not clear pending", t)
        }
        fatal?.let { throw it }
        return next
    }

    /**
     * One sync of the fetching source at [nowMillis], the loader's one clock read for it (spec §5.1, §7.1, #147), and
     * the time of the next one ([PollSchedule]): 6 h plus a jitter in `[0, 36 min)` after a poll that did not fail,
     * the source's backoff after one that did, and 15 min after a sync that wrote nothing.
     * 1. While [storeReadUnresolved], the start task's recovery chain runs again first, to re-read the store; the sync
     *    runs only once it resolves, and otherwise fetches nothing, writes nothing and is retried after the failure
     *    backoff of its consecutive re-reads ([PollSchedule.unresolvedRetryAtMillis]: 15 min, doubled up to 6 h).
     * 2. [CrliteSync.syncOnce]; its result is logged (spec §11's 0.2 row has no `state`): `INSTALLED` at `INFO`, each
     *    warning at `WARN`; `FAILED` is logged by the sync.
     * 3. The seed's `STALE` gate (§8): once `updater.json` records an attempt since the seed's install, the seed
     *    generation is published again with the gate open and `generationEpoch++`.
     *
     * A non-fatal throwable is logged and swallowed, and the next sync is at [retryAtMillis]; a fatal one is logged and
     * rethrown for the loader to reschedule first (§6.5: "nothing escapes the loader thread"; the loader's task swallows
     * what it rethrows, so the log line is its only trace). Throws [IllegalStateException] when nothing polls.
     */
    @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable.
    public fun sync(nowMillis: Long): Long {
        val sync = checkNotNull(updater) { "no fetching source" }
        return try {
            if (storeReadUnresolved) reRead(nowMillis)?.let { return it }
            val run = sync.syncOnce(nowMillis)
            report(run)
            openGate(run.updater)
            PollSchedule.nextAtMillis(run, checkNotNull(sourceId), nowMillis, random)
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t)) {
                logger.safeLog(LogLevel.ERROR, "the sync threw a fatal error, rethrown", t)
                throw t
            }
            logger.safeLog(LogLevel.ERROR, "the sync threw", t)
            PollSchedule.retryAtMillis(nowMillis)
        }
    }

    /**
     * The start task's store step again (#147), for [sync] while [storeReadUnresolved]: no sync while it does not
     * resolve, rather than one that ignores the watermark beside a generation the store may hold (fail closed). Returns
     * null once it resolves, else when to try again: each re-read decodes again what failed, so the next waits the
     * failure backoff of the consecutive re-reads (spec §5.1 "The sync schedule").
     */
    private fun reRead(nowMillis: Long): Long? {
        storeReadUnresolved = recover({ nowMillis }, withSeed = loader != null && !seedHeaderFailed).unresolved
        if (!storeReadUnresolved) {
            unresolvedReReads = 0
            return null
        }
        if (unresolvedReReads < Int.MAX_VALUE) unresolvedReReads++
        logger.safeLog(LogLevel.WARN, "the store read is still unresolved: no sync until it resolves (spec §7.1)")
        return PollSchedule.unresolvedRetryAtMillis(nowMillis, unresolvedReReads)
    }

    /**
     * In the sole-seed configuration, after the start task's store step (not run when `start()` installed the seed): a
     * step that left no generation served (spec §4 S bullet: a stored `live` that passes Load's steps 1 and 2 but not 3
     * or 4, beside a seed that does not install) is logged at `ERROR`, naming `SEED_UNREADABLE` and `NO_DATA`, since
     * `start()` has returned (0.2 has no `state`).
     */
    private fun reportNoData() {
        if (!soleSeed || seededSynchronously) return
        if (snapshot.snapshot.datasets[Dataset.CRLITE]?.generationId != null) return
        logger.safeLog(
            LogLevel.ERROR,
            "SEED_UNREADABLE: the stored generation does not load and the seed does not install, so NO_DATA rejects " +
                "every handshake until a sync installs a generation (spec §4)",
        )
    }

    /**
     * The delay from [nowMillis] until [atMillis], a time [startTask] or [sync] returned, clamped to 60 s to 24 h
     * ([PollSchedule.delayMillis]): the loader waits it on its monotonic timer.
     */
    public fun delayMillis(
        atMillis: Long,
        nowMillis: Long,
    ): Long = PollSchedule.delayMillis(atMillis, nowMillis)

    /** When the loader syncs after a sync step that threw a fatal error: 15 min after [nowMillis]. */
    public fun retryAtMillis(nowMillis: Long): Long = PollSchedule.retryAtMillis(nowMillis)

    /**
     * The start task's store step (spec §5.1 "one loader task", §6.5 crash recovery): `live` → `previous` → seed →
     * nothing, each failure logged and counted once. The seed load decides first, on Load's step 1 alone (each stored
     * candidate's `<ts>` against the seed's): it skips the seed beside a trustworthy `live` that is not older, adopts a
     * newer stored generation under rule (b), or installs the seed. Only the generation that wins is then loaded in full
     * ([serveStored]); one that fails falls down the chain, and the seed load runs again with it [SeedLoader.load]'s
     * `unloadable`, so rule (b) applies to it. A stored generation older than the seed is not decoded here (B4).
     * Without a seed ([withSeed] false, or none configured), the chain is the pointer's `live`, then its `previous`.
     *
     * Returns whether the store read stays unresolved (a store read that threw, or a seed install that failed before
     * `activate`), and the start's store failures: the chain's, and each pass's new ones through one fault set
     * ([SeedLoader.load]'s `faults`), so each fault is counted once across passes. A fatal error propagates, for the
     * start task to rethrow after `pending` is cleared.
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount", "CyclomaticComplexMethod") // One arm per way a step ends.
    private fun recover(
        clock: () -> Long,
        withSeed: Boolean,
    ): Recovery {
        val store = store ?: return Recovery(unresolved = false, storeFailures = 0)
        val failed = LinkedHashSet<String>()
        val faults = HashSet<String>()
        var counted = 0
        // Read once, and only when a step needs it: an empty store with no seed reads no clock here.
        val nowMillis by lazy(clock)

        fun chain(notBefore: Long? = null): StartChain {
            val before = failed.toSet()
            return serveChain(store, { nowMillis }, failed, engine, snapshot, fetchingSource, logger, notBefore).also {
                // A failed generation whose file reads is that one fault: the seed's rewrite of its blobs is not another
                // (as the sync's heal-install does not count them, #336 review).
                for (name in failed - before) {
                    (store.stored(name) as? StoreRead.Found)?.value?.let { faults += it.blobNames }
                }
                // A stored seed generation an earlier process installed is live as if this one had (spec §4).
                val served = snapshot.snapshot.datasets[store.dataset]?.takeIf { g -> g.fromSeed }
                val servedAt = served?.sourceTimestampMillis
                if (it != StartChain.NONE && servedAt != null) seedLive(servedAt, nowMillis)
            }
        }

        fun done(unresolved: Boolean): Recovery {
            // A generation the chain failed is a fault of its own unless a seed pass counted it first.
            counted += failed.count { faults.add(it) }
            // Noted for [startStoreFailures], and logged: §11's 0.2 row has no `state`.
            startStoreFailures = counted
            if (counted > 0) logger.safeLog(LogLevel.WARN, "the start task counted $counted store failures")
            return Recovery(unresolved, counted)
        }
        return try {
            val seedLoader = loader.takeIf { withSeed } ?: return chain().let { done(unresolved = false) }
            // The generation the chain fell back to, served: no seed pass adopts it again (#336), so it decodes once.
            var served: String? = null
            // At start nothing is served yet, so each pass that does not end fails a generation: this bound suffices.
            repeat(store.generationNames().size + 2) {
                val load = seedLoader.load(nowMillis, failed, setOfNotNull(served), faults)
                counted += load.storeFailures
                when (load) {
                    is SeedLoad.Installed, is SeedLoad.Failed -> {
                        return done(loaded(load) { nowMillis })
                    }

                    is SeedLoad.Absent, is SeedLoad.Unreadable, is SeedLoad.ChannelMismatch -> {
                        loaded(load) { nowMillis }
                        if (served == null) chain()
                        return done(unresolved = false)
                    }

                    is SeedLoad.Skipped -> {
                        // Kept beside the previous the chain fell back to, when nothing newer is adoptable.
                        if (served != null) return done(unresolved = false)
                        when (chain(notBefore = load.seedTimestampMillis)) {
                            StartChain.LIVE -> return done(unresolved = false)

                            // Rule (b) still runs for the live that did not load: a newer stored generation wins.
                            StartChain.PREVIOUS -> served = snapshot.servedFile(store.dataset)

                            StartChain.NONE -> Unit
                        }
                    }

                    is SeedLoad.Adopted -> {
                        if (chain() != StartChain.NONE) return done(unresolved = false)
                    }
                }
            }
            // Fail closed: a chain that does not settle leaves the read unresolved, retried at the next sync.
            logger.safeLog(LogLevel.WARN, "${store.root}: the recovery chain did not settle; the read stays unresolved")
            done(unresolved = true)
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t)) throw t
            logger.safeLog(LogLevel.WARN, "${store.root}: a store read of the recovery chain threw", t)
            done(unresolved = true)
        }
    }

    /** How [recover] ended: whether the store read stays unresolved, and the store failures it counted, each once. */
    private class Recovery(
        val unresolved: Boolean,
        val storeFailures: Int,
    )

    /** Logs [run]'s result (spec §11's 0.2 row: no `state` yet): `FAILED` is the sync's own log line. */
    private fun report(run: SyncRun) {
        val result = run.result
        if (result.outcome == SyncOutcome.INSTALLED) {
            logger.safeLog(LogLevel.INFO, "${result.sourceId}: installed ${result.installed.values.joinToString()}")
        }
        for (w in result.warnings) logger.safeLog(LogLevel.WARN, "${w.code}: ${w.message}")
        if (run.storeFailures > 0) logger.safeLog(LogLevel.WARN, "the sync counted ${run.storeFailures} store failures")
    }

    /**
     * Opens the live seed generation's `STALE` gate (spec §8: "until a sync attempt has completed since the seed was
     * installed", `datasetLastAttemptAtMillis ≥ seedInstalledAtMillis`, both in [record], which the sync wrote; null when
     * it wrote none, which is no attempt): published again with the gate open and `generationEpoch++`.
     */
    private fun openGate(record: UpdaterRecord?) {
        val attempt = record?.datasetLastAttemptAtMillis ?: return
        val current = snapshot.snapshot
        val live = current.datasets[Dataset.CRLITE] ?: return
        if (live.generationId == null || !live.fromSeed || live.staleGateOpen) return
        if (attempt < (record.seedInstalledAtMillis ?: Long.MIN_VALUE)) return
        snapshot.publish(
            GenerationSnapshot(
                current.generationEpoch + 1,
                current.datasets + (Dataset.CRLITE to live.copy(staleGateOpen = true)),
                current.coverageEndMillis,
            ),
        )
    }

    /**
     * What the loader does with a seed load's end: the live seed's `<ts>` and its diagnostics, or the warning for a load
     * that did not install. Returns whether the store read stays unresolved: after an install that failed before
     * `activate`. `Skipped` and `Adopted` are [recover]'s, which then loads the stored generation.
     */
    private fun loaded(
        load: SeedLoad,
        nowMillis: () -> Long,
    ): Boolean {
        when (load) {
            is SeedLoad.Installed -> {
                seedLive(load.timestampMillis, nowMillis())
            }

            is SeedLoad.Failed -> {
                return !load.activated
            }

            is SeedLoad.Absent -> {
                logAbsent()
            }

            // Logged by the loader; the stored ones are recover's.
            is SeedLoad.Unreadable, is SeedLoad.ChannelMismatch, is SeedLoad.Skipped, is SeedLoad.Adopted -> {
                return false
            }
        }
        return false
    }

    /**
     * A seed generation at the signed [timestampMillis] is live, installed now or stored by an earlier process: its
     * `<ts>` for [diagnostics], and `SEED_PAST_REJECT_THRESHOLD` logged as well as returned, since the start task may
     * end after `start()` returned (spec §4; 0.2 has no `state`).
     */
    private fun seedLive(
        timestampMillis: Long,
        nowMillis: Long,
    ) {
        seedTimestampMillis = timestampMillis
        seedPastRejectThreshold(policy.form, timestampMillis, nowMillis).forEach {
            logger.safeLog(LogLevel.WARN, "${it.code}: ${it.message}")
        }
    }

    /** Every configured dataset out of `pending`; a dataset with no generation advances the epoch (spec §8). */
    private fun clearPending() {
        val current = snapshot.snapshot
        val waiting = current.datasets.filterValues { it.pending }
        if (waiting.isEmpty()) return
        val cleared = waiting.mapValues { (_, g) -> g.copy(pending = false) }
        snapshot.publish(
            GenerationSnapshot(current.generationEpoch + 1, current.datasets + cleared, current.coverageEndMillis),
        )
    }

    /**
     * The S diagnostics of spec §4 that `start()` returns (`SEED_PAST_REJECT_THRESHOLD`,
     * `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP`, `RULE_FLIPPED_THIS_MINOR`), at [nowMillis], over the seed live so far.
     */
    public fun diagnostics(nowMillis: Long): List<PolicyDiagnostic> =
        startDiagnostics(policy.form, probe, seedTimestampMillis, nowMillis)

    /**
     * The [Evaluator] over this runtime's generation reference (spec §4 `revokt.evaluator`): [lifecycle] and [anchors]
     * are the binding's, read once per evaluation; [fallback] is decision step 6's PKIX builder, null under
     * `pkixFallback(false)`.
     */
    public fun evaluator(
        lifecycle: () -> RevoktLifecycle,
        anchors: () -> IndexedSnapshot?,
        fallback: PathBuilderFallback?,
        clock: () -> Long,
    ): Evaluator =
        RevoktEvaluator(
            lifecycle = lifecycle,
            anchors = anchors,
            generation = { snapshot.snapshot },
            policy = { policy.form },
            engine = engine,
            walk = DecideInputs(verifier, probe, lruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES), fallback),
            clock = clock,
            logger = logger,
        )

    /**
     * Clears the generation reference (spec §5.1 `close()`): after the loader stopped, the one write left. Every
     * configured dataset is published with no generation and not pending.
     */
    public fun clear() {
        snapshot.publish(initial(pending = false, epoch = snapshot.snapshot.generationEpoch + 1))
    }

    /**
     * `engine.close()` (spec §5.1 `close()`: always, last; `Revokt` owns the engine). A throw propagates: `close()`
     * rethrows it once every other step has run, so an engine that did not close is never hidden (a `try`-with-resources
     * or `use {}` attaches it as suppressed when its body threw).
     */
    public fun closeEngine() {
        engine.close()
    }

    /** Logs [message] at [level], swallowing a throwing logger (spec §3). */
    public fun log(
        level: LogLevel,
        message: String,
        cause: Throwable? = null,
    ) {
        logger.safeLog(level, message, cause)
    }

    private fun initial(
        pending: Boolean,
        epoch: Long,
    ): GenerationSnapshot =
        GenerationSnapshot(
            epoch,
            if (crlite) {
                mapOf(
                    Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, pending, false),
                )
            } else {
                emptyMap()
            },
            null,
        )

    private fun logAbsent() {
        logger.safeLog(LogLevel.WARN, "${WarningCode.SEED_UNREADABLE}: the configured seed source opened no archive")
    }

    private fun unreadable(load: SeedLoad): String =
        "${WarningCode.SEED_UNREADABLE}: the seed is the only local data source and " +
            (if (load is SeedLoad.Absent) "opened no archive" else "did not load") +
            ", and under ENFORCE with NO_DATA rejecting every handshake would be rejected: fix the seed artifact, " +
            "or allow NO_DATA (spec §4; the cause is logged)"

    @RevoktInternalApi
    public companion object {
        private val CHANNEL_MISMATCH =
            "${WarningCode.SEED_CHANNEL_MISMATCH}: the seed is for another channel than the configured " +
                "one; ship the seed of the configured channel (spec §4, §6.5)"

        /**
         * The runtime of a `Revokt` whose store is [storage]: the seed pins and collection from [remoteSettings], else
         * `MozillaRemoteSettings.DEFAULT`'s. When [remoteSettings] serves CRLite and a channel is set, its client fetches
         * through [http] on [ioDispatcher] under the four caps (spec §4 `limits { }`), and the schedule draws its jitter
         * from [random] (#147).
         */
        @Suppress("LongParameterList") // One per configuration value the data side reads.
        public fun of(
            seed: SeedSource?,
            channel: CrliteChannel?,
            remoteSettings: MozillaRemoteSettings?,
            engine: RevocationEngine,
            verifier: SignatureVerifier,
            policy: RevoktPolicy,
            storage: RevoktStorage,
            logger: RevoktLogger,
            http: HttpFetcher,
            ioDispatcher: CoroutineDispatcher,
            caps: FetchCaps,
            random: Random,
        ): CrliteRuntime {
            val source = remoteSettings ?: MozillaRemoteSettings.DEFAULT
            val fetching = remoteSettings?.collection(Dataset.CRLITE) != null
            val client =
                if (fetching && channel != null) {
                    RemoteSettingsClient(
                        checkNotNull(remoteSettings),
                        Dataset.CRLITE,
                        http,
                        ioDispatcher,
                        FetchLimits(caps.maxJsonBytes, caps.maxX5uBytes, caps.maxFilterBytes, caps.maxChangesetRecords),
                    )
                } else {
                    null
                }
            return CrliteRuntime(
                seed = seed,
                channel = channel,
                crlite = seed != null || fetching,
                fetchingSource = fetching,
                engine = engine,
                verifier = verifier,
                policy = policy,
                pinnedRootSpkis = source.pinnedRootSpkis,
                storage = storage.backend,
                logger = logger,
                client = client,
                random = random,
            )
        }
    }

    /** The four caps a fetching source fetches under (spec §4 `limits { }`), each at least its `RevoktLimits` constant. */
    @RevoktInternalApi
    public class FetchCaps(
        public val maxFilterBytes: Long,
        public val maxJsonBytes: Long,
        public val maxX5uBytes: Long,
        public val maxChangesetRecords: Int,
    )
}

/**
 * The storage a runtime's layout runs on (spec §3): [target], the configured one until `openStore()` replaces it with
 * the in-memory fallback. Only `openStore()` locks the configured one; this one has no lock and no identity of its own.
 */
private class ActiveStorage(
    @Volatile var target: StorageBackend,
) : StorageBackend {
    override fun read(name: String): ByteArray? = target.read(name)

    override fun write(
        name: String,
        bytes: ByteArray,
    ) = target.write(name, bytes)

    override fun delete(name: String) = target.delete(name)

    override fun names(): Set<String> = target.names()

    override fun isEmpty(): Boolean = target.isEmpty()

    override fun lock(): AutoCloseable = error("the runtime's store is locked by openStore() only")
}
