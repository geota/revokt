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
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.CrliteSync
import dev.revokt.engine.update.PollSchedule
import dev.revokt.engine.update.SnapshotRef
import dev.revokt.engine.update.SyncRun
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
 * §5.1 gives: [startSeed] under its lock on the `start()` caller, [startTask] and each scheduled [sync] on the loader,
 * [clear] and [closeEngine] from `close()`. Never two of them at once, so the reference has one writer at a time (spec
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
@Suppress("LongParameterList") // One per configuration value the data side reads; `of` is the binding's entry.
public class CrliteRuntime internal constructor(
    private val seed: SeedSource?,
    channel: CrliteChannel?,
    private val crlite: Boolean,
    private val fetchingSource: Boolean,
    private val engine: RevocationEngine,
    private val verifier: SignatureVerifier,
    private val policy: RevoktPolicy,
    pinnedRootSpkis: Set<ByteString>,
    collection: String?,
    storage: RevoktStorage,
    private val logger: RevoktLogger,
    client: RemoteSettingsClient? = null,
    private val random: Random = Random.Default,
) {
    private val store: StoreLayout? = channel?.let { StoreLayout(storage, Dataset.CRLITE, it) }

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
                SeedPolicy(pinnedRootSpkis, collection, fetchingSource),
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

    /** The signed `<ts>` of the seed this instance installed; null until one is. */
    @Volatile
    private var seedTimestampMillis: Long? = null

    /**
     * Whether the seed load's store step did not resolve (the #273 review on #143, spec §7.1 "no sync runs after a
     * stored-generation read that threw until that read resolves"): its read threw, or its install failed before
     * `activate`, or it found a stored generation 0.2 does not load (`Skipped`, `Adopted`). No generation is live then,
     * although the store may hold one, so a sync would wrongly treat it as "none loaded" and ignore the watermark. While
     * it is set, every sync re-runs the seed load first and syncs only once it resolves ([sync], #147).
     */
    @Volatile
    public var storeReadUnresolved: Boolean = false
        private set

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
        val loader = loader ?: return false
        val header = loader.checkHeader()
        check(header !is SeedLoad.ChannelMismatch) { CHANNEL_MISMATCH }
        if (header != null) {
            check(!soleSeed) { unreadable(header) }
            if (header is SeedLoad.Absent) logAbsent()
            return false
        }
        if (!soleSeed) return true
        val load = loader.load(nowMillis)
        when (load) {
            is SeedLoad.Installed -> seedTimestampMillis = load.timestampMillis

            // The engine holds the seed; the snapshot was published unless a fatal error interrupted it (§6.5).
            is SeedLoad.Failed -> check(load.activated) { unreadable(load) }

            else -> error(if (load is SeedLoad.ChannelMismatch) CHANNEL_MISMATCH else unreadable(load))
        }
        return false
    }

    /**
     * The loader's start task (spec §5.1 "one loader task": the seed, then the first sync): the seed load when
     * [loadSeed], then, when a fetching source is configured ([polls]), the first sync, as [sync] runs it, then
     * `pending` cleared for every configured dataset (§8): a dataset the task left without a generation is published
     * with `pending = false` and `generationEpoch++`, so `NO_DATA` can fire. Returns when the loader syncs next (a
     * wall-clock time on [nowMillis]'s clock, for [delayMillis]), or null when nothing polls. Never throws: a throwable
     * from any step is logged and the task still clears `pending`, as §5.1 has every loader task catch `Throwable`; a
     * fatal error is rethrown after that, and the loader then reschedules at [retryAtMillis] (#147).
     */
    @Suppress("TooGenericExceptionCaught") // §5.1: every loader task catches Throwable.
    public fun startTask(
        loadSeed: Boolean,
        nowMillis: () -> Long,
    ): Long? {
        var fatal: Throwable? = null
        try {
            if (loadSeed) {
                storeReadUnresolved =
                    loaded(checkNotNull(loader).load(nowMillis()), nowMillis, resolved = true)
            }
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t)) fatal = t
            logger.safeLog(LogLevel.ERROR, "the start task's seed step threw", t)
        }
        var next: Long? = null
        if (polls && fatal == null) {
            try {
                next = sync(nowMillis())
            } catch (t: Throwable) {
                // sync() lets only a fatal error out.
                fatal = t
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
     * 1. While [storeReadUnresolved], the seed load runs again first, to re-read the store; the sync runs only once it
     *    resolves, and otherwise fetches nothing, writes nothing and is retried in 15 min.
     * 2. [CrliteSync.syncOnce]; its result is logged (spec §11's 0.2 row has no `state`): `INSTALLED` at `INFO`, each
     *    warning at `WARN`; `FAILED` is logged by the sync.
     * 3. The seed's `STALE` gate (§8): once `updater.json` records an attempt since the seed's install, the seed
     *    generation is published again with the gate open and `generationEpoch++`.
     *
     * A non-fatal throwable is logged and swallowed, and the next sync is at [retryAtMillis]; a fatal one is rethrown
     * for the loader to reschedule first (§6.5: "nothing escapes the loader thread"). Throws [IllegalStateException]
     * when nothing polls.
     */
    @Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable.
    public fun sync(nowMillis: Long): Long {
        val sync = checkNotNull(updater) { "no fetching source" }
        return try {
            if (storeReadUnresolved && !reread(nowMillis)) return PollSchedule.retryAtMillis(nowMillis)
            val run = sync.syncOnce(nowMillis)
            report(run)
            openGate(run.updater)
            PollSchedule.nextAtMillis(run, checkNotNull(sourceId), nowMillis, random)
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t)) throw t
            logger.safeLog(LogLevel.ERROR, "the sync threw", t)
            PollSchedule.retryAtMillis(nowMillis)
        }
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
     * The seed load again, for [storeReadUnresolved] (#147): true once the store read resolves, which here is a load
     * that left the seed live (`Installed`, or `Failed` after `activate`). Anything else keeps the read unresolved: a
     * read that throws again, an install that failed before `activate`, a stored generation 0.2 does not load
     * (`Skipped`, `Adopted`), and a seed that no longer reaches the store read (`Unreadable`, `Absent`). Fail closed:
     * no sync then, rather than one that ignores the watermark beside a generation the store may hold.
     */
    private fun reread(nowMillis: Long): Boolean {
        val load = checkNotNull(loader) { "only the seed load leaves the store read unresolved" }.load(nowMillis)
        storeReadUnresolved = loaded(load, { nowMillis }, resolved = false)
        if (storeReadUnresolved) {
            logger.safeLog(
                LogLevel.WARN,
                "the store read is still unresolved ($load): no sync until it resolves (spec §7.1)",
            )
        }
        return !storeReadUnresolved
    }

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
     * What the loader does with a seed load's end: the live seed's `<ts>`, or the warning for a load that did not.
     * Returns whether the store read stays unresolved ([storeReadUnresolved]): after a load that threw or failed before
     * `activate`, or that found a stored generation 0.2 does not load (`Skipped`, `Adopted`); after one that never
     * reached the store read (`Unreadable`, `Absent`, `ChannelMismatch`), [resolved], which is the start task's reading
     * (nothing read yet, the 0.2 store fresh) and not a re-read's.
     */
    private fun loaded(
        load: SeedLoad,
        nowMillis: () -> Long,
        resolved: Boolean,
    ): Boolean {
        when (load) {
            is SeedLoad.Installed -> {
                seedTimestampMillis = load.timestampMillis
                // Logged as well as returned: the start task may end after start() returned (spec §4, 0.2 has no state).
                seedPastRejectThreshold(policy.form, load.timestampMillis, nowMillis()).forEach {
                    logger.safeLog(LogLevel.WARN, "${it.code}: ${it.message}")
                }
            }

            is SeedLoad.Failed -> {
                return !load.activated
            }

            is SeedLoad.Absent -> {
                logAbsent()
                return !resolved
            }

            // Logged by the loader.
            is SeedLoad.Unreadable, is SeedLoad.ChannelMismatch -> {
                return !resolved
            }

            // A stored generation this in-memory store, fresh at every build, cannot hold at start; 0.3 loads it. 0.2
            // does not, so nothing is live beside it, and a sync must not take that for "none loaded" (fail closed).
            is SeedLoad.Skipped, is SeedLoad.Adopted -> {
                return true
            }
        }
        return false
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
                collection = source.collection(Dataset.CRLITE)?.let { source.bucket + "/" + it },
                storage = storage,
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
