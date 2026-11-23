// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.Evaluator
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
import dev.revokt.WarningCode
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.policy.seedPastRejectThreshold
import dev.revokt.engine.policy.startDiagnostics
import dev.revokt.engine.seed.SeedLoad
import dev.revokt.engine.seed.SeedLoader
import dev.revokt.engine.seed.SeedPolicy
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.update.SnapshotRef
import dev.revokt.engine.walker.AnchorSnapshots
import dev.revokt.engine.walker.DecideInputs
import dev.revokt.engine.walker.IndexedSnapshot
import dev.revokt.engine.walker.absorb
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.lruMap
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog
import okio.ByteString
import javax.net.ssl.X509TrustManager

/**
 * The data side of one `Revokt` (spec §4, §5.1 "Lifecycle", §11's 0.2 row): the store over [storage], the one published
 * generation reference, the seed's start steps, the S diagnostics, the anchor index build and the [Evaluator]. The JVM
 * binding (revokt-jsse) keeps the lifecycle, the start lock, the loader thread and the join, and calls these in the order
 * §5.1 gives: [startSeed] under its lock on the `start()` caller, [startTask] on the loader, [clear] and [closeEngine]
 * from `close()`. Never two of them at once, so the reference has one writer at a time (spec §3 "Purity gate").
 * `@RevoktInternalApi`: the binding's plumbing, outside the public API.
 *
 * - [seed] is the resolved seed (null: no local data source), [channel] the configured one (set whenever a CRLite
 *   source is, `Revokt.Builder.build()`'s `CHANNEL_UNSET`), [fetchingSource] whether a fetching source serves CRLite.
 * - The seed's x5u chain must end in [pinnedRootSpkis]: the configured Remote Settings source's pins, else
 *   `MozillaRemoteSettings.DEFAULT`'s ([of]); the seed is Mozilla's signed collection either way (spec §6.5).
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

    /** The verifier's startup probe (spec §3 "Verifier contract"), read once, here, for the walk and the S diagnostics. */
    private val probe: Set<String> = verifier.unsupportedOids().toSet()

    /** The signed `<ts>` of the seed this instance installed; null until one is. */
    @Volatile
    private var seedTimestampMillis: Long? = null

    /**
     * Whether the start task's store read threw, so no generation loaded although the store may hold one (the #273
     * review on #143): a sync must re-read the store before it treats the absent generation as "none loaded" (#147).
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
     * The loader's start task (spec §5.1 "one loader task"): the seed load when [loadSeed], then `pending` cleared for
     * every configured dataset (§8): a dataset the load left without a generation is published with `pending = false`
     * and `generationEpoch++`, so `NO_DATA` can fire. Never throws: a throwable from any step is logged and the task
     * still clears `pending`, as §5.1 has every loader task catch `Throwable`; a fatal error is rethrown after that.
     */
    @Suppress("TooGenericExceptionCaught") // §5.1: every loader task catches Throwable.
    public fun startTask(
        loadSeed: Boolean,
        nowMillis: () -> Long,
    ) {
        var fatal: Throwable? = null
        try {
            if (loadSeed) loaded(checkNotNull(loader).load(nowMillis()), nowMillis)
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t)) fatal = t
            logger.safeLog(LogLevel.ERROR, "the start task's seed step threw", t)
        }
        try {
            clearPending()
        } catch (t: Throwable) {
            restoreInterrupt(t)
            if (isFatal(t) && fatal == null) fatal = t
            logger.safeLog(LogLevel.ERROR, "the start task could not clear pending", t)
        }
        fatal?.let { throw it }
    }

    /** What the loader does with a seed load's end: the live seed's `<ts>`, or the warning for a load that did not. */
    private fun loaded(
        load: SeedLoad,
        nowMillis: () -> Long,
    ) {
        when (load) {
            is SeedLoad.Installed -> {
                seedTimestampMillis = load.timestampMillis
                // Logged as well as returned: the start task may end after start() returned (spec §4, 0.2 has no state).
                seedPastRejectThreshold(policy.form, load.timestampMillis, nowMillis()).forEach {
                    logger.safeLog(LogLevel.WARN, "${it.code}: ${it.message}")
                }
            }

            is SeedLoad.Failed -> {
                if (!load.activated) storeReadUnresolved = true
            }

            is SeedLoad.Absent -> {
                logAbsent()
            }

            // Unreadable and ChannelMismatch are logged by the loader; Skipped and Adopted need a stored generation
            // this in-memory store, fresh at every build, cannot hold at start (0.3 loads them).
            is SeedLoad.Unreadable, is SeedLoad.ChannelMismatch, is SeedLoad.Skipped, is SeedLoad.Adopted -> {}
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
         * `MozillaRemoteSettings.DEFAULT`'s.
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
        ): CrliteRuntime {
            val source = remoteSettings ?: MozillaRemoteSettings.DEFAULT
            val fetching = remoteSettings?.collection(Dataset.CRLITE) != null
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
            )
        }
    }
}
