// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.CrliteChannel
import dev.revokt.Enforcement
import dev.revokt.Evaluator
import dev.revokt.HttpFetcher
import dev.revokt.LogLevel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.Outcome
import dev.revokt.PlatformTrust
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLifecycle
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktLoggers
import dev.revokt.RevoktPolicy
import dev.revokt.RevoktStorage
import dev.revokt.Rule
import dev.revokt.SeedSource
import dev.revokt.Severity
import dev.revokt.SignatureVerifier
import dev.revokt.engine.walker.IndexedSnapshot
import dev.revokt.verify.JcaSignatureVerifier
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * The JVM facade (spec §4): one configured revokt instance. Built by [builder] in Java, or by `Revokt { }` in Kotlin,
 * whose block, `sources { }`, `limits { }` and assignment-style properties are `@JvmSynthetic` sugar over the same
 * [Builder]. Final, with no public constructor.
 *
 * [Builder.build] runs the spec §4 R checks and throws [IllegalArgumentException] on the first that fails;
 * [validate] returns the V diagnostics for an enforcement. The lifecycle is `CREATED → STARTED → CLOSED` (spec §5.1):
 * [start] loads the data and [close] releases it, both idempotent; [evaluator] evaluates in `STARTED`.
 */
public class Revokt private constructor(
    internal val config: RevoktConfig,
) : AutoCloseable {
    private val runtime = config.runtime

    /** Serialises [start]'s synchronous part and [close]'s flip (spec §5.1; the 0.3 factory lock replaces it). */
    private val lock = Any()

    @Volatile
    private var lifecycle: RevoktLifecycle = RevoktLifecycle.CREATED

    /** The anchor snapshot and its index, published by [start]; null before, after [close], or when none could be built. */
    @Volatile
    private var indexed: IndexedSnapshot? = null

    /** The thread running [start]'s seed steps, so a call back into [start] or [close] from it throws. */
    @Volatile
    private var startThread: Thread? = null

    /** The loader (spec §5.1): one daemon thread, created by [start], which also runs the sync schedule; guarded by [lock]. */
    private var loader: ScheduledExecutorService? = null

    @Volatile
    private var loaderThread: Thread? = null

    /** Counted down when the start task ends, or by [close]: what [start]'s join waits on. Guarded by [lock]. */
    private var startTaskDone: CountDownLatch? = null

    /** The thread running [close], and the latch it counts down when done, so a second [close] waits for the first. */
    @Volatile
    private var closing: Thread? = null
    private val closed = CountDownLatch(1)

    /**
     * Evaluates outside any trust manager (spec §4 `revokt.evaluator`) over the anchor index [start] built and the
     * published generation. Available in every state; `evaluate` throws [IllegalStateException] outside `STARTED`, and in
     * `STARTED` while no anchor index exists (a default trust store that is empty, throws, or holds no anchor revokt
     * parses: §11's 0.2 row).
     */
    public val evaluator: Evaluator =
        runtime.evaluator({ lifecycle }, { indexed }, config.pathBuilder, ::nowMillis)

    /**
     * Starts the instance (spec §4, §5.1 "Lifecycle"), synchronously: call it off the main thread. In order, under one
     * lock:
     * 1. `validate(enforcement)`: an `ERROR` throws [IllegalStateException], as [validateOrThrow] does;
     * 2. the anchor snapshot over the default trust manager and its index; when it cannot be built `start()` goes on with
     *    none, and [evaluator] throws until one exists (§11's 0.2 row);
     * 3. the store (§5.1, §6.5): its identity registered, where a second instance on one store in this process throws
     *    [IllegalStateException], its lock taken and held until [close], and `store.version` read; a lock another
     *    process holds, a store that cannot be opened or one of a newer layout runs the instance in memory for the life
     *    of the process, with the warning logged (`STORE_LOCKED`, `STORE_UNREADABLE`, `STORE_NEWER_LAYOUT`);
     * 4. the seed's `seed.json` header: a seed for another channel throws [IllegalStateException]
     *    (`SEED_CHANNEL_MISMATCH`);
     * 5. under `ENFORCE` with `NO_DATA` rejecting, where the seed is the only local data source, the seed's whole load
     *    on this thread: a seed that is absent, unreadable, or does not install throws [IllegalStateException]
     *    (`SEED_UNREADABLE`) instead of every handshake being rejected;
     * 6. the flip to `STARTED`, and one task on the loader thread `revokt-loader-<n>`: the seed's load unless step 5 ran
     *    it, then, with a fetching source, the first sync, then the data's `pending` cleared. The loader then syncs on
     *    its schedule (spec §5.1, §7.1, #147): 6 h plus a jitter of up to 36 min after a poll that did not fail, the
     *    source's backoff after one that did, every wait between 60 s and 24 h.
     *
     * A `start()` that throws leaves the instance `CREATED`, holding nothing, and may be called again; one that throws
     * after its loader started (only an `Error` can) leaves the store to the loader, and [close] releases it. Then `start()`
     * waits for that task up to `awaitData` (a bounded wait on the task, not a readiness future: §11's 0.2 row has none)
     * and returns the start diagnostics: `validate()`'s `WARNING`s, then the S diagnostics of §4
     * (`SEED_PAST_REJECT_THRESHOLD` once the seed is live, `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP`,
     * `RULE_FLIPPED_THIS_MINOR`). Runtime warnings (`SEED_UNREADABLE` where it does not throw) are logged; they reach a
     * public value with the 0.3 `state`.
     *
     * Idempotent: in `STARTED` it returns the diagnostics at once, without waiting. After [close] it throws
     * [IllegalStateException]; one whose wait sees [close] returns normally. Called from the thread of step 5 (an
     * engine, a seed source or a verifier calling back) it throws [IllegalStateException].
     */
    public fun start(): List<PolicyDiagnostic> {
        checkNotFromStart()
        val done: CountDownLatch
        val flipped: TimeMark
        synchronized(lock) {
            when (lifecycle) {
                RevoktLifecycle.CLOSED -> error("closed: start() after close() (spec §5.1)")
                RevoktLifecycle.STARTED -> return startDiagnostics()
                RevoktLifecycle.CREATED -> Unit
            }
            // Every step below may call consumer code (the logger, the trust store, the seed source, the engine), and
            // the lock is re-entrant: a call back into start() or close() from this thread throws instead.
            startThread = Thread.currentThread()
            // Once the loader runs it owns the store: only close(), after stopping the loader, releases it (spec §5.1).
            var loaderOwnsStore = false
            try {
                validateOrThrow(config.enforcement)
                val index = runtime.anchorIndex(config.platformTrust, config.defaultDelegate, nowMillis())
                // The registry, the store lock and store.version (spec §5.1); released below if start() throws after.
                runtime.openStore()
                val loadSeed = runtime.startSeed(soleSeed(), nowMillis())
                done = CountDownLatch(1)
                val executor = newLoader()
                try {
                    executor.execute {
                        var next: Long? = null
                        try {
                            next = runtime.startTask(loadSeed, ::nowMillis)
                        } catch (e: VirtualMachineError) {
                            // The loader's task swallows what it throws: this line is the error's only trace.
                            runtime.log(LogLevel.ERROR, "the start task threw a fatal error, rethrown", e)
                            throw e
                        } finally {
                            // Rescheduled before a fatal error propagates, so the schedule never stops (#147, §6.5).
                            done.countDown()
                            if (runtime.polls) reschedule(executor, next)
                        }
                    }
                } catch (
                    // A loader that cannot start (no thread): start() throws, the instance stays CREATED. Under the
                    // sole-seed path the engine already holds the seed then, and the stored seed generation: a retry
                    // finds it live (storedLive), keeps serving it, and its start task skips the chain.
                    @Suppress("TooGenericExceptionCaught") t: Throwable,
                ) {
                    // A worker the refused execute started must be gone before the store is released below.
                    executor.shutdownNow()
                    awaitUninterruptibly { executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS) }
                    throw t
                }
                // First, so that close() stops this loader whatever throws below.
                loader = executor
                loaderOwnsStore = true
                indexed = index
                startTaskDone = done
                lifecycle = RevoktLifecycle.STARTED
                flipped = config.timeSource.markNow()
            } finally {
                // A start() that throws before its loader runs holds nothing: the store's lock released and its
                // identity deregistered. After, the loader may be writing, so close() releases it once it has stopped.
                if (!loaderOwnsStore) releaseStore()
                startThread = null
            }
        }
        join(done, flipped)
        return startDiagnostics()
    }

    /**
     * Closes the instance (spec §5.1 `close()`); it blocks. Idempotent: a second `close()` returns once the first has
     * finished. In order: the flip to `CLOSED` (under the start lock, so a `close()` racing [start] waits for its
     * synchronous part); the loader cancelled, and an in-flight install and the loader thread's exit awaited, without a
     * deadline, so the engine is never closed while it prepares or activates a generation and no loader thread outlives
     * `close()`; the store's lock released and its identity deregistered; the generation reference cleared; then
     * `engine.close()`,
     * always, last, in `CREATED` too (`Revokt` owns the engine). A throw from `engine.close()` is rethrown once every
     * other step has run, so an engine that did not close is never hidden (`try`-with-resources and `use {}` attach it
     * as suppressed when their body threw); a second `close()` is then a no-op. Throws [IllegalStateException] on the
     * loader thread and from [start]'s own thread, before doing anything.
     */
    override fun close() {
        val current = Thread.currentThread()
        check(current !== loaderThread) { "close() on the revokt loader thread, which it would wait for (spec §5.1)" }
        checkNotFromStart()
        val executor: ScheduledExecutorService?
        val first: Boolean
        synchronized(lock) {
            first = lifecycle != RevoktLifecycle.CLOSED
            if (first) {
                lifecycle = RevoktLifecycle.CLOSED
                closing = current
            }
            executor = loader
            loader = null
            if (first) startTaskDone?.countDown()
        }
        if (!first) {
            // The closing thread itself (an engine's close() calling back) returns at once: it cannot wait for itself.
            if (current !== closing) awaitUninterruptibly { closed.await() }
            return
        }
        var failure: Throwable? = null
        try {
            executor?.let(::stop)
            // Once the loader has stopped, so nothing writes after (spec §5.1 close()): then the reference is cleared.
            try {
                runtime.closeStore()
            } finally {
                runtime.clear()
                indexed = null
            }
        } catch (
            // Rethrown below, after engine.close(), which always runs; with engine.close()'s own throw suppressed in it.
            @Suppress("TooGenericExceptionCaught") t: Throwable,
        ) {
            failure = t
        }
        try {
            runtime.closeEngine()
        } catch (
            @Suppress("TooGenericExceptionCaught") t: Throwable,
        ) {
            failure?.addSuppressed(t) ?: run { failure = t }
        } finally {
            closed.countDown()
        }
        failure?.let { throw it }
    }

    /**
     * The V diagnostics of spec §4 for [enforcement]: the configuration's, then the policy's, then the I/O
     * dispatcher's. An `ERROR` is possible only under [Enforcement.ENFORCE]; under [Enforcement.OFF] every diagnostic is a
     * `WARNING`. Tests and consumers match on the code, never on the message.
     */
    public fun validate(enforcement: Enforcement): List<PolicyDiagnostic> = validateConfiguration(config, enforcement)

    /**
     * [validate], throwing [IllegalStateException] when any diagnostic is an `ERROR`, with every `ERROR` in the message;
     * `WARNING`s alone return normally.
     */
    public fun validateOrThrow(enforcement: Enforcement) {
        val errors = validate(enforcement).filter { it.severity == Severity.ERROR }
        check(errors.isEmpty()) {
            "the configuration is invalid under $enforcement: " +
                errors.joinToString("; ") { "${it.code}: ${it.message}" }
        }
    }

    /** `validate()`'s `WARNING`s for the configured enforcement, then the S diagnostics (spec §4). */
    private fun startDiagnostics(): List<PolicyDiagnostic> =
        validate(config.enforcement).filter { it.severity == Severity.WARNING } + runtime.diagnostics(nowMillis())

    /**
     * The store's lock released and its identity deregistered after a `start()` that threw (spec §5.1: it holds
     * nothing); a release that throws is logged, so the start's own throwable is the one that propagates.
     */
    private fun releaseStore() {
        try {
            runtime.closeStore()
        } catch (
            @Suppress("TooGenericExceptionCaught") e: Exception,
        ) {
            runtime.log(LogLevel.WARN, "releasing the store after a failed start() threw", e)
        }
    }

    /**
     * The sole-seed `ENFORCE` configuration (spec §4 S bullet): `ENFORCE`, `NO_DATA` rejecting, and a seed, which in 0.2
     * is always the only local data source (the store is in memory, fresh at every build).
     */
    private fun soleSeed(): Boolean =
        config.enforcement == Enforcement.ENFORCE &&
            config.policy.outcome(Rule.NO_DATA) == Outcome.REJECT &&
            config.seed != null

    /** [start]'s wait for the start task: up to `awaitData` from the flip, measured on the configured time source. */
    private fun join(
        done: CountDownLatch,
        flipped: TimeMark,
    ) {
        val remaining = config.awaitDataMillis - flipped.elapsedNow().inWholeMilliseconds
        if (remaining <= 0) return
        try {
            done.await(remaining, TimeUnit.MILLISECONDS)
        } catch (
            // The caller asked to stop waiting: start() returns, STARTED, with its interrupt kept.
            @Suppress("SwallowedException") e: InterruptedException,
        ) {
            Thread.currentThread().interrupt()
        }
    }

    /**
     * The next sync on [executor], at [atMillis] (a wall-clock time the runtime returned; null after a sync step that
     * threw, which retries in 15 min), as a delay clamped to 60 s to 24 h and waited on the loader's monotonic timer
     * ([PollTimer]). Nothing is scheduled after [close]: its flip is read here, and a timer it has already shut down
     * refuses the task, which is dropped. A clock that throws here retries in 15 min too; a fatal error from it is
     * rethrown once the next sync is scheduled.
     */
    private fun reschedule(
        executor: ScheduledExecutorService,
        atMillis: Long?,
    ) {
        if (lifecycle == RevoktLifecycle.CLOSED) return
        var fatal: Throwable? = null
        // A consumer clock that throws: retry in 15 min, as after a sync that threw.
        val retry = runtime.delayMillis(runtime.retryAtMillis(0), 0)
        val delay =
            try {
                val now = nowMillis()
                runtime.delayMillis(atMillis ?: runtime.retryAtMillis(now), now)
            } catch (e: VirtualMachineError) {
                fatal = e
                retry
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                runtime.log(LogLevel.ERROR, "the clock was interrupted", e)
                retry
            } catch (
                @Suppress("TooGenericExceptionCaught") t: Throwable,
            ) {
                runtime.log(LogLevel.ERROR, "the clock threw", t)
                retry
            }
        try {
            config.pollTimer.schedule(executor, delay) { sync(executor) }
        } catch (
            // close() shut the loader down after the flip was read: nothing runs after close() (spec §5.1).
            @Suppress("SwallowedException") e: RejectedExecutionException,
        ) {
            // Dropped.
        }
        fatal?.let { throw it }
    }

    /**
     * One scheduled sync on the loader (spec §5.1, #147), then the next one scheduled, in a `finally`, so that a fatal
     * error, which the runtime rethrows, never ends the schedule; the runtime restores an interrupt it absorbed. A clock
     * that throws before the sync is a logged failure, retried in 15 min; a fatal error is logged and rethrown.
     */
    private fun sync(executor: ScheduledExecutorService) {
        var next: Long? = null
        try {
            next = runtime.sync(nowMillis())
        } catch (e: VirtualMachineError) {
            // The loader's task swallows what it throws: this line is the error's only trace.
            runtime.log(LogLevel.ERROR, "the sync task threw a fatal error, rethrown", e)
            throw e
        } catch (e: InterruptedException) {
            // A consumer clock's: logged, the interrupt restored, retried in 15 min.
            Thread.currentThread().interrupt()
            runtime.log(LogLevel.ERROR, "the clock was interrupted before the sync", e)
        } catch (
            // A consumer clock that throws: logged and retried in 15 min (the runtime catches the sync's own).
            @Suppress("TooGenericExceptionCaught") t: Throwable,
        ) {
            runtime.log(LogLevel.ERROR, "the clock threw before the sync", t)
        } finally {
            reschedule(executor, next)
        }
    }

    /**
     * Cancels [executor] and waits for it, uninterruptibly: an in-flight install ends before the engine closes. Then
     * waits for the loader thread to exit, which a pool that has terminated has signalled before its worker leaves, so
     * no loader thread outlives [close] (spec §5.1).
     */
    private fun stop(executor: ScheduledExecutorService) {
        executor.shutdownNow()
        awaitUninterruptibly { executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS) }
        loaderThread?.let { thread -> awaitUninterruptibly { thread.join() } }
    }

    /**
     * The loader: one daemon thread `revokt-loader-<build sequence>` (spec §5.1), started by its first task, which also
     * waits the schedule's delays. A cancelled sync leaves its queue, and `shutdownNow()` drops the queued one.
     */
    private fun newLoader(): ScheduledExecutorService =
        ScheduledThreadPoolExecutor(1) { task ->
            Thread(task, "revokt-loader-${config.sequence}").also {
                it.isDaemon = true
                loaderThread = it
            }
        }.apply {
            removeOnCancelPolicy = true
            executeExistingDelayedTasksAfterShutdownPolicy = false
            continueExistingPeriodicTasksAfterShutdownPolicy = false
        }

    private fun checkNotFromStart() {
        check(Thread.currentThread() !== startThread) { "re-entrant start()/close() from the start() thread" }
    }

    private fun nowMillis(): Long = config.clock.now().toEpochMilliseconds()

    override fun toString(): String =
        "Revokt(channel=${config.channel}, enforcement=${config.enforcement}, engine=${config.engineName})"

    public companion object {
        /** A builder with every default of spec §4. */
        @JvmStatic
        public fun builder(): Builder = Builder()
    }

    /**
     * The configuration surface of spec §4. Every method returns this builder; arguments are checked when [build] runs,
     * except a negative duration, which throws [IllegalArgumentException] at once.
     *
     * Defaults: no channel, no fetching source (a library never opens the network unasked), the seed
     * `SeedSource.bundled()` resolved for the channel at [build], `JcaSignatureVerifier()`, the Kotlin revocation
     * engine, `Clock.System`, `RevoktLoggers.jul()`, [RevoktPolicy.DEFAULT], [Enforcement.ENFORCE], a 2 s readiness
     * deadline (spec §5.1: fixed on the JVM), `Dispatchers.IO`, the `RevoktLimits` caps, `JdkHttpFetcher()` and the PKIX
     * fallback enabled. The store is `RevoktStorage.inMemory()`.
     */
    @Suppress("TooManyFunctions") // One method per spec §4 builder member.
    public class Builder internal constructor() {
        /** The CRLite channel (spec §4, §7.2); mandatory whenever a CRLite source, a seed included, is configured. */
        @get:JvmSynthetic @set:JvmSynthetic
        public var channel: CrliteChannel? = null

        internal var remoteSettings: MozillaRemoteSettings? = null
            private set

        /** The configured seed; null means the default, `SeedSource.bundled()`, created at [build]. */
        internal var seed: SeedSource? = null
            private set

        private var verifier: SignatureVerifier? = null

        /** Verifies certificate signatures; default `JcaSignatureVerifier()`, created at the first read or at [build]. */
        @get:JvmSynthetic @set:JvmSynthetic
        public var signatureVerifier: SignatureVerifier
            get() = verifier ?: JcaSignatureVerifier().also { verifier = it }
            set(value) {
                verifier = value
            }

        /** The injected engine (spec §3.2 "Seam"); null means a fresh Kotlin engine at each [build]. */
        @RevoktInternalApi
        @get:JvmSynthetic
        @set:JvmSynthetic
        public var revocationEngine: RevocationEngine? = null

        /** The wall clock: staleness, the sync schedule and `nowMillis` when a request has none. */
        @get:JvmSynthetic @set:JvmSynthetic
        public var clock: Clock = Clock.System

        /** The monotonic source for deadlines; internal, a test seam. */
        internal var timeSource: TimeSource = TimeSource.Monotonic

        /** Where the loader waits for its next sync (#147): the loader's own timer; internal, a test seam. */
        internal var pollTimer: PollTimer = PollTimer.LOADER

        /** The sync schedule's jitter source (#147); internal, a test seam. */
        internal var random: Random = Random.Default

        /**
         * The store (spec §3, §6.5); null means a fresh `RevoktStorage.inMemory()` at [build]. Internal, a test seam: the
         * §4 `storage(…)` member comes with `JvmStorage.directory(…)` (#340).
         */
        internal var storage: RevoktStorage? = null

        /** The platform trust (spec §3, §5.3): `JvmPlatformTrust()`; internal, a test seam (the §4 member is [0.3]). */
        internal var platformTrust: PlatformTrust = JvmPlatformTrust()

        @get:JvmSynthetic @set:JvmSynthetic
        public var logger: RevoktLogger = RevoktLoggers.jul()

        @get:JvmSynthetic @set:JvmSynthetic
        public var policy: RevoktPolicy = RevoktPolicy.DEFAULT

        @get:JvmSynthetic @set:JvmSynthetic
        public var enforcement: Enforcement = Enforcement.ENFORCE

        internal var awaitDataMillis: Long = AWAIT_DATA_MILLIS
            private set

        /**
         * Where fetches run (spec §4). It must not run tasks inline: an inline dispatcher runs each fetch on the loader
         * thread, before the per-fetch timeout can apply, and `validate()` warns for `Dispatchers.Unconfined`.
         */
        @get:JvmSynthetic @set:JvmSynthetic
        @Suppress("InjectDispatcher") // The builder is the injection point; Dispatchers.IO is §4's default.
        public var ioDispatcher: CoroutineDispatcher = Dispatchers.IO

        /** The transport every fetching source fetches through (spec §3 `HttpFetcher`); default `JdkHttpFetcher()`. */
        @get:JvmSynthetic @set:JvmSynthetic
        public var http: HttpFetcher = JdkHttpFetcher()

        internal var maxFilterBytes: Long = RevoktLimits.MAX_FILTER_BYTES
            private set
        internal var maxJsonBytes: Long = RevoktLimits.MAX_JSON_BYTES
            private set
        internal var maxX5uBytes: Long = RevoktLimits.MAX_X5U_BYTES
            private set
        internal var maxChangesetRecords: Int = RevoktLimits.MAX_CHANGESET_RECORDS
            private set

        internal var pkixFallback: Boolean = true
            private set

        public fun channel(c: CrliteChannel): Builder = apply { channel = c }

        /**
         * The Mozilla Remote Settings source (spec §4, §7.1), the fetching source; replaces an earlier one. Its
         * `baseUrl` and a pinned `attachmentBaseUrl` are checked at [build].
         */
        public fun remoteSettings(source: MozillaRemoteSettings): Builder = apply { remoteSettings = source }

        /** The seed (spec §6.5), the local data source; replaces an earlier one. `SeedSource.none()` opts out. */
        public fun seed(source: SeedSource): Builder = apply { seed = source }

        public fun signatureVerifier(verifier: SignatureVerifier): Builder = apply { signatureVerifier = verifier }

        /**
         * Injects the revocation engine (spec §3.2 "Seam"), which the built `Revokt` then owns and closes. An instance
         * goes into one `Revokt` only: a second [build] with it throws.
         */
        @RevoktInternalApi
        public fun revocationEngine(engine: RevocationEngine): Builder = apply { revocationEngine = engine }

        /** The wall clock, from a `java.time.Clock` (Kotlin: the `clock` property, a `kotlin.time.Clock`). */
        public fun clock(clock: java.time.Clock): Builder = apply { this.clock = JavaClock(clock) }

        public fun logger(logger: RevoktLogger): Builder = apply { this.logger = logger }

        public fun policy(policy: RevoktPolicy): Builder = apply { this.policy = policy }

        public fun enforcement(enforcement: Enforcement): Builder = apply { this.enforcement = enforcement }

        /**
         * How long `start()` waits for the first data (spec §4, §5.1), a deadline; default 2 s on the JVM. Kept in
         * whole milliseconds, truncated toward zero. Throws [IllegalArgumentException] for any negative duration, a
         * sub-millisecond one included, and for one beyond `Long` milliseconds; the Kotlin `kotlin.time.Duration` form
         * takes the same rule, so `Duration.INFINITE` throws too.
         */
        public fun awaitData(d: java.time.Duration): Builder {
            require(!d.isNegative) { "awaitData is non-negative, got $d" }
            return awaitDataMillis(
                try {
                    d.toMillis()
                } catch (
                    // The message says why; the ArithmeticException adds nothing.
                    @Suppress("SwallowedException") e: ArithmeticException,
                ) {
                    throw IllegalArgumentException("awaitData does not fit in Long milliseconds: $d")
                },
            )
        }

        /** [awaitData] in milliseconds; a negative value throws [IllegalArgumentException]. */
        public fun awaitDataMillis(millis: Long): Builder =
            apply {
                require(millis >= 0) { "awaitData is non-negative, got $millis ms" }
                awaitDataMillis = millis
            }

        /** Where fetches run, from an `Executor` (Kotlin: the `ioDispatcher` property); it must not run tasks inline. */
        public fun ioExecutor(executor: Executor): Builder = apply { ioDispatcher = executor.asCoroutineDispatcher() }

        public fun http(fetcher: HttpFetcher): Builder = apply { http = fetcher }

        /** The filter download cap, raisable only: [build] throws below `RevoktLimits.MAX_FILTER_BYTES`. */
        public fun maxFilterBytes(bytes: Long): Builder = apply { maxFilterBytes = bytes }

        /** The JSON body cap, raisable only: [build] throws below `RevoktLimits.MAX_JSON_BYTES`. */
        public fun maxJsonBytes(bytes: Long): Builder = apply { maxJsonBytes = bytes }

        /** The x5u chain cap, raisable only: [build] throws below `RevoktLimits.MAX_X5U_BYTES`. */
        public fun maxX5uBytes(bytes: Long): Builder = apply { maxX5uBytes = bytes }

        /** The changeset record cap, raisable only: [build] throws below `RevoktLimits.MAX_CHANGESET_RECORDS`. */
        public fun maxChangesetRecords(records: Int): Builder = apply { maxChangesetRecords = records }

        /**
         * Whether the PKIX fallback runs when the walker finds no path (spec §5.1 decision step 6); default true. The
         * fallback is load-bearing where `NO_ISSUER` allows, as under [RevoktPolicy.DEFAULT]: [build] throws when it is
         * disabled and the policy's `NO_ISSUER` outcome is `ALLOW`.
         */
        public fun pkixFallback(enabled: Boolean): Builder = apply { pkixFallback = enabled }

        /** Configures the sources (Kotlin DSL; Java: [remoteSettings] and [seed]). */
        @JvmSynthetic
        public fun sources(block: Sources.() -> Unit): Builder = apply { Sources(this).block() }

        /** Raises the download and record caps (Kotlin DSL; Java: [maxFilterBytes] and the other cap methods). */
        @JvmSynthetic
        public fun limits(block: Limits.() -> Unit): Builder = apply { Limits(this).block() }

        /**
         * Runs the spec §4 R checks, then builds the `Revokt`. Throws [IllegalArgumentException], naming the rule, when:
         * - a CRLite source (a seed counts, the default `SeedSource.bundled()` included) is configured with no channel
         *   (`CHANNEL_UNSET`);
         * - the Remote Settings `baseUrl`, or a pinned `attachmentBaseUrl`, is not an `https` URL with a host, no
         *   userinfo, no query or fragment, and a port from 1 to 65535 or none: what the default fetch path accepts;
         * - a download or record cap is below its `RevoktLimits` constant;
         * - the PKIX fallback is disabled while the policy's `NO_ISSUER` outcome is `ALLOW`;
         * - the injected revocation engine already went into another `Revokt`.
         *
         * A [build] that throws leaves an injected engine with the caller. Each [build] without an injected engine
         * creates a fresh one.
         */
        public fun build(): Revokt = Revokt(RevoktConfig(this))
    }

    /** The `sources { }` scope (spec §4): each call sets the builder's source of that kind, replacing an earlier one. */
    public class Sources internal constructor(
        private val builder: Builder,
    ) {
        @JvmSynthetic
        public fun remoteSettings(source: MozillaRemoteSettings) {
            builder.remoteSettings(source)
        }

        @JvmSynthetic
        public fun seed(source: SeedSource) {
            builder.seed(source)
        }
    }

    /** The `limits { }` scope (spec §4): the download and record caps, each raisable only. */
    public class Limits internal constructor(
        private val builder: Builder,
    ) {
        @get:JvmSynthetic @set:JvmSynthetic
        public var maxFilterBytes: Long
            get() = builder.maxFilterBytes
            set(value) {
                builder.maxFilterBytes(value)
            }

        @get:JvmSynthetic @set:JvmSynthetic
        public var maxJsonBytes: Long
            get() = builder.maxJsonBytes
            set(value) {
                builder.maxJsonBytes(value)
            }

        @get:JvmSynthetic @set:JvmSynthetic
        public var maxX5uBytes: Long
            get() = builder.maxX5uBytes
            set(value) {
                builder.maxX5uBytes(value)
            }

        @get:JvmSynthetic @set:JvmSynthetic
        public var maxChangesetRecords: Int
            get() = builder.maxChangesetRecords
            set(value) {
                builder.maxChangesetRecords(value)
            }
    }
}

/** Spec §5.1 limits table: `AWAIT_DATA_<CHANNEL>` is a fixed 2 s on the JVM (measured on Android, 0.3). */
internal const val AWAIT_DATA_MILLIS: Long = 2_000L

/**
 * Runs [wait] until it returns without being interrupted, then restores the interrupt it absorbed: [Revokt.close] keeps
 * its order whatever the caller's thread is told.
 */
private inline fun awaitUninterruptibly(wait: () -> Any?) {
    var interrupted = false
    while (true) {
        try {
            wait()
            break
        } catch (
            // Kept: restored below, once the wait is over.
            @Suppress("SwallowedException") e: InterruptedException,
        ) {
            interrupted = true
        }
    }
    if (interrupted) Thread.currentThread().interrupt()
}

/**
 * Where the loader waits for its next sync (spec §5.1, #147): [schedule] runs [task] on [loader] after [delayMillis].
 * [LOADER] is the loader's monotonic timer; a test's timer records the delays and runs the task when it chooses. A
 * timer whose loader is shut down throws `RejectedExecutionException`.
 */
internal fun interface PollTimer {
    fun schedule(
        loader: ScheduledExecutorService,
        delayMillis: Long,
        task: Runnable,
    )

    companion object {
        val LOADER = PollTimer { loader, delay, task -> loader.schedule(task, delay, TimeUnit.MILLISECONDS) }
    }
}

/** A `java.time.Clock` as a `kotlin.time.Clock`, at millisecond precision. */
internal class JavaClock(
    val clock: java.time.Clock,
) : Clock {
    override fun now(): Instant = Instant.fromEpochMilliseconds(clock.millis())
}
