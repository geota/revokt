// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse

import dev.revokt.CrliteChannel
import dev.revokt.Enforcement
import dev.revokt.HttpFetcher
import dev.revokt.MozillaRemoteSettings
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktLoggers
import dev.revokt.RevoktPolicy
import dev.revokt.SeedSource
import dev.revokt.Severity
import dev.revokt.SignatureVerifier
import dev.revokt.verify.JcaSignatureVerifier
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import java.util.concurrent.Executor
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.TimeSource

/**
 * The JVM facade (spec §4): one configured revokt instance. Built by [builder] in Java, or by `Revokt { }` in Kotlin,
 * whose block, `sources { }`, `limits { }` and assignment-style properties are `@JvmSynthetic` sugar over the same
 * [Builder]. Final, with no public constructor.
 *
 * [Builder.build] runs the spec §4 R checks and throws [IllegalArgumentException] on the first that fails;
 * [validate] returns the V diagnostics for an enforcement.
 */
public class Revokt private constructor(
    internal val config: RevoktConfig,
) {
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

/** A `java.time.Clock` as a `kotlin.time.Clock`, at millisecond precision. */
internal class JavaClock(
    val clock: java.time.Clock,
) : Clock {
    override fun now(): Instant = Instant.fromEpochMilliseconds(clock.millis())
}
