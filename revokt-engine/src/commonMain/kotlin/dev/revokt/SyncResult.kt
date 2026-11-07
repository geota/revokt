// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.jvm.Transient

/**
 * How one sync ended (spec §4): what it installed, where it stopped and why, without parsing a message. An output type:
 * a value with a private constructor and a `@RevoktTestingApi` builder; equality is by content except [cause], and
 * `ByteArray` getters return fresh copies. The builder checks that the `BLOCKED_BY_SELF` fields are set only on a
 * [SyncOutcome.BLOCKED_BY_SELF] result (§8), which nothing produces before 0.3.
 */
@OptIn(RevoktTestingApi::class)
public class SyncResult private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).
    public val outcome: SyncOutcome = requireNotNull(builder.outcome) { "outcome is not set" }

    public val atMillis: Long = requireNotNull(builder.atMillis) { "atMillis is not set" }

    /** The datasets this sync installed, each with the id of the generation it installed. */
    public val installed: Map<Dataset, String> = builder.installed

    /** The source the outcome is about; null when no one source is (a `FETCHER_TRUST` failure, for example). */
    public val sourceId: String? = builder.sourceId

    /** Where a `FAILED`, `STORE_FAILED` or `CLOCK_SKEW` sync stopped. */
    public val stage: SyncStage? = builder.stage

    /** The last response status, when a fetch was involved. */
    public val httpStatus: Int? = builder.httpStatus

    /** The fetcher's or the loader's throwable. Not part of equality, and null after deserialisation. */
    @Transient
    public val cause: Throwable? = builder.cause

    /** On a [SyncOutcome.BLOCKED_BY_SELF] result, which source is blocked. */
    public val blockedSource: String? = builder.blockedSource

    private val blockedChain: ByteString? = builder.blockedChainSha256

    private val blockedSerial: ByteString? = builder.blockedLeafSerial

    /** The sync-time diagnostics: matched on code, never on message. */
    public val warnings: List<PolicyDiagnostic> = builder.warnings

    init {
        require(
            outcome == SyncOutcome.BLOCKED_BY_SELF ||
                (blockedSource == null && blockedChain == null && blockedSerial == null),
        ) { "the blocked fields are set only on a BLOCKED_BY_SELF result (spec §4, §8): got outcome=$outcome" }
    }

    /**
     * On a [SyncOutcome.BLOCKED_BY_SELF] result, the SHA-256 of the blocked host chain, to compare with the host's
     * current chain (§8). A fresh copy.
     */
    public val blockedChainSha256: ByteArray? get() = blockedChain?.toByteArray()

    /** On a [SyncOutcome.BLOCKED_BY_SELF] result, the blocked leaf's raw serial. A fresh copy. */
    public val blockedLeafSerial: ByteArray? get() = blockedSerial?.toByteArray()

    /** A builder holding this result's values, [cause] included. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .outcome(outcome)
            .atMillis(atMillis)
            .installed(installed)
            .sourceId(sourceId)
            .stage(stage)
            .httpStatus(httpStatus)
            .cause(cause)
            .blockedSource(blockedSource)
            .blockedChainSha256(blockedChainSha256)
            .blockedLeafSerial(blockedLeafSerial)
            .warnings(warnings)

    /**
     * Every field but [cause], named, in declaration order: equality, hashing and [toString] all read this one list.
     * [cause] is left out because it does not survive deserialisation.
     */
    private fun fields(): List<Pair<String, Any?>> =
        listOf(
            "outcome" to outcome,
            "atMillis" to atMillis,
            "installed" to installed,
            "sourceId" to sourceId,
            "stage" to stage,
            "httpStatus" to httpStatus,
            "blockedSource" to blockedSource,
            "blockedChainSha256" to blockedChain,
            "blockedLeafSerial" to blockedSerial,
            "warnings" to warnings,
        )

    override fun equals(other: Any?): Boolean = other is SyncResult && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    override fun toString(): String =
        fields().joinToString(prefix = "SyncResult(", postfix = ")") { (name, value) ->
            "$name=${if (value is ByteString) value.hex() else value}"
        }

    /** Builds a [SyncResult] for tests and fakes; [build] checks the invariant the constructor does. */
    @RevoktTestingApi
    @Suppress("TooManyFunctions") // One setter per spec §4 field, plus build().
    public class Builder {
        internal var outcome: SyncOutcome? = null
            private set
        internal var atMillis: Long? = null
            private set
        internal var installed: Map<Dataset, String> = emptyMap()
            private set
        internal var sourceId: String? = null
            private set
        internal var stage: SyncStage? = null
            private set
        internal var httpStatus: Int? = null
            private set
        internal var cause: Throwable? = null
            private set
        internal var blockedSource: String? = null
            private set
        internal var blockedChainSha256: ByteString? = null
            private set
        internal var blockedLeafSerial: ByteString? = null
            private set
        internal var warnings: List<PolicyDiagnostic> = emptyList()
            private set

        public fun outcome(outcome: SyncOutcome): Builder = apply { this.outcome = outcome }

        public fun atMillis(atMillis: Long): Builder = apply { this.atMillis = atMillis }

        /** Replaces the installed generations with a copy of [installed]. */
        public fun installed(installed: Map<Dataset, String>): Builder = apply { this.installed = installed.toMap() }

        public fun sourceId(sourceId: String?): Builder = apply { this.sourceId = sourceId }

        public fun stage(stage: SyncStage?): Builder = apply { this.stage = stage }

        public fun httpStatus(status: Int?): Builder = apply { httpStatus = status }

        public fun cause(cause: Throwable?): Builder = apply { this.cause = cause }

        public fun blockedSource(sourceId: String?): Builder = apply { blockedSource = sourceId }

        public fun blockedChainSha256(sha256: ByteArray?): Builder =
            apply { blockedChainSha256 = sha256?.toByteString() }

        public fun blockedLeafSerial(serial: ByteArray?): Builder = apply { blockedLeafSerial = serial?.toByteString() }

        /** Replaces the warnings with a copy of [warnings]. */
        public fun warnings(warnings: List<PolicyDiagnostic>): Builder = apply { this.warnings = warnings.toList() }

        public fun build(): SyncResult = SyncResult(this)
    }
}
