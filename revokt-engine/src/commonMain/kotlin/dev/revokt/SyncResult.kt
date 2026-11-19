// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.jvm.Transient

/**
 * How one sync ended (spec §4): what it installed, where it stopped and why, without parsing a message. An output type:
 * a value with a private constructor and a `@RevoktTestingApi` builder; equality is by content except [cause].
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

    /** The source the outcome is about; null when no one source is. */
    public val sourceId: String? = builder.sourceId

    /**
     * Where a `FAILED`, `STORE_FAILED` or `CLOCK_SKEW` sync stopped. A 401 or 407 carries the stage of the fetch it
     * interrupted: `CHANGESET`, `X5U` or `ATTACHMENT` (§3).
     */
    public val stage: SyncStage? = builder.stage

    /** The last response status, when a fetch was involved. */
    public val httpStatus: Int? = builder.httpStatus

    /** The fetcher's or the loader's throwable. Not part of equality, and null after deserialisation. */
    @Transient
    public val cause: Throwable? = builder.cause

    /** The sync-time diagnostics: matched on code, never on message. */
    public val warnings: List<PolicyDiagnostic> = builder.warnings

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
            "warnings" to warnings,
        )

    override fun equals(other: Any?): Boolean = other is SyncResult && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    override fun toString(): String =
        fields().joinToString(prefix = "SyncResult(", postfix = ")") { (name, value) -> "$name=$value" }

    /** Builds a [SyncResult] for tests and fakes. */
    @RevoktTestingApi
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
        internal var warnings: List<PolicyDiagnostic> = emptyList()
            private set

        public fun outcome(outcome: SyncOutcome): Builder = apply { this.outcome = outcome }

        public fun atMillis(atMillis: Long): Builder = apply { this.atMillis = atMillis }

        /** Replaces the installed generations with a read-only copy of [installed]. */
        public fun installed(installed: Map<Dataset, String>): Builder =
            apply {
                this.installed =
                    buildMap { putAll(installed) }
            }

        public fun sourceId(sourceId: String?): Builder = apply { this.sourceId = sourceId }

        public fun stage(stage: SyncStage?): Builder = apply { this.stage = stage }

        public fun httpStatus(status: Int?): Builder = apply { httpStatus = status }

        public fun cause(cause: Throwable?): Builder = apply { this.cause = cause }

        /** Replaces the warnings with a read-only copy of [warnings]. */
        public fun warnings(warnings: List<PolicyDiagnostic>): Builder =
            apply {
                this.warnings =
                    buildList { addAll(warnings) }
            }

        public fun build(): SyncResult = SyncResult(this)
    }
}
