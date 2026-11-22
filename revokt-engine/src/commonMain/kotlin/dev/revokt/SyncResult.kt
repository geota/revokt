// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.jvm.Transient

/**
 * How one sync ended (spec §4): what it installed, or why it stopped, without parsing a message. An output type: a
 * value with a private constructor and a `@RevoktTestingApi` builder; equality is by content except [cause]. The
 * builder checks that [failure] is set exactly when [outcome] is `SKIPPED` or `FAILED`, and is a code of that outcome.
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
     * Why a `SKIPPED` or `FAILED` sync stopped; null otherwise. A 401 or 407 is the code of the fetch it interrupted:
     * `CHANGESET_FETCH`, `X5U_FETCH` or `ATTACHMENT_FETCH` (§3).
     */
    public val failure: SyncFailure? = builder.failure

    /** The last response status, when a fetch was involved. */
    public val httpStatus: Int? = builder.httpStatus

    /** The fetcher's or the loader's throwable. Not part of equality, and null after deserialisation. */
    @Transient
    public val cause: Throwable? = builder.cause

    /** The sync's runtime warnings, `CAP_NEAR_LIMIT`: matched on code, never on message. */
    public val warnings: List<RevoktWarning> = builder.warnings

    init {
        val stopped = outcome == SyncOutcome.SKIPPED || outcome == SyncOutcome.FAILED
        require((failure != null) == stopped) {
            "failure is set exactly when outcome is SKIPPED or FAILED (spec §4): got outcome=$outcome, failure=$failure"
        }
        require(failure == null || failure.outcome == outcome) { "$failure is not a $outcome code (spec §4)" }
    }

    /** A builder holding this result's values, [cause] included. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .outcome(outcome)
            .atMillis(atMillis)
            .installed(installed)
            .sourceId(sourceId)
            .failure(failure)
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
            "failure" to failure,
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
        internal var failure: SyncFailure? = null
            private set
        internal var httpStatus: Int? = null
            private set
        internal var cause: Throwable? = null
            private set
        internal var warnings: List<RevoktWarning> = emptyList()
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

        public fun failure(failure: SyncFailure?): Builder = apply { this.failure = failure }

        public fun httpStatus(status: Int?): Builder = apply { httpStatus = status }

        public fun cause(cause: Throwable?): Builder = apply { this.cause = cause }

        /** Replaces the warnings with a read-only copy of [warnings]. */
        public fun warnings(warnings: List<RevoktWarning>): Builder =
            apply {
                this.warnings =
                    buildList { addAll(warnings) }
            }

        public fun build(): SyncResult = SyncResult(this)
    }
}
