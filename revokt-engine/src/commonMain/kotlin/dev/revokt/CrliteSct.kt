// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * One SCT as a CRLite query sees it (spec §3.2): the log id and the timestamp. The timestamp is RFC 6962's `u64` carried
 * in a [Long] and compared unsigned. A value type: equality is by content.
 */
@OptIn(RevoktTestingApi::class)
public class CrliteSct private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature.
    private val log: ByteString = requireNotNull(builder.logId) { "logId is not set" }

    public val timestampMillis: Long = requireNotNull(builder.timestampMillis) { "timestampMillis is not set" }

    init {
        require(log.size == LOG_ID_BYTES) { "a log id is $LOG_ID_BYTES bytes, got ${log.size}" }
    }

    /** The CT log id, the SHA-256 of the log's key: 32 bytes, as a fresh copy. */
    public val logId: ByteArray get() = log.toByteArray()

    internal val logIdBytes: ByteString get() = log

    /** A builder holding this SCT's values. */
    @RevoktTestingApi
    public fun newBuilder(): Builder = Builder().logId(log.toByteArray()).timestampMillis(timestampMillis)

    override fun equals(other: Any?): Boolean =
        other is CrliteSct && log == other.log && timestampMillis == other.timestampMillis

    override fun hashCode(): Int = 31 * log.hashCode() + timestampMillis.hashCode()

    override fun toString(): String = "CrliteSct(logId=${log.hex()}, timestampMillis=${timestampMillis.toULong()})"

    /** Builds a [CrliteSct] for tests and fakes. */
    @RevoktTestingApi
    public class Builder {
        internal var logId: ByteString? = null
            private set
        internal var timestampMillis: Long? = null
            private set

        public fun logId(logId: ByteArray): Builder = apply { this.logId = logId.toByteString() }

        public fun timestampMillis(millis: Long): Builder = apply { timestampMillis = millis }

        public fun build(): CrliteSct = CrliteSct(this)
    }

    internal companion object {
        private const val LOG_ID_BYTES = 32

        /** The parser's SCT pair (spec §9.2) as a query SCT. */
        fun of(
            logId: ByteString,
            timestampMillis: Long,
        ): CrliteSct = Builder().logId(logId.toByteArray()).timestampMillis(timestampMillis).build()
    }
}
