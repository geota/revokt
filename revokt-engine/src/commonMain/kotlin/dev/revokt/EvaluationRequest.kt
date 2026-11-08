// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * What [Evaluator.evaluate] is asked about (spec §4): a presented chain, which is walked (decision steps 2 to 6), or
 * platform-verified paths, which are trusted without re-verification and skip the walk, or both; plus the host and the
 * evaluation time. Raw DER here is presumed to come from a platform-accepted chain: `PARSE_FAILED` on caller-fabricated
 * bytes is the caller's to police (§9.2), and these bytes get no §9.2 read fallback. A value with a private constructor
 * and a builder; equality is by content, and the DER is copied when it is set.
 */
public class EvaluationRequest private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (M3 adds tlsScts, M5 credentialType).

    /** The presented chain, leaf first, as sent; null when not set. */
    internal val presented: List<ByteString>? = builder.presented

    /** The verified paths, each leaf to anchor; null when not set. */
    internal val verifiedPaths: List<List<ByteString>>? = builder.verifiedPaths

    /** The host as given; the evaluation derives host' from it. */
    internal val host: String? = builder.host

    /** The evaluation time; null when not set, and the evaluator then reads its clock. */
    internal val nowMillis: Long? = builder.nowMillis

    /** Derived: `PLATFORM` when verified paths are given, since they skip the walk; else `RECONSTRUCTED`. */
    internal val chainSource: ChainSource =
        if (verifiedPaths != null) ChainSource.PLATFORM else ChainSource.RECONSTRUCTED

    init {
        require(presented != null || verifiedPaths != null) {
            "at least one of presented and verifiedPaths is set (spec §4)"
        }
    }

    /** A builder holding this request's values. */
    public fun newBuilder(): Builder {
        val builder = Builder().host(host)
        presented?.let { chain -> builder.presented(chain.map { it.toByteArray() }) }
        verifiedPaths?.let { paths -> builder.verifiedPaths(paths.map { path -> path.map { it.toByteArray() } }) }
        nowMillis?.let { builder.nowMillis(it) }
        return builder
    }

    /** Every field, named, in declaration order: equality, hashing and [toString] all read this one list. */
    private fun fields(): List<Pair<String, Any?>> =
        listOf(
            "presented" to presented,
            "verifiedPaths" to verifiedPaths,
            "host" to host,
            "nowMillis" to nowMillis,
        )

    override fun equals(other: Any?): Boolean = other is EvaluationRequest && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    /** Each certificate is shown by the SHA-256 of its DER, so a chain prints in a line. */
    override fun toString(): String =
        "EvaluationRequest(presented=${presented?.let(::digests)}, " +
            "verifiedPaths=${verifiedPaths?.map(::digests)}, host=$host, nowMillis=$nowMillis)"

    /** Builds an [EvaluationRequest]; [build] throws `IllegalArgumentException` unless a chain or a path is set. */
    public class Builder {
        internal var presented: List<ByteString>? = null
            private set
        internal var verifiedPaths: List<List<ByteString>>? = null
            private set
        internal var host: String? = null
            private set
        internal var nowMillis: Long? = null
            private set

        /** The presented chain, leaf first, as sent; walked (decision steps 2 to 6). Copied. */
        public fun presented(chain: List<ByteArray>): Builder = apply { presented = chain.map { it.toByteString() } }

        /**
         * Platform-verified paths, each leaf to anchor, trusted without re-verification: the source is `PLATFORM` and
         * the walk is skipped. Copied.
         */
        public fun verifiedPaths(paths: List<List<ByteArray>>): Builder =
            apply { verifiedPaths = paths.map { path -> path.map { it.toByteString() } } }

        /** The host the chain was presented for, used for host' only; null for none. */
        public fun host(host: String?): Builder = apply { this.host = host }

        public fun nowMillis(nowMillis: Long): Builder = apply { this.nowMillis = nowMillis }

        public fun build(): EvaluationRequest = EvaluationRequest(this)
    }
}

private fun digests(ders: List<ByteString>): List<String> = ders.map { it.sha256().hex() }
