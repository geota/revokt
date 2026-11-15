// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * What [Evaluator.evaluate] is asked about (spec §4): a presented chain, which is walked (decision steps 2 to 6), or
 * one platform-verified path, which is trusted without re-verification and skips the walk, or both, the path then
 * starting with the presented leaf; plus the host and the evaluation time. Raw DER here is presumed to come from a
 * platform-accepted chain: `PARSE_FAILED` on caller-fabricated bytes is the caller's to police (§9.2), and these bytes
 * get no §9.2 read fallback. A value with a private constructor and a builder; equality is by content, and the DER is
 * copied when it is set.
 */
public class EvaluationRequest private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (M3 adds tlsScts, M5 credentialType).

    /** The presented chain, leaf first, as sent; null when not set. */
    internal val presented: List<ByteString>? = builder.presented

    /** The verified path, leaf to anchor; null when not set. */
    internal val verifiedPath: List<ByteString>? = builder.verifiedPath

    /** The host as given; the evaluation derives host' from it. */
    internal val host: String? = builder.host

    /** The evaluation time; null when not set, and the evaluator then reads its clock. */
    internal val nowMillis: Long? = builder.nowMillis

    /** Derived: `PLATFORM` when a verified path is given, since it skips the walk; else `RECONSTRUCTED`. */
    internal val chainSource: ChainSource =
        if (verifiedPath != null) ChainSource.PLATFORM else ChainSource.RECONSTRUCTED

    init {
        require(presented != null || verifiedPath != null) {
            "at least one of presented and verifiedPath is set (spec §4)"
        }
        require(presented == null || presented.isNotEmpty()) { "presented is set but empty: a chain has a leaf" }
        require(verifiedPath == null || verifiedPath.isNotEmpty()) {
            "verifiedPath is set but empty: it runs leaf to anchor"
        }
        require(verifiedPath == null || verifiedPath.size <= RevoktLimits.MAX_DEPTH + 1) {
            "verifiedPath holds more than MAX_DEPTH + 1 certificates, the longest path a walk builds"
        }
        require(presented == null || verifiedPath == null || presented[0] == verifiedPath[0]) {
            "verifiedPath does not start with the presented leaf"
        }
    }

    /** A builder holding this request's values. */
    public fun newBuilder(): Builder {
        val builder = Builder().host(host)
        presented?.let { chain -> builder.presented(chain.map { it.toByteArray() }) }
        verifiedPath?.let { path -> builder.verifiedPath(path.map { it.toByteArray() }) }
        nowMillis?.let { builder.nowMillis(it) }
        return builder
    }

    /** Every field, named, in declaration order: equality, hashing and [toString] all read this one list. */
    private fun fields(): List<Pair<String, Any?>> =
        listOf(
            "presented" to presented,
            "verifiedPath" to verifiedPath,
            "host" to host,
            "nowMillis" to nowMillis,
        )

    override fun equals(other: Any?): Boolean = other is EvaluationRequest && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    /** Each certificate is shown by the SHA-256 of its DER, so a chain prints in a line. */
    override fun toString(): String =
        "EvaluationRequest(presented=${presented?.let(::digests)}, " +
            "verifiedPath=${verifiedPath?.let(::digests)}, host=$host, nowMillis=$nowMillis)"

    /**
     * Builds an [EvaluationRequest]. [build] throws `IllegalArgumentException` unless a chain or a path is set, for an
     * empty chain or an empty path (the maintainer's decision on #182), for a path longer than `MAX_DEPTH + 1`
     * certificates, and when both are set and the path's first certificate is not the presented leaf, byte for byte
     * (the maintainer's decisions on #195).
     */
    public class Builder {
        internal var presented: List<ByteString>? = null
            private set
        internal var verifiedPath: List<ByteString>? = null
            private set
        internal var host: String? = null
            private set
        internal var nowMillis: Long? = null
            private set

        /** The presented chain, leaf first, as sent; walked (decision steps 2 to 6). Copied. */
        public fun presented(chain: List<ByteArray>): Builder = apply { presented = chain.map { it.toByteString() } }

        /**
         * One platform-verified path, leaf to anchor, as the platform's validator returned it (upki's single webpki
         * `VerifiedPath`), trusted without re-verification: the source is `PLATFORM` and the walk is skipped. Copied.
         */
        public fun verifiedPath(path: List<ByteArray>): Builder =
            apply { verifiedPath = path.map { it.toByteString() } }

        /** The host the chain was presented for, used for host' only; null for none. */
        public fun host(host: String?): Builder = apply { this.host = host }

        public fun nowMillis(nowMillis: Long): Builder = apply { this.nowMillis = nowMillis }

        public fun build(): EvaluationRequest = EvaluationRequest(this)
    }
}

private fun digests(ders: List<ByteString>): List<String> = ders.map { it.sha256().hex() }
