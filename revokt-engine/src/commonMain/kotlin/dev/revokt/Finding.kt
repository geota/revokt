// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * What an evaluation found, carried on a verdict (spec §4). Growable: a subtype may be added in a minor, so a `when`
 * over findings needs an `else` branch. Every subtype is a value type with a private constructor and a
 * `@RevoktTestingApi` builder; equality is by content, and `ByteArray` getters return fresh copies.
 */
public sealed class Finding {
    /**
     * The path finding (spec §4, §5.1): the status the walk and decision steps 1 to 6 reached and how they reached it.
     * The builder checks the invariants that need no other finding: [parseReason] is set exactly when [status] is
     * `PARSE_FAILED`, [keyabilityClause] exactly when [parseReason] is `PRODUCER_UNKEYABLE`, and [noIssuerReason]
     * exactly when [status] is `NO_ISSUER`.
     */
    @OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
    public class Path private constructor(
        builder: Builder,
    ) : Finding() {
        // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
        // fields are added (the class is growable).
        public val status: PathStatus = requireNotNull(builder.status) { "status is not set" }

        public val source: ChainSource = requireNotNull(builder.source) { "source is not set" }

        /** The reported reason, after any `PLATFORM_ONLY` promotion; set exactly when [status] is `NO_ISSUER`. */
        public val noIssuerReason: NoIssuerReason? = builder.noIssuerReason

        /** The walker's own reason, before any `PLATFORM_ONLY` promotion. */
        public val walkerReason: NoIssuerReason? = builder.walkerReason

        /** Set exactly when [status] is `PARSE_FAILED`. */
        public val parseReason: ParseReason? = builder.parseReason

        /** The first failing §9.2 keyability clause; set exactly when [parseReason] is `PRODUCER_UNKEYABLE`. */
        public val keyabilityClause: KeyabilityClause? = builder.keyabilityClause

        /** The reported path's terminal; null when the reported path is empty. */
        public val terminalKind: TerminalKind? = builder.terminalKind

        /** How a re-walk ended; null unless one ran (M2). */
        public val rewalkEnd: WalkEnd? = builder.rewalkEnd

        /** How the walk ended; null only when no walk ran (`NOT_WALKED`, `PLATFORM`, an anchor leaf). */
        public val endReason: WalkEnd? = builder.endReason

        /** The path size at which the walk ended (1 = the leaf level). */
        public val endDepth: Int? = builder.endDepth

        public val cacheHit: Boolean = builder.cacheHit

        /** The id of the `AnchorSnapshot` the decision read; 0 when none was consulted. */
        public val anchorSnapshotId: Long = builder.anchorSnapshotId

        /** True whenever a PKIX fallback path was evaluated. */
        public val usedFallback: Boolean = builder.usedFallback

        /** The paths found, or on `PATH_BUDGET_EXCEEDED` the partial paths. */
        public val pathsFound: Int = builder.pathsFound

        private val reportedPath: List<ByteString> = builder.reportedPathSha256s

        private val issuerSpkis: List<ByteString> = builder.issuerSpkiSha256s

        /** Presented or platform-built certificates the parser rejected and the walker never saw. */
        public val candidatesDropped: Int = builder.candidatesDropped

        private val anchor: ByteString? = builder.anchorSha256

        /** The walker's counters; walker internals. */
        @RevoktInternalApi
        public val walkStats: WalkStats = builder.walkStats

        public val credentialType: CredentialType = builder.credentialType

        init {
            require((parseReason != null) == (status == PathStatus.PARSE_FAILED)) {
                "parseReason is set exactly when status is PARSE_FAILED (spec §4): got status=$status, " +
                    "parseReason=$parseReason"
            }
            require((keyabilityClause != null) == (parseReason == ParseReason.PRODUCER_UNKEYABLE)) {
                "keyabilityClause is set exactly when parseReason is PRODUCER_UNKEYABLE (spec §4): got " +
                    "parseReason=$parseReason, keyabilityClause=$keyabilityClause"
            }
            require((noIssuerReason != null) == (status == PathStatus.NO_ISSUER)) {
                "noIssuerReason is set exactly when status is NO_ISSUER (spec §4): got status=$status, " +
                    "noIssuerReason=$noIssuerReason"
            }
        }

        /**
         * The SHA-256 of each DER of the reported path, leaf to terminal: the first found path, else the first partial
         * path, else empty. Fresh copies.
         */
        public val reportedPathSha256s: List<ByteArray> get() = reportedPath.map { it.toByteArray() }

        /**
         * The SHA-256 of every distinct leaf-issuer SPKI evaluated: walker keys in candidate order, then the fallback
         * key if new; the first is the reported path's. Fresh copies.
         */
        public val issuerSpkiSha256s: List<ByteArray> get() = issuerSpkis.map { it.toByteArray() }

        /** The SHA-256 of the reported path's anchor DER; null when the reported path is empty. A fresh copy. */
        public val anchorSha256: ByteArray? get() = anchor?.toByteArray()

        /** A builder holding this finding's values. */
        @RevoktTestingApi
        public fun newBuilder(): Builder =
            Builder()
                .status(status)
                .source(source)
                .noIssuerReason(noIssuerReason)
                .walkerReason(walkerReason)
                .parseReason(parseReason)
                .keyabilityClause(keyabilityClause)
                .terminalKind(terminalKind)
                .rewalkEnd(rewalkEnd)
                .endReason(endReason)
                .endDepth(endDepth)
                .cacheHit(cacheHit)
                .anchorSnapshotId(anchorSnapshotId)
                .usedFallback(usedFallback)
                .pathsFound(pathsFound)
                .reportedPathSha256s(reportedPathSha256s)
                .issuerSpkiSha256s(issuerSpkiSha256s)
                .candidatesDropped(candidatesDropped)
                .anchorSha256(anchorSha256)
                .walkStats(walkStats)
                .credentialType(credentialType)

        /** Every field, named, in declaration order: equality, hashing and [toString] all read this one list. */
        private fun fields(): List<Pair<String, Any?>> =
            listOf(
                "status" to status,
                "source" to source,
                "noIssuerReason" to noIssuerReason,
                "walkerReason" to walkerReason,
                "parseReason" to parseReason,
                "keyabilityClause" to keyabilityClause,
                "terminalKind" to terminalKind,
                "rewalkEnd" to rewalkEnd,
                "endReason" to endReason,
                "endDepth" to endDepth,
                "cacheHit" to cacheHit,
                "anchorSnapshotId" to anchorSnapshotId,
                "usedFallback" to usedFallback,
                "pathsFound" to pathsFound,
                "reportedPathSha256s" to reportedPath,
                "issuerSpkiSha256s" to issuerSpkis,
                "candidatesDropped" to candidatesDropped,
                "anchorSha256" to anchor,
                "walkStats" to walkStats,
                "credentialType" to credentialType,
            )

        override fun equals(other: Any?): Boolean = other is Path && fields() == other.fields()

        override fun hashCode(): Int = fields().hashCode()

        override fun toString(): String =
            fields().joinToString(prefix = "Path(", postfix = ")") { (name, value) -> "$name=${shown(value)}" }

        /** Builds a [Finding.Path] for tests and fakes; [build] checks the invariants the constructor does. */
        @RevoktTestingApi
        @Suppress("TooManyFunctions") // One setter per spec §4 field, plus build().
        public class Builder {
            internal var status: PathStatus? = null
                private set
            internal var source: ChainSource? = null
                private set
            internal var noIssuerReason: NoIssuerReason? = null
                private set
            internal var walkerReason: NoIssuerReason? = null
                private set
            internal var parseReason: ParseReason? = null
                private set
            internal var keyabilityClause: KeyabilityClause? = null
                private set
            internal var terminalKind: TerminalKind? = null
                private set
            internal var rewalkEnd: WalkEnd? = null
                private set
            internal var endReason: WalkEnd? = null
                private set
            internal var endDepth: Int? = null
                private set
            internal var cacheHit: Boolean = false
                private set
            internal var anchorSnapshotId: Long = 0
                private set
            internal var usedFallback: Boolean = false
                private set
            internal var pathsFound: Int = 0
                private set
            internal var reportedPathSha256s: List<ByteString> = emptyList()
                private set
            internal var issuerSpkiSha256s: List<ByteString> = emptyList()
                private set
            internal var candidatesDropped: Int = 0
                private set
            internal var anchorSha256: ByteString? = null
                private set
            internal var walkStats: WalkStats = WalkStats(0, 0, 0, 0)
                private set
            internal var credentialType: CredentialType = CredentialType.X509
                private set

            public fun status(status: PathStatus): Builder = apply { this.status = status }

            public fun source(source: ChainSource): Builder = apply { this.source = source }

            public fun noIssuerReason(reason: NoIssuerReason?): Builder = apply { noIssuerReason = reason }

            public fun walkerReason(reason: NoIssuerReason?): Builder = apply { walkerReason = reason }

            public fun parseReason(reason: ParseReason?): Builder = apply { parseReason = reason }

            public fun keyabilityClause(clause: KeyabilityClause?): Builder = apply { keyabilityClause = clause }

            public fun terminalKind(kind: TerminalKind?): Builder = apply { terminalKind = kind }

            public fun rewalkEnd(end: WalkEnd?): Builder = apply { rewalkEnd = end }

            public fun endReason(end: WalkEnd?): Builder = apply { endReason = end }

            public fun endDepth(depth: Int?): Builder = apply { endDepth = depth }

            public fun cacheHit(hit: Boolean): Builder = apply { cacheHit = hit }

            public fun anchorSnapshotId(id: Long): Builder = apply { anchorSnapshotId = id }

            public fun usedFallback(used: Boolean): Builder = apply { usedFallback = used }

            public fun pathsFound(count: Int): Builder = apply { pathsFound = count }

            /** Replaces the reported path's hashes with copies of [sha256s]. */
            public fun reportedPathSha256s(sha256s: List<ByteArray>): Builder =
                apply { reportedPathSha256s = sha256s.map { it.toByteString() } }

            /** Replaces the leaf-issuer key hashes with copies of [sha256s]. */
            public fun issuerSpkiSha256s(sha256s: List<ByteArray>): Builder =
                apply { issuerSpkiSha256s = sha256s.map { it.toByteString() } }

            public fun candidatesDropped(count: Int): Builder = apply { candidatesDropped = count }

            public fun anchorSha256(sha256: ByteArray?): Builder = apply { anchorSha256 = sha256?.toByteString() }

            @RevoktInternalApi
            public fun walkStats(stats: WalkStats): Builder = apply { walkStats = stats }

            public fun credentialType(type: CredentialType): Builder = apply { credentialType = type }

            public fun build(): Path = Path(this)
        }
    }

    /**
     * An algorithm OID a layer could not verify (spec §4, §5.1): the walk emits one per OID it met, on every outcome,
     * with [outcomeDepended] true exactly when the status is `ISSUER_UNVERIFIED`.
     */
    @OptIn(RevoktTestingApi::class)
    public class UnsupportedAlgorithm private constructor(
        builder: Builder,
    ) : Finding() {
        /** The dotted OID. */
        public val oid: String = requireNotNull(builder.oid) { "oid is not set" }

        /** The layer that met it. */
        public val where: Layer = requireNotNull(builder.where) { "where is not set" }

        public val outcomeDepended: Boolean = builder.outcomeDepended

        /** A builder holding this finding's values. */
        @RevoktTestingApi
        public fun newBuilder(): Builder = Builder().oid(oid).where(where).outcomeDepended(outcomeDepended)

        override fun equals(other: Any?): Boolean =
            other is UnsupportedAlgorithm &&
                oid == other.oid &&
                where == other.where &&
                outcomeDepended == other.outcomeDepended

        override fun hashCode(): Int = listOf(oid, where, outcomeDepended).hashCode()

        override fun toString(): String =
            "UnsupportedAlgorithm(oid=$oid, where=$where, outcomeDepended=$outcomeDepended)"

        /** Builds a [Finding.UnsupportedAlgorithm] for tests and fakes. */
        @RevoktTestingApi
        public class Builder {
            internal var oid: String? = null
                private set
            internal var where: Layer? = null
                private set
            internal var outcomeDepended: Boolean = false
                private set

            public fun oid(oid: String): Builder = apply { this.oid = oid }

            public fun where(layer: Layer): Builder = apply { where = layer }

            public fun outcomeDepended(depended: Boolean): Builder = apply { outcomeDepended = depended }

            public fun build(): UnsupportedAlgorithm = UnsupportedAlgorithm(this)
        }
    }

    /**
     * A verifier or algorithm failure the walk recorded (spec §3 "Verifier contract", §4, §5.1): the link counts as
     * `INVALID`. Never the PKIX fallback, which is [FallbackNotUsed].
     */
    @OptIn(RevoktTestingApi::class)
    public class VerifierError private constructor(
        builder: Builder,
    ) : Finding() {
        /** The dotted OID of the signature algorithm whose verification failed. */
        public val oid: String = requireNotNull(builder.oid) { "oid is not set" }

        public val message: String = requireNotNull(builder.message) { "message is not set" }

        /** A builder holding this finding's values. */
        @RevoktTestingApi
        public fun newBuilder(): Builder = Builder().oid(oid).message(message)

        override fun equals(other: Any?): Boolean =
            other is VerifierError && oid == other.oid && message == other.message

        override fun hashCode(): Int = 31 * oid.hashCode() + message.hashCode()

        override fun toString(): String = "VerifierError(oid=$oid, message=$message)"

        /** Builds a [Finding.VerifierError] for tests and fakes. */
        @RevoktTestingApi
        public class Builder {
            internal var oid: String? = null
                private set
            internal var message: String? = null
                private set

            public fun oid(oid: String): Builder = apply { this.oid = oid }

            public fun message(message: String): Builder = apply { this.message = message }

            public fun build(): VerifierError = VerifierError(this)
        }

        internal companion object {
            /**
             * A verifier throw as the walk records it (spec §5.1 decision list): [oid] is the child's own TBS signature
             * OID, `""` when that `AlgorithmIdentifier` does not decode (`Cert.tbsSigOid`).
             */
            fun of(
                oid: String,
                message: String,
            ): VerifierError = Builder().oid(oid).message(message).build()
        }
    }

    /**
     * Decision step 6 evaluated no PKIX fallback path (spec §4, §5.1): exactly one when the step-5 walk ended `NotFound`
     * or `Budget` and `Finding.Path.usedFallback` is false. "Not used" rather than "not run": a [FallbackReason.FAILED]
     * fallback did run.
     */
    @OptIn(RevoktTestingApi::class)
    public class FallbackNotUsed private constructor(
        builder: Builder,
    ) : Finding() {
        public val reason: FallbackReason = requireNotNull(builder.reason) { "reason is not set" }

        /** A builder holding this finding's values. */
        @RevoktTestingApi
        public fun newBuilder(): Builder = Builder().reason(reason)

        override fun equals(other: Any?): Boolean = other is FallbackNotUsed && reason == other.reason

        override fun hashCode(): Int = reason.hashCode()

        override fun toString(): String = "FallbackNotUsed(reason=$reason)"

        /** Builds a [Finding.FallbackNotUsed] for tests and fakes. */
        @RevoktTestingApi
        public class Builder {
            internal var reason: FallbackReason? = null
                private set

            public fun reason(reason: FallbackReason): Builder = apply { this.reason = reason }

            public fun build(): FallbackNotUsed = FallbackNotUsed(this)
        }
    }

    /**
     * A presented certificate whose outer signature AlgorithmIdentifier differs from its TBS one after NULL/absent
     * normalisation (spec §5.1): once per such certificate, computed at parse time.
     */
    @OptIn(RevoktTestingApi::class)
    public class AlgorithmIdMismatch private constructor(
        builder: Builder,
    ) : Finding() {
        /** The certificate's index in the presented chain, the leaf at 0. */
        public val certIndex: Int = requireNotNull(builder.certIndex) { "certIndex is not set" }

        init {
            require(certIndex >= 0) { "certIndex is an index into the presented chain, got $certIndex" }
        }

        /** A builder holding this finding's values. */
        @RevoktTestingApi
        public fun newBuilder(): Builder = Builder().certIndex(certIndex)

        override fun equals(other: Any?): Boolean = other is AlgorithmIdMismatch && certIndex == other.certIndex

        override fun hashCode(): Int = certIndex

        override fun toString(): String = "AlgorithmIdMismatch(certIndex=$certIndex)"

        /** Builds a [Finding.AlgorithmIdMismatch] for tests and fakes. */
        @RevoktTestingApi
        public class Builder {
            internal var certIndex: Int? = null
                private set

            public fun certIndex(index: Int): Builder = apply { certIndex = index }

            public fun build(): AlgorithmIdMismatch = AlgorithmIdMismatch(this)
        }
    }
}

/** A field value as [Finding] subtypes print it: hashes in hex. */
private fun shown(value: Any?): Any? =
    when (value) {
        is ByteString -> value.hex()
        is List<*> -> value.map(::shown)
        else -> value
    }
