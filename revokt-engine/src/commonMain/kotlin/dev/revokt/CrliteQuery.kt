// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * The only engine input (spec §3.2, §6.1), extracted by revokt's parser from the path-verified leaf and issuer, so an
 * engine swap cannot change what is looked up. Growable: a field added in a minor does not break engines. A value
 * type: equality is by content, and, as for the query itself, the order of [scts] is not significant.
 */
@OptIn(RevoktTestingApi::class)
public class CrliteQuery private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).
    private val issuerHash: ByteString = requireNotNull(builder.issuerSpkiHash) { "issuerSpkiHash is not set" }

    private val serialBytes: ByteString = requireNotNull(builder.serial) { "serial is not set" }

    init {
        require(issuerHash.size == ISSUER_HASH_BYTES) {
            "an issuer SPKI hash is $ISSUER_HASH_BYTES bytes, got ${issuerHash.size}"
        }
    }

    /** The SHA-256 of the issuer's SPKI TLV, as a fresh copy. */
    public val issuerSpkiHash: ByteArray get() = issuerHash.toByteArray()

    /** The DER INTEGER content bytes as encoded (`rawSerial`, §9.2), as a fresh copy. */
    public val serial: ByteArray get() = serialBytes.toByteArray()

    /**
     * The SCTs the leaf's SCT extensions keep under §9.2; empty when none parses. Order is not significant to a
     * query. Read-only.
     */
    public val scts: List<CrliteSct> = buildList { addAll(builder.scts) }

    internal val issuerSpkiHashBytes: ByteString get() = issuerHash

    internal val serialByteString: ByteString get() = serialBytes

    /** A builder holding this query's values. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .issuerSpkiHash(issuerHash.toByteArray())
            .serial(serialBytes.toByteArray())
            .also { b -> scts.forEach { b.sct(it) } }

    override fun equals(other: Any?): Boolean =
        other is CrliteQuery &&
            issuerHash == other.issuerHash &&
            serialBytes == other.serialBytes &&
            sctCounts == other.sctCounts

    // Order-insensitive: the same SCTs in another order are the same query (§3.2).
    override fun hashCode(): Int = listOf(issuerHash, serialBytes, sctCounts).hashCode()

    private val sctCounts: Map<CrliteSct, Int> get() = scts.groupingBy { it }.eachCount()

    override fun toString(): String =
        "CrliteQuery(issuerSpkiHash=${issuerHash.hex()}, serial=${serialBytes.hex()}, scts=$scts)"

    /** Builds a [CrliteQuery] for tests and fakes. */
    @RevoktTestingApi
    public class Builder {
        internal var issuerSpkiHash: ByteString? = null
            private set
        internal var serial: ByteString? = null
            private set
        internal val scts = ArrayList<CrliteSct>()

        public fun issuerSpkiHash(hash: ByteArray): Builder = apply { issuerSpkiHash = hash.toByteString() }

        public fun serial(serial: ByteArray): Builder = apply { this.serial = serial.toByteString() }

        /** Adds one SCT. */
        public fun sct(sct: CrliteSct): Builder = apply { scts += sct }

        /** Replaces the SCTs. */
        public fun scts(scts: List<CrliteSct>): Builder =
            apply {
                this.scts.clear()
                this.scts += scts
            }

        public fun build(): CrliteQuery = CrliteQuery(this)
    }

    private companion object {
        private const val ISSUER_HASH_BYTES = 32
    }
}
