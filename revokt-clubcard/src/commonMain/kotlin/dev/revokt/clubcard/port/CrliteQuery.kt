// SPDX-FileCopyrightText: Mozilla Foundation and clubcard contributors; translation 2026 revokt contributors
// SPDX-License-Identifier: MPL-2.0
// Translation of clubcard-crlite 0.6.2 src/query.rs (git b8ca6961975d51518097dd4eb99d0fdeabee7845), spec §3.1.
// Decoding and querying only: `to_bytes`, the `encode` halves, `Display` and `ApproximateSizeOf` are not translated;
// `impl Codec for ClubcardIndex` is in Codec.kt beside the entry reader. The bincode (v3) path is not part of the
// port: it is decoded by `dev.revokt.clubcard.api.ClubcardFilters`. Lines marked `revokt:` are spec §6.3 additions.
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
// distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dev.revokt.clubcard.port

import dev.revokt.clubcard.RevoktInternalApi
import okio.Buffer
import okio.ByteString

/** SHA-256 of the issuer's SubjectPublicKeyInfo (spec §6.1); exactly 32 bytes. */
@RevoktInternalApi
public data class IssuerSpkiHash(
    public val bytes: ByteString,
) {
    init {
        require(bytes.size == 32) { "an issuer SPKI hash is 32 bytes, got ${bytes.size}" }
    }

    override fun toString(): String = "IssuerSpkiHash(${bytes.hex()})"
}

/** A CT log id (`opaque LogId[32]`, the SHA-256 of the log's public key); exactly 32 bytes. */
@RevoktInternalApi
public data class LogId(
    public val bytes: ByteString,
) {
    init {
        require(bytes.size == 32) { "a log id is 32 bytes, got ${bytes.size}" }
    }

    override fun toString(): String = "LogId(${bytes.hex()})"

    @RevoktInternalApi
    public companion object {
        /** `opaque LogId[32]`: a fixed-width 32-byte digest, no length prefix. */
        public fun read(buf: ByteReader): LogId = LogId(buf.bytes(32, "LogId"))
    }
}

/** A CT timestamp in milliseconds, an unsigned `u64` upstream: comparisons are unsigned. */
@RevoktInternalApi
public data class Timestamp(
    public val value: Long,
) : Comparable<Timestamp> {
    override fun compareTo(other: Timestamp): Int = value.toULong().compareTo(other.value.toULong())

    override fun toString(): String = "Timestamp(${value.toULong()})"

    @RevoktInternalApi
    public companion object {
        public val MIN: Timestamp = Timestamp(0)
        public val MAX: Timestamp = Timestamp(ULong.MAX_VALUE.toLong())

        /** `uint64 Timestamp`, big-endian. */
        public fun read(buf: ByteReader): Timestamp = Timestamp(buf.readU64())
    }
}

/** `struct { Timestamp low; Timestamp high; } TimestampInterval;` */
@RevoktInternalApi
public data class TimestampInterval(
    public val low: Timestamp,
    public val high: Timestamp,
) {
    @RevoktInternalApi
    public companion object {
        public fun read(buf: ByteReader): TimestampInterval {
            val low = Timestamp.read(buf)
            val high = Timestamp.read(buf)
            return TimestampInterval(low, high)
        }
    }
}

/** The universe metadata: which CT logs the filter covers, and over which timestamp interval. */
@RevoktInternalApi
public class CrliteCoverage(
    public val logs: Map<LogId, TimestampInterval>,
) {
    @RevoktInternalApi
    public companion object {
        /**
         * ```
         * struct {
         *     LogId             log_id;
         *     TimestampInterval interval;
         * } Coverage;
         *
         * Coverage coverage<count>;   // uint16 count, then `count` entries
         * ```
         */
        public fun read(buf: ByteReader): CrliteCoverage {
            val count = buf.readLen(2).toInt()
            // Linked so iteration follows the file, which keeps every consumer deterministic (upstream: HashMap).
            val map = LinkedHashMap<LogId, TimestampInterval>(count)
            repeat(count) {
                val logId = LogId.read(buf)
                val interval = TimestampInterval.read(buf)
                // revokt: spec §6.3, log ids distinct (a C2SP MUST; upstream overwrites the earlier interval).
                if (map.put(logId, interval) != null) {
                    throw ClubcardError.Deserialize("coverage lists log ${logId.bytes.hex()} twice")
                }
            }
            return CrliteCoverage(map)
        }
    }
}

/** An (issuer, serial) pair with its `SHA-256(issuer || serial)`, the bytes every query hashes (spec §6.1). */
@RevoktInternalApi
public class CrliteKey(
    public val issuer: IssuerSpkiHash,
    public val serial: ByteString,
    /** `SHA-256(issuer || serial)`; not verified by the constructor (upstream `with_hash`). */
    public val issuerSerialHash: ByteString,
) {
    /** Computes the hash (upstream `new`). */
    public constructor(issuer: IssuerSpkiHash, serial: ByteString) :
        this(issuer, serial, Buffer().write(issuer.bytes).write(serial).sha256())

    init {
        require(issuerSerialHash.size == 32) { "an issuer-serial hash is 32 bytes, got ${issuerSerialHash.size}" }
    }
}

/** One SCT's `(LogId, Timestamp)` as a query sees it. */
@RevoktInternalApi
public data class LogTimestamp(
    public val logId: LogId,
    public val timestamp: Timestamp,
)

/** A key with the SCT it is being checked under (`None` upstream when there is no SCT: never in the universe). */
@RevoktInternalApi
public class CrliteQuery(
    public val key: CrliteKey,
    public val logTimestamp: LogTimestamp?,
) : Queryable<CrliteCoverage> {
    override fun block(): ByteString = key.issuer.bytes

    /** Spec §6.2: `a[i]` = little-endian `u64` limbs of the key hash, `a[0] |= 1`, `s = a[3] % max(1, m)`. */
    override fun asQuery(m: Long): Equation {
        val a = LongArray(WORD_WIDTH)
        val hash = key.issuerSerialHash
        for (i in 0 until WORD_WIDTH) {
            var limb = 0L
            for (j in 7 downTo 0) limb = (limb shl 8) or (hash[8 * i + j].toLong() and 0xff)
            a[i] = limb
        }
        a[0] = a[0] or 1L
        val s = (a[3].toULong() % maxOf(m.toULong(), 1uL)).toLong()
        return Equation.homogeneous(s, a)
    }

    override fun discriminant(): ByteString = key.serial

    override fun inUniverse(meta: CrliteCoverage): Boolean {
        val (logId, timestamp) = logTimestamp ?: return false
        val interval = meta.logs[logId] ?: return false
        return interval.low <= timestamp && timestamp <= interval.high
    }
}

/** `ClubcardError` upstream; `Serialize` has no decoding counterpart. */
@RevoktInternalApi
public sealed class ClubcardError(
    message: String,
) : Exception(message) {
    @RevoktInternalApi
    public class Deserialize(
        detail: String,
    ) : ClubcardError("failed to deserialize clubcard: $detail")

    @RevoktInternalApi
    public class UnsupportedVersion(
        public val version: Int,
    ) : ClubcardError("unsupported clubcard version ($version)")
}

/** The per-filter answer (`CRLiteStatus` upstream). */
@RevoktInternalApi
public enum class CrliteStatus {
    GOOD,
    NOT_COVERED,
    NOT_ENROLLED,
    REVOKED,
    ;

    @RevoktInternalApi
    public companion object {
        public fun of(membership: Membership): CrliteStatus =
            when (membership) {
                Membership.NONMEMBER -> GOOD
                Membership.NOT_IN_UNIVERSE -> NOT_COVERED
                Membership.NO_DATA -> NOT_ENROLLED
                Membership.MEMBER -> REVOKED
            }
    }
}

/** The 2-byte prefix `[version, reserved0 = 0]`; cascade-based CRLite filters used versions 0, 1 and 2. */
@RevoktInternalApi
public enum class Encoding(
    public val version: Int,
) {
    V3(3),
    V4(4),
    ;

    @RevoktInternalApi
    public companion object {
        public fun read(buf: ByteReader): Encoding {
            val prefix = buf.bytes(2, "Encoding")
            val version = prefix[0].toInt() and 0xff
            val reserved0 = prefix[1].toInt() and 0xff
            if (reserved0 != 0) throw ClubcardError.Deserialize("non-zero reserved0 byte after version")
            return entries.firstOrNull { it.version == version } ?: throw ClubcardError.UnsupportedVersion(version)
        }
    }
}

/** A clubcard over CRLite's universe (`CRLiteClubcard` upstream). */
@RevoktInternalApi
public class CrliteClubcard(
    public val inner: Clubcard<CrliteCoverage>,
) {
    public val universe: CrliteCoverage get() = inner.universe

    public val index: ClubcardIndex get() = inner.index

    /**
     * The first status other than [CrliteStatus.NOT_COVERED] over the given SCTs, else [CrliteStatus.NOT_COVERED]
     * (spec §6.2 `perFilter`: one covered SCT suffices).
     */
    public fun contains(
        key: CrliteKey,
        timestamps: Iterable<LogTimestamp>,
    ): CrliteStatus {
        for (logTimestamp in timestamps) {
            val status = CrliteStatus.of(inner.contains(CrliteQuery(key, logTimestamp)))
            if (status != CrliteStatus.NOT_COVERED) return status
        }
        return CrliteStatus.NOT_COVERED
    }

    @RevoktInternalApi
    public companion object {
        /**
         * Deserialize a v4 clubcard, rejecting trailing bytes. A v3 prefix is refused here: bincode is not part of
         * the translation (see `dev.revokt.clubcard.api.ClubcardFilters`).
         */
        public fun fromBytes(bytes: ByteArray): CrliteClubcard {
            val buf = ByteReader(bytes)
            return when (Encoding.read(buf)) {
                Encoding.V3 -> {
                    throw ClubcardError.Deserialize(
                        "v3 (bincode) is decoded by dev.revokt.clubcard.api.ClubcardFilters",
                    )
                }

                Encoding.V4 -> {
                    val clubcard = Codec.readClubcard(buf)
                    if (!buf.isEmpty()) throw ClubcardError.Deserialize("trailing bytes after clubcard")
                    CrliteClubcard(clubcard)
                }
            }
        }
    }
}
