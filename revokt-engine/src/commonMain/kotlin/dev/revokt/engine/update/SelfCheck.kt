// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.CrliteSct
import dev.revokt.LogLevel
import dev.revokt.RevoktLogger
import dev.revokt.RevoktTestingApi
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.port.ClubcardIndexEntry
import dev.revokt.clubcard.port.CrliteClubcard
import dev.revokt.clubcard.port.CrliteKey
import dev.revokt.clubcard.port.CrliteStatus
import dev.revokt.clubcard.port.IssuerSpkiHash
import dev.revokt.clubcard.port.LogId
import dev.revokt.clubcard.port.LogTimestamp
import dev.revokt.clubcard.port.Timestamp
import dev.revokt.engine.c2sp.IndexFile
import dev.revokt.engine.c2sp.Window
import dev.revokt.safeLog
import okio.ByteString
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString

/** What a self-check probe tests (spec §6.5). */
internal enum class ProbeKind {
    /** The absent issuer with a filter's inside SCT: the `NOT_ENROLLED` class. */
    ABSENT_INSIDE,

    /** The absent issuer with a filter's outside SCT: `NOT_COVERED` or its class. */
    ABSENT_OUTSIDE,

    /** `REVOKED`, branch one: the first candidate serial revoked against an inverted block. */
    REVOKED_CANDIDATE_INVERTED,

    /** `REVOKED`, branch two: an exception-list serial of an inverted block. */
    REVOKED_EXCEPTION,

    /** `REVOKED`, branch three: the first candidate serial that is a member of a non-inverted block. */
    REVOKED_CANDIDATE_MEMBER,
}

/** One self-check query and the answers that pass it. */
internal class Probe(
    val kind: ProbeKind,
    val filter: String,
    val query: CrliteQuery,
    val expected: Set<CrliteQueryResult>,
) {
    override fun toString(): String = "Probe($kind, $filter, $query, expected=$expected)"
}

/** The self-check's verdict on a prepared generation. */
internal sealed interface SelfCheckResult {
    /** Every probe answered as expected; [probes] is what ran, in order. */
    class Passed(
        val probes: List<Probe>,
    ) : SelfCheckResult

    /** [probe] answered [actual]. */
    class Mismatch(
        val probe: Probe,
        val actual: CrliteQueryResult,
    ) : SelfCheckResult {
        override fun toString(): String = "Mismatch($probe answered $actual)"
    }
}

/**
 * The engine self-check of spec §6.5, run on `prepared.query` between `prepare` and `activate`: deterministic, with
 * every input named, so it catches an engine that answers a constant (its purpose) while the §9 oracle covers decoder
 * bugs the engine and the loader would share.
 *
 * Filters are iterated in `index.bin` filename order and each filter's index entries by ascending issuer hash. A
 * filter's inside SCT is (`logId`, `low`) of its first non-empty coverage entry in `index.bin` order (log directory
 * order, then entry order); its outside SCT is (`logId`, `high + 1`), or `low − 1` when `high` is the maximum. The
 * absent issuer is `SHA-256("revokt-self-check")`, its last byte incremented until no filter's index holds it; with
 * serial `0x01` and each filter's inside and outside SCT it must answer in the `{NOT_COVERED, NOT_ENROLLED, NO_SCTS}`
 * class (§3.2), so the upki engine passes.
 *
 * The `REVOKED` probe takes the first branch that yields, each judged by the loader's own `revokt-clubcard` reference
 * evaluator against the block's filter under that filter's inside SCT: the first of the serials `0x01`..`0x1000`
 * (minimal DER INTEGER content, ascending) revoked against some inverted block; else an exception-list serial of an
 * inverted block; else the first candidate that is a member of a non-inverted block. It must answer exactly `REVOKED`.
 * A probe with no input (no coverage entry, every candidate issuer present, no block yielding) is skipped and logged at
 * [LogLevel.INFO].
 */
@OptIn(RevoktInternalApi::class, RevoktTestingApi::class)
internal object SelfCheck {
    /** The answers spec §3.2 puts in one class, so a not-enrolled or uncovered certificate passes on every engine. */
    val NOT_ENROLLED_CLASS: Set<CrliteQueryResult> =
        setOf(CrliteQueryResult.NOT_COVERED, CrliteQueryResult.NOT_ENROLLED, CrliteQueryResult.NO_SCTS)

    /** `SHA-256("revokt-self-check")`, the absent issuer's first candidate. */
    val ABSENT_ISSUER_SEED: ByteString = "revokt-self-check".encodeUtf8().sha256()

    /** The last candidate serial of the `REVOKED` probe. */
    private const val LAST_CANDIDATE = 0x1000
    private const val BYTE_VALUES = 256

    /** The candidate serials `0x01`..`0x1000` as minimal DER INTEGER content bytes, ascending. */
    val CANDIDATES: List<ByteString> = (1..LAST_CANDIDATE).map(::minimalInteger)

    /** Runs [probes] against [query], stopping at the first mismatch. */
    fun run(
        index: IndexFile,
        filters: Map<String, CrliteClubcard>,
        query: (CrliteQuery) -> CrliteQueryResult,
        logger: RevoktLogger,
    ): SelfCheckResult {
        val probes = probes(index, filters, logger)
        for (probe in probes) {
            val actual = query(probe.query)
            if (actual !in probe.expected) return SelfCheckResult.Mismatch(probe, actual)
        }
        return SelfCheckResult.Passed(probes)
    }

    /** The probes for the generation [index] lays out over the decoded [filters] (by name), in the order they run. */
    fun probes(
        index: IndexFile,
        filters: Map<String, CrliteClubcard>,
        logger: RevoktLogger,
    ): List<Probe> {
        val tested =
            index.filenames.distinct().mapNotNull { name ->
                val filter = requireNotNull(filters[name]) { "$name is not decoded" }
                inside(index, name)?.let { Tested(name, filter, it.first, it.second) }
            }
        if (tested.isEmpty()) {
            logger.safeLog(LogLevel.INFO, "engine self-check: no coverage entry, every probe skipped")
            return emptyList()
        }
        val out = mutableListOf<Probe>()
        val absent = absentIssuer(filters.values)
        if (absent == null) {
            logger.safeLog(
                LogLevel.INFO,
                "engine self-check: every candidate issuer is enrolled, absent probes skipped",
            )
        } else {
            for (t in tested) {
                val outside = if (t.window.high == ULong.MAX_VALUE) t.window.low - 1u else t.window.high + 1u
                out +=
                    Probe(
                        ProbeKind.ABSENT_INSIDE,
                        t.name,
                        query(absent, ONE, t.logId, t.window.low),
                        NOT_ENROLLED_CLASS,
                    )
                out += Probe(ProbeKind.ABSENT_OUTSIDE, t.name, query(absent, ONE, t.logId, outside), NOT_ENROLLED_CLASS)
            }
        }
        val revoked = revokedProbe(tested)
        if (revoked == null) {
            logger.safeLog(LogLevel.INFO, "engine self-check: no block yields a REVOKED probe, skipped")
        } else {
            out += revoked
        }
        return out
    }

    /** A filter under test with its inside coverage entry. */
    private class Tested(
        val name: String,
        val filter: CrliteClubcard,
        val logId: ByteString,
        val window: Window,
    ) {
        /** The filter's index entries by ascending issuer hash (unsigned bytes). */
        val blocks: List<Pair<ByteString, ClubcardIndexEntry>> =
            filter.index.entries
                .sortedBy { it.key }
                .map { it.toPair() }

        /** Whether the loader's reference evaluator calls (issuer, serial) revoked in this filter at the inside SCT. */
        fun revoked(
            issuer: ByteString,
            serial: ByteString,
        ): Boolean {
            val key = CrliteKey(IssuerSpkiHash(issuer), serial)
            val at = LogTimestamp(LogId(logId), Timestamp(window.low.toLong()))
            return filter.contains(key, listOf(at)) == CrliteStatus.REVOKED
        }

        /** The `REVOKED` probe for (issuer, serial) with this filter's inside SCT. */
        fun probe(
            kind: ProbeKind,
            issuer: ByteString,
            serial: ByteString,
        ): Probe = Probe(kind, name, query(issuer, serial, logId, window.low), setOf(CrliteQueryResult.REVOKED))
    }

    /** The first non-empty entry for [name] in `index.bin` order: log directory order, then each section's order. */
    private fun inside(
        index: IndexFile,
        name: String,
    ): Pair<ByteString, Window>? {
        for ((logId, entries) in index.logs) {
            for (e in entries) if (index.filenames[e.filterIndex] == name && !e.window.isEmpty) return logId to e.window
        }
        return null
    }

    /** [ABSENT_ISSUER_SEED] with its last byte incremented (mod 256) until no filter's index holds it, or null. */
    private fun absentIssuer(filters: Collection<CrliteClubcard>): ByteString? {
        val bytes = ABSENT_ISSUER_SEED.toByteArray()
        repeat(BYTE_VALUES) {
            val candidate = bytes.toByteString()
            if (filters.none { candidate in it.index }) return candidate
            bytes[bytes.size - 1]++
        }
        return null
    }

    /** The first branch of the `REVOKED` probe that yields, in spec order. */
    private fun revokedProbe(tested: List<Tested>): Probe? =
        firstCandidate(tested, ProbeKind.REVOKED_CANDIDATE_INVERTED) { it.inverted }
            ?: firstException(tested)
            // A non-inverted block with approxM == 0 holds no member (clubcard's empty filter), so it is not queried.
            ?: firstCandidate(tested, ProbeKind.REVOKED_CANDIDATE_MEMBER) { !it.inverted && it.approxFilterM != 0L }

    /**
     * The first of [CANDIDATES] that the reference evaluator calls revoked against an [eligible] block, serial first:
     * for each serial, the filters in `index.bin` order and their blocks by ascending issuer hash.
     */
    private fun firstCandidate(
        tested: List<Tested>,
        kind: ProbeKind,
        eligible: (ClubcardIndexEntry) -> Boolean,
    ): Probe? {
        for (serial in CANDIDATES) {
            for (t in tested) {
                val issuer = t.blocks.firstOrNull { (issuer, block) -> eligible(block) && t.revoked(issuer, serial) }
                if (issuer != null) return t.probe(kind, issuer.first, serial)
            }
        }
        return null
    }

    /** The first exception-list serial of an inverted block that the reference evaluator calls revoked. */
    private fun firstException(tested: List<Tested>): Probe? {
        for (t in tested) {
            for ((issuer, block) in t.blocks.filter { it.second.inverted }) {
                val serial = block.exceptions.firstOrNull { t.revoked(issuer, it) }
                if (serial != null) return t.probe(ProbeKind.REVOKED_EXCEPTION, issuer, serial)
            }
        }
        return null
    }

    private val ONE: ByteString = byteArrayOf(1).toByteString()

    private fun query(
        issuer: ByteString,
        serial: ByteString,
        logId: ByteString,
        timestamp: ULong,
    ): CrliteQuery =
        CrliteQuery
            .Builder()
            .issuerSpkiHash(issuer.toByteArray())
            .serial(serial.toByteArray())
            .sct(CrliteSct.of(logId, timestamp.toLong()))
            .build()

    /** The DER INTEGER content of the positive [n]: big-endian, no leading zero byte unless the top bit is set. */
    private fun minimalInteger(n: Int): ByteString {
        var bytes = byteArrayOf((n ushr 8).toByte(), n.toByte()).dropWhile { it == 0.toByte() }
        if (bytes.first() < 0) bytes = listOf(0.toByte()) + bytes
        return bytes.toByteArray().toByteString()
    }
}
