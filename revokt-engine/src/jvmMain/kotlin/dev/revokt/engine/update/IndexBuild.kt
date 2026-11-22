// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// detekt 1.23 resolves types with a Kotlin 2.0 compiler that cannot read the 2.4 stdlib's metadata, so it reports the code
// after an inline lambda's non-local return or `Nothing` call as unreachable; kotlinc's own unreachable-code check holds.
@file:Suppress("UnreachableCode")

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.DiagnosticCode
import dev.revokt.SyncStage
import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.StoreLayout
import okio.ByteString

/**
 * One Remote Settings CRLite record as [buildIndex] reads it (spec §6.5, §7.1): the schema-checked fields that place a
 * filter in a generation. [channel] is the record's wire name ([CrliteChannel.wireName]); [filename] is its
 * §6.3-checked `attachment.filename`, which stays in the signed records only and maps to the file's name in the
 * generation.
 */
internal class FilterRecord(
    val id: String,
    val channel: String,
    val incremental: Boolean,
    val effectiveTimestamp: Long,
    val filename: String,
) {
    init {
        require(id.isNotEmpty()) { "a record id is empty" }
        require(GenerationNames.isSourceFilename(filename)) { "'$filename' is not a §6.3 filename" }
    }

    override fun toString(): String =
        "FilterRecord($id, $channel, ${if (incremental) "delta" else "full"}, $effectiveTimestamp, $filename)"
}

/** A record [buildIndex] placed in the generation, under [name], its file's name there (spec §6.5). */
internal class PlacedFilter(
    val record: FilterRecord,
    val name: String,
) {
    val full: Boolean get() = !record.incremental

    override fun toString(): String = "PlacedFilter(${record.id} as $name)"
}

/** Why [buildIndex] refused a record set. */
internal enum class IndexRefusal {
    /** Two placed attachments map to one name, or one maps to a name the generation directory reserves (spec §6.5). */
    NAME_COLLISION,

    /** The channel's records hold no full filter, or more than one. */
    FULL_COUNT,

    /** The index would be over [C2spIndex.MAX_BYTES] (spec §3.2, revision 53). */
    OVER_CAP,

    /** A placed filter does not decode under §6.3, so its coverage cannot be read. */
    FILTER_UNREADABLE,
}

/** What [placeFilters] decided: the records a generation places, or why it places none. */
internal sealed interface Placement {
    /** [filters] are the placed records in `index.bin` filename order, each with its name in the generation. */
    class Placed(
        val filters: List<PlacedFilter>,
    ) : Placement
}

/** What [buildIndex] produced. */
internal sealed interface IndexBuild {
    /** [index] is the generation's `index.bin`; [filters] are the placed records in its filename order. */
    class Built(
        val index: ByteArray,
        val filters: List<PlacedFilter>,
    ) : IndexBuild

    /**
     * The record set builds no generation. A sync maps it to `SyncOutcome.FAILED` with [code] at [stage]; a seed loader
     * to `SEED_UNREADABLE` (spec §6.5).
     */
    class Refused(
        val reason: IndexRefusal,
        val detail: String,
        val cause: Throwable? = null,
    ) : IndexBuild,
        Placement {
        /** [SyncStage.INDEX], except for an undecodable filter: a corrupt generation, the `prepare` stage's failure. */
        val stage: SyncStage get() =
            if (reason ==
                IndexRefusal.FILTER_UNREADABLE
            ) {
                SyncStage.PREPARE
            } else {
                SyncStage.INDEX
            }

        /** [DiagnosticCode.INDEX_INCONSISTENT], except for an undecodable filter, which has no code of its own. */
        val code: DiagnosticCode?
            get() = if (reason == IndexRefusal.FILTER_UNREADABLE) null else DiagnosticCode.INDEX_INCONSISTENT

        override fun toString(): String = "Refused($reason: $detail)"
    }
}

/**
 * The records of [channel] a Remote Settings generation places, each under its name in the generation (spec §6.5), or
 * why it places none, read from the records alone, so a sync refuses a record set before any body is fetched: the
 * channel must hold exactly one full filter, as Firefox requires (`RemoteSecuritySettings.sys.mjs` 646-659 at
 * `cac25a6`; DECISIONS 2026-11-08), and every placed delta, ordered by `(effectiveTimestamp, record id)` after the full;
 * each record's file is named by [GenerationNames.derive], and two that map to one name, or one that maps to
 * `index.bin`, `meta.json` or `records.json`, refuse the set.
 */
internal fun placeFilters(
    records: List<FilterRecord>,
    channel: CrliteChannel,
): Placement {
    val wire = channel.wireName
    val placed =
        records
            .filter { it.channel == wire }
            .sortedWith(compareBy<FilterRecord>({ it.incremental }, { it.effectiveTimestamp }, { it.id }))
            .map { PlacedFilter(it, GenerationNames.derive(it.filename)) }
    val fulls = placed.count { it.full }
    if (fulls != 1) return IndexBuild.Refused(IndexRefusal.FULL_COUNT, "$wire has $fulls full filters, not 1")
    collision(placed)?.let { return IndexBuild.Refused(IndexRefusal.NAME_COLLISION, it) }
    return Placement.Placed(placed)
}

/**
 * Builds a Remote Settings generation's `index.bin` (spec §3.2, §6.5 seed archive): the one function a sync and the seed
 * loader share, so its output bytes are frozen per `seedFormat` (1 today) and a seed's shipped index is rebuilt and
 * byte-compared with it.
 *
 * The generation is [placeFilters]' records of [records] for [channel], refused as there before any [body] is read.
 * Then each placed filter's [body] is read once, in order, and its coverage decoded with the clubcard decoders; the
 * index is laid out by [C2spIndex.index] and refused when over [C2spIndex.MAX_BYTES], before a generation directory
 * could be written.
 */
@OptIn(RevoktInternalApi::class)
internal fun buildIndex(
    records: List<FilterRecord>,
    channel: CrliteChannel,
    body: (FilterRecord) -> ByteArray,
): IndexBuild {
    val placed =
        when (val placement = placeFilters(records, channel)) {
            is Placement.Placed -> placement.filters
            is IndexBuild.Refused -> return placement
        }
    val coverage = ArrayList<Pair<String, Map<ByteString, Window>>>(placed.size)
    for (p in placed) {
        val decoded =
            try {
                ClubcardFilters.decode(body(p.record))
            } catch (e: ClubcardFormatException) {
                return IndexBuild.Refused(IndexRefusal.FILTER_UNREADABLE, "${p.record.id}: ${e.message}", e)
            }
        coverage +=
            p.name to
            decoded.universe.logs.entries
                .associate { (log, interval) -> log.bytes to window(interval) }
    }
    val index = C2spIndex.index(coverage)
    val size = C2spIndex.byteSize(index)
    if (size > C2spIndex.MAX_BYTES) {
        return IndexBuild.Refused(IndexRefusal.OVER_CAP, "index.bin would be $size bytes, over ${C2spIndex.MAX_BYTES}")
    }
    return IndexBuild.Built(C2spIndex.write(index), placed)
}

/** The names a generation directory holds beside its filters. */
private val DIRECTORY_FILES = setOf(StoreLayout.INDEX, StoreLayout.META, StoreLayout.RECORDS)

/** Why [placed] cannot share one directory, or null when every name is distinct and none is a directory file. */
private fun collision(placed: List<PlacedFilter>): String? {
    placed.firstOrNull { it.name in DIRECTORY_FILES }?.let { return "${it.record.filename} is named ${it.name}" }
    val byName = placed.groupBy { it.name }.values.firstOrNull { it.size > 1 } ?: return null
    return "${byName.joinToString { it.record.filename }} map to ${byName.first().name}"
}

@OptIn(RevoktInternalApi::class)
private fun window(interval: dev.revokt.clubcard.port.TimestampInterval): Window =
    Window(interval.low.value.toULong(), interval.high.value.toULong())
