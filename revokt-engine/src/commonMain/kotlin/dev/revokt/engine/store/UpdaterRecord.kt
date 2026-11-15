// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.RevoktLimits
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.json.JsonValue
import okio.ByteString
import okio.ByteString.Companion.decodeHex

/**
 * A dataset and channel's `updater.json` (spec §6.5): the rollback watermark, [seedInstalledAtMillis] and
 * [datasetLastAttemptAtMillis] once per dataset and channel, outside the per-source map [sources], which is keyed by
 * each source's stable id.
 */
internal data class UpdaterRecord(
    val watermarkMillis: Long? = null,
    val seedInstalledAtMillis: Long? = null,
    val datasetLastAttemptAtMillis: Long? = null,
    val sources: Map<String, SourceRecord> = emptyMap(),
)

/**
 * A decoded `updater.json`: its [record], the ids of the source entries that did not decode and were dropped, and
 * whether a `sources` member was there but not an object ([sourcesMalformed], read as no sources), each a store failure
 * for the caller to count (spec §6.5, `storeFailures`).
 */
internal data class UpdaterRead(
    val record: UpdaterRecord,
    val droppedSources: Set<String> = emptySet(),
    val sourcesMalformed: Boolean = false,
) {
    /** What reading the file costs `storeFailures`: one per dropped entry, and one for a malformed `sources`. */
    val storeFailures: Int get() = droppedSources.size + if (sourcesMalformed) 1 else 0
}

/** One source's entry in [UpdaterRecord.sources] (spec §6.5). */
internal data class SourceRecord(
    val lastVerifiedLastModified: Long? = null,
    val lastVerifiedAtMillis: Long? = null,
    val lastAttemptAtMillis: Long? = null,
    val backoffUntilMillis: Long? = null,
    val consecutiveFailures: Int = 0,
    val feedHostBlock: FeedHostBlock? = null,
) {
    init {
        require(consecutiveFailures >= 0) { "consecutiveFailures is negative" }
    }
}

/** The §8 signed-source hold: when it began and the SHA-256 of each chain that hit. */
internal data class FeedHostBlock(
    val sinceMillis: Long,
    val chainSha256s: Set<ByteString>,
) {
    init {
        require(chainSha256s.all { it.size == SHA256_BYTES }) { "a chain hash is not a SHA-256" }
    }
}

/**
 * `updater.json`'s encoding. `backoffUntilMillis` is clamped to `now + MAX_BACKOFF` on write and again on read, so a
 * clock that was far ahead at write time cannot leave a years-long backoff.
 */
internal object UpdaterJson {
    fun write(
        record: UpdaterRecord,
        nowMillis: Long,
    ): ByteArray =
        StoreFields.encode(
            "watermarkMillis" to StoreFields.long(record.watermarkMillis),
            "seedInstalledAtMillis" to StoreFields.long(record.seedInstalledAtMillis),
            "datasetLastAttemptAtMillis" to StoreFields.long(record.datasetLastAttemptAtMillis),
            "sources" to
                StoreFields.objectOf(record.sources.map { (id, s) -> id to source(clamped(s, nowMillis)) }),
        )

    /**
     * The record in [bytes] with every backoff clamped against [nowMillis], or null when the file or a dataset-level
     * member is malformed. The dataset-level members are read independently of the per-source map: a source entry that
     * does not decode is dropped alone and its id reported in [UpdaterRead.droppedSources], and a `sources` that is
     * absent or not an object reads as no sources (the latter reported as [UpdaterRead.sourcesMalformed]), so a bad
     * entry never costs the rollback watermark (§10).
     */
    fun read(
        bytes: ByteArray,
        nowMillis: Long,
    ): UpdaterRead? =
        StoreFields.decodeOrNull(bytes) { f ->
            val sources = LinkedHashMap<String, SourceRecord>()
            val dropped = LinkedHashSet<String>()
            for ((id, value) in f.objectOrNull("sources")?.members.orEmpty()) {
                val source = sourceOrNull(value)
                if (source == null) dropped += id else sources[id] = clamped(source, nowMillis)
            }
            val record =
                UpdaterRecord(
                    watermarkMillis = f.optLong("watermarkMillis"),
                    seedInstalledAtMillis = f.optLong("seedInstalledAtMillis"),
                    datasetLastAttemptAtMillis = f.optLong("datasetLastAttemptAtMillis"),
                    sources = sources,
                )
            UpdaterRead(record, dropped, sourcesMalformed = f.presentNotObject("sources"))
        }

    /** The source entry [value], or null when it does not decode. */
    private fun sourceOrNull(value: JsonValue): SourceRecord? =
        try {
            (value as? JsonObject)?.let(::source)
        } catch (ignored: MalformedStoreFileException) {
            null
        } catch (ignored: IllegalArgumentException) {
            null
        }

    /** The last `now` at which `now + MAX_BACKOFF` does not overflow. */
    private val LAST_UNSATURATED: Long = Long.MAX_VALUE - RevoktLimits.MAX_BACKOFF

    /** [s] with its backoff at most [nowMillis] + `MAX_BACKOFF`, saturating rather than overflowing. */
    private fun clamped(
        s: SourceRecord,
        nowMillis: Long,
    ): SourceRecord {
        val backoff = s.backoffUntilMillis ?: return s
        val cap = if (nowMillis > LAST_UNSATURATED) Long.MAX_VALUE else nowMillis + RevoktLimits.MAX_BACKOFF
        return if (backoff <= cap) s else s.copy(backoffUntilMillis = cap)
    }

    private fun source(s: SourceRecord): JsonObject =
        StoreFields.objectOf(
            listOf(
                "lastVerifiedLastModified" to StoreFields.long(s.lastVerifiedLastModified),
                "lastVerifiedAtMillis" to StoreFields.long(s.lastVerifiedAtMillis),
                "lastAttemptAtMillis" to StoreFields.long(s.lastAttemptAtMillis),
                "backoffUntilMillis" to StoreFields.long(s.backoffUntilMillis),
                "consecutiveFailures" to StoreFields.long(s.consecutiveFailures.toLong()),
                "feedHostBlock" to s.feedHostBlock?.let(::feedHostBlock),
            ),
        )

    private fun feedHostBlock(b: FeedHostBlock): JsonObject =
        StoreFields.objectOf(
            listOf(
                "sinceMillis" to StoreFields.long(b.sinceMillis),
                "chainSha256s" to
                    JsonArray(
                        b.chainSha256s
                            .map { it.hex() }
                            .sorted()
                            .map(::JsonString),
                    ),
            ),
        )

    private fun source(obj: JsonObject): SourceRecord {
        val f = StoreFields(obj)
        val failures = f.optLong("consecutiveFailures") ?: 0
        // In Int range here; a negative count is SourceRecord's own check.
        if (failures !in Int.MIN_VALUE..Int.MAX_VALUE) f.wrong("consecutiveFailures")
        return SourceRecord(
            lastVerifiedLastModified = f.optLong("lastVerifiedLastModified"),
            lastVerifiedAtMillis = f.optLong("lastVerifiedAtMillis"),
            lastAttemptAtMillis = f.optLong("lastAttemptAtMillis"),
            backoffUntilMillis = f.optLong("backoffUntilMillis"),
            consecutiveFailures = failures.toInt(),
            feedHostBlock = f.optObject("feedHostBlock")?.let(::feedHostBlock),
        )
    }

    private fun feedHostBlock(f: StoreFields): FeedHostBlock =
        FeedHostBlock(
            sinceMillis = f.long("sinceMillis"),
            chainSha256s =
                (f.optArray("chainSha256s") ?: f.missing("chainSha256s")).items.mapTo(LinkedHashSet()) { v: JsonValue ->
                    val hex = (v as? JsonString)?.value
                    if (hex == null || !GenerationNames.isSha256Hex(hex)) f.wrong("chainSha256s")
                    hex.decodeHex()
                },
        )
}
