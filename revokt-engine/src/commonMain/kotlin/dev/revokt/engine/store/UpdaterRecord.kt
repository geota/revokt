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

    /** The record in [bytes] with every backoff clamped against [nowMillis], or null when it is malformed. */
    fun read(
        bytes: ByteArray,
        nowMillis: Long,
    ): UpdaterRecord? =
        StoreFields.decodeOrNull(bytes) { f ->
            UpdaterRecord(
                watermarkMillis = f.optLong("watermarkMillis"),
                seedInstalledAtMillis = f.optLong("seedInstalledAtMillis"),
                datasetLastAttemptAtMillis = f.optLong("datasetLastAttemptAtMillis"),
                sources =
                    (f.optObject("sources") ?: f.missing("sources")).members.associate { (id, value) ->
                        id to clamped(source(value as? JsonObject ?: f.wrong(id)), nowMillis)
                    },
            )
        }

    /** [s] with its backoff at most [nowMillis] + `MAX_BACKOFF`, saturating rather than overflowing. */
    private fun clamped(
        s: SourceRecord,
        nowMillis: Long,
    ): SourceRecord {
        val backoff = s.backoffUntilMillis ?: return s
        val cap =
            if (nowMillis >
                Long.MAX_VALUE - RevoktLimits.MAX_BACKOFF
            ) {
                Long.MAX_VALUE
            } else {
                nowMillis + RevoktLimits.MAX_BACKOFF
            }
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
        if (failures !in 0..Int.MAX_VALUE) f.wrong("consecutiveFailures")
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
