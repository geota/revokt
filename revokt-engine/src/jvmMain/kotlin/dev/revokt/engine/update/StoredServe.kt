// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.Freshness
import dev.revokt.LogLevel
import dev.revokt.PreparedGeneration
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLogger
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.walker.absorb
import dev.revokt.engine.walker.isFatal
import dev.revokt.engine.walker.restoreInterrupt
import dev.revokt.safeLog

/** How [serveStored] ended: [Served], or [Failed] at a load or an engine step, which the caller counts once. */
internal sealed interface StoredServe {
    /** The generation file [name] is live in the engine and published as [generationId]. */
    class Served(
        val name: String,
        val generationId: String,
        val timestampMillis: Long,
    ) : StoredServe

    class Failed(
        val detail: String,
        val cause: Throwable? = null,
    ) : StoredServe {
        override fun toString(): String = "Failed($detail)"
    }
}

/**
 * Serves the stored generation file [name] (spec §5.1 "one loader task", §6.5 crash recovery): Load, steps 1 to 4, then
 * `engine.prepare` → `engine.activate` → publish the snapshot (`generationEpoch++`), under its file name. Nothing is
 * written to the store. A seed's generation is published `fromSeed`, with its stored `seedFormat`, and its §8 `STALE`
 * gate read from `updater.json` (open with no [fetchingSource], or once `datasetLastAttemptAtMillis ≥
 * seedInstalledAtMillis`). A failure leaves the engine and the snapshot as they were; a throw from the store's reads
 * propagates, since the caller tells a read that threw from one that found nothing (§7.1). Every other throwable from the
 * engine is caught, an `OutOfMemoryError` included, so nothing escapes the loader.
 */
@OptIn(RevoktInternalApi::class)
@Suppress("TooGenericExceptionCaught") // §6.5: every loader task catches Throwable from the engine.
internal fun serveStored(
    name: String,
    engine: RevocationEngine,
    store: StoreLayout,
    snapshot: SnapshotRef,
    fetchingSource: Boolean,
    nowMillis: Long,
    logger: RevoktLogger,
): StoredServe {
    val loaded =
        when (val load = store.load(name)) {
            is GenerationLoad.Failed -> return StoredServe.Failed(load.detail)
            is GenerationLoad.Loaded -> load.value
        }
    val generation = loaded.generation
    val file = generation.file
    val fromSeed = file.freshness == Freshness.SEED_SIGNED_TIME
    val record = (store.updater(nowMillis) as? StoreRead.Found)?.value?.record
    val gateOpen =
        !fromSeed || !fetchingSource ||
            (record?.datasetLastAttemptAtMillis ?: Long.MIN_VALUE) >= (record?.seedInstalledAtMillis ?: Long.MAX_VALUE)
    var prepared: PreparedGeneration? = null
    try {
        val p = engine.prepare(loaded.files).also { prepared = it }
        engine.activate(p)
    } catch (t: Throwable) {
        restoreInterrupt(t)
        try {
            prepared?.close()
        } catch (c: Throwable) {
            absorb(c)
        }
        if (isFatal(t)) logger.safeLog(LogLevel.ERROR, "${store.root}: the engine failed on $name", t)
        return StoredServe.Failed("the engine refused $name: $t", t)
    }
    val current = snapshot.snapshot
    val served =
        DatasetGeneration(
            generationId = generation.generationId,
            freshness = file.freshness,
            fromSeed = fromSeed,
            sourceTimestampMillis = generation.timestampMillis,
            seedFormat = file.seedFormat,
            pending = false,
            staleGateOpen = gateOpen,
            generationFile = name,
        )
    val coverageEnd =
        try {
            engine.coverageEndMillis
        } catch (t: Throwable) {
            absorb(t)
            null
        }
    snapshot.publish(
        GenerationSnapshot(current.generationEpoch + 1, current.datasets + (file.dataset to served), coverageEnd),
    )
    return StoredServe.Served(name, generation.generationId, generation.timestampMillis)
}
