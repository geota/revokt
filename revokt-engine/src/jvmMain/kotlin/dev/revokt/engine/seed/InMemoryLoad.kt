// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLogger
import dev.revokt.RevoktStorage
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.generation.GenerationSnapshot
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.update.SnapshotRef

/**
 * One [SeedLoader] load of [seed] as a seed of [channel] under [source]'s pins and collection, into a fresh in-memory
 * store and [engine], with nothing live: the seed job's self-load ([SeedJob]) and the weekly job's re-verification of
 * the last released seed (`seedTimestamp<Channel>` in data/seed, #308). It is the load an app's start runs, so the
 * archive passes exactly when an app would install it: the raw content signature over the x5u chain to the pins, the
 * x5u validity at the signed `<ts>`, the canonical payload, the schema, each attachment's size and SHA-256, and the
 * rebuilt `index.bin`. [nowMillis] is written only into the in-memory store's bookkeeping (`seedInstalledAtMillis`,
 * the backoff clamp); no check reads it, so a seed weeks old loads as it did on its day.
 */
@OptIn(dev.revokt.RevoktInternalApi::class)
internal fun loadInMemory(
    seed: SeedSource,
    channel: CrliteChannel,
    source: MozillaRemoteSettings,
    verifier: SignatureVerifier,
    engine: RevocationEngine,
    logger: RevoktLogger,
    nowMillis: Long,
): SeedLoad {
    val snapshot =
        SnapshotRef(
            GenerationSnapshot(
                0,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false)),
                null,
            ),
        )
    val collection = source.collection(Dataset.CRLITE)?.let { source.bucket + "/" + it }
    return SeedLoader(
        seed,
        StoreLayout(RevoktStorage.inMemory(), Dataset.CRLITE, channel),
        engine,
        snapshot,
        verifier,
        SeedPolicy(source.pinnedRootSpkis, collection, fetchingSource = true),
        logger,
    ).load(nowMillis)
}
