// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.runtime

import dev.revokt.LogLevel
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLogger
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.SnapshotRef
import dev.revokt.engine.update.StoredServe
import dev.revokt.engine.update.serveStored
import dev.revokt.engine.update.stored
import dev.revokt.engine.walker.absorb
import dev.revokt.safeLog

/** Which pointed generation [serveChain] served. */
internal enum class StartChain { LIVE, PREVIOUS, NONE }

/**
 * Whether the store's pointer reads and its `live` passes Load's steps 1 and 2 (§4 S bullet, B5): one small file
 * read on the calling thread, no blob. A read that throws is no stored generation here; the seed load then reads the
 * store itself and fails as §6.5 says.
 */
@Suppress("TooGenericExceptionCaught") // The seed load that follows reports the store's failure.
internal fun storedLive(store: StoreLayout?): Boolean =
    try {
        val s = store
        val live = s?.let { (it.pointer() as? StoreRead.Found)?.value?.live }
        s != null && live != null && s.stored(live) is StoreRead.Found
    } catch (t: Throwable) {
        absorb(t)
        false
    }

/**
 * Serves the pointer's `live`, else its `previous`, skipping any in [failed] and adding each that fails to it, logged
 * once ([serveStored]); which one it served. A pointer that does not read serves nothing.
 */
@Suppress("LongParameterList") // The chain's store, clock and failures, and the runtime's engine side.
internal fun serveChain(
    store: StoreLayout,
    nowMillis: () -> Long,
    failed: MutableSet<String>,
    engine: RevocationEngine,
    snapshot: SnapshotRef,
    fetchingSource: Boolean,
    logger: RevoktLogger,
): StartChain {
    val pointer = (store.pointer() as? StoreRead.Found)?.value ?: return StartChain.NONE
    for ((i, name) in listOfNotNull(pointer.live, pointer.previous).withIndex()) {
        if (name in failed) continue
        when (val served = serveStored(name, engine, store, snapshot, fetchingSource, nowMillis(), logger)) {
            is StoredServe.Served -> {
                logger.safeLog(LogLevel.INFO, "${store.root}: loaded the stored generation ${served.generationId}")
                return if (i == 0) StartChain.LIVE else StartChain.PREVIOUS
            }

            is StoredServe.Failed -> {
                failed += name
                logger.safeLog(LogLevel.WARN, "${store.root}: the stored generation $name does not load: $served")
            }
        }
    }
    return StartChain.NONE
}
