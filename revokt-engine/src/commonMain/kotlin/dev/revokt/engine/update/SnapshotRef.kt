// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import kotlin.concurrent.Volatile

/**
 * The one `@Volatile` reference a handshake reads the published [GenerationSnapshot] through (spec §3 "Purity gate").
 * Its only writers are the loader dispatcher and, in the sole-seed synchronous path of §4 S, the `start()` caller
 * before any loader task exists; [publish] is serialised by them, never called from a handshake.
 */
internal class SnapshotRef(
    initial: GenerationSnapshot,
) {
    @Volatile
    var snapshot: GenerationSnapshot = initial
        private set

    fun publish(next: GenerationSnapshot) {
        snapshot = next
    }

    override fun toString(): String = "SnapshotRef($snapshot)"
}
