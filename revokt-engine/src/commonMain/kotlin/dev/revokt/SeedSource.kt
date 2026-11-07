// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.Source
import kotlin.jvm.JvmStatic

/**
 * Where a seed archive comes from (spec §4, §6.5). The loader re-opens it on every start task and on every seed
 * re-check of a sync without a fetching source, so a replaced archive is picked up. Reading the archive is the loader's.
 * The JVM adds `of(SeedOpener)`, `fromResource(path)`, `bundled()` and `JvmSeedSource.fromPath(path)`.
 */
public expect class SeedSource internal constructor(
    opening: SeedOpening,
) {
    /**
     * A fresh stream over the archive, or null when there is none to open; a throw means it is there but unreadable.
     * Okio never appears in a public signature.
     */
    internal fun open(): Source?

    /**
     * This source for [channel]: `bundled()` becomes the channel's `/revokt/seed-<channel>.zip`, or null when the
     * classpath has none (no seed source); any other source is itself. Called when the `Revokt` is built.
     */
    @RevoktInternalApi
    public fun resolve(channel: CrliteChannel): SeedSource?

    public companion object {
        /** No seed: an explicit opt-out of the bundled default. Opens null. */
        @JvmStatic
        public fun none(): SeedSource
    }
}

/** How a [SeedSource] opens its archive; [resolve] binds a channel-dependent source to a channel. */
internal fun interface SeedOpening {
    fun open(): Source?

    fun resolve(channel: CrliteChannel): SeedOpening? = this
}
