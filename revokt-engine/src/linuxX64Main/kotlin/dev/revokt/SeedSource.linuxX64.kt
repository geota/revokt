// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.Source

// The linuxX64 purity gate only compiles (spec §3): the common members over the opening, without the JVM factories.
public actual class SeedSource internal actual constructor(
    private val opening: SeedOpening,
) {
    internal actual fun open(): Source? = opening.open()

    @RevoktInternalApi
    public actual fun resolve(channel: CrliteChannel): SeedSource? =
        opening.resolve(channel)?.let { if (it === opening) this else SeedSource(it) }

    public actual companion object {
        public actual fun none(): SeedSource = SeedSource { null }
    }
}
