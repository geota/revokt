// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.FilterFormat
import dev.revokt.GenerationFiles
import dev.revokt.PreparedGeneration
import dev.revokt.RevocationEngine
import dev.revokt.RevoktInternalApi

/** An engine that answers nothing: the builder only reads its [formats] and [name]. */
internal class StubEngine(
    var advertised: Set<FilterFormat> = setOf(FilterFormat.V3, FilterFormat.V4),
    private val equalsEverything: Boolean = false,
) : RevocationEngine {
    var formatReads = 0
        private set

    override val formats: Set<FilterFormat>
        get() {
            formatReads++
            return advertised
        }

    override val name: String get() = "stub"

    override fun prepare(generation: GenerationFiles): PreparedGeneration = error("not used")

    override fun activate(prepared: PreparedGeneration): Unit = error("not used")

    override fun query(q: CrliteQuery): CrliteQueryResult = CrliteQueryResult.NO_DATA

    override val coverageEndMillis: Long? get() = null

    override fun close() = Unit

    // A hostile equals, so the registry is shown to compare by identity.
    override fun equals(other: Any?): Boolean = equalsEverything || this === other

    override fun hashCode(): Int = if (equalsEverything) 0 else System.identityHashCode(this)
}
