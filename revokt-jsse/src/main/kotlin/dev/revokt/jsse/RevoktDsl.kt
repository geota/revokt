// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:JvmName("RevoktDsl")

package dev.revokt.jsse

/**
 * Builds a [Revokt] from a Kotlin block over [Revokt.Builder] (spec §4): `Revokt { channel = CrliteChannel.COMPAT }`.
 * Sugar over `Revokt.builder()…build()`, so it runs the same checks and throws the same exceptions.
 */
@JvmSynthetic
@Suppress("FunctionName", "ktlint:standard:function-naming") // Named as the type it builds, the §4 DSL entry point.
public fun Revokt(block: Revokt.Builder.() -> Unit): Revokt = Revokt.builder().apply(block).build()

/**
 * [Revokt.Builder.awaitData] over a `kotlin.time.Duration`, under the same rule as the `java.time` form: whole
 * milliseconds, truncated toward zero; any negative duration, a sub-millisecond one included, and an infinite one throw
 * [IllegalArgumentException].
 */
@JvmSynthetic
public fun Revokt.Builder.awaitData(d: kotlin.time.Duration): Revokt.Builder {
    require(!d.isNegative()) { "awaitData is non-negative, got $d" }
    require(d.isFinite()) { "awaitData is a deadline, so it is finite, got $d" }
    return awaitDataMillis(d.inWholeMilliseconds)
}
