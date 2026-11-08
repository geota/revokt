// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.policy.StalenessTable
import java.time.Duration

/**
 * A dataset's staleness thresholds (spec §4, §8), stored as milliseconds with `java.time.Duration` accessors and
 * factories; Kotlin also has `Staleness.of` over `kotlin.time.Duration`. [staleAfterMillis] is the loud threshold only
 * (`DataState.stale`); [rejectStaleAfterMillis] is the only threshold at which `Rule.STALE` fires, and null means it
 * never fires for the dataset. Both are non-negative. A reject threshold below the loud one is accepted here and
 * refused by `RevoktPolicy.Builder.build()` (§4 B check). A value: equality is by both thresholds.
 */
public class Staleness private constructor(
    public val staleAfterMillis: Long,
    public val rejectStaleAfterMillis: Long?,
) {
    init {
        require(staleAfterMillis >= 0) { "staleAfter is non-negative, got $staleAfterMillis ms" }
        require(rejectStaleAfterMillis == null || rejectStaleAfterMillis >= 0) {
            "rejectStaleAfter is non-negative, got $rejectStaleAfterMillis ms"
        }
    }

    public fun staleAfter(): Duration = Duration.ofMillis(staleAfterMillis)

    public fun rejectStaleAfter(): Duration? = rejectStaleAfterMillis?.let(Duration::ofMillis)

    internal fun toTable(): StalenessTable = StalenessTable(staleAfterMillis, rejectStaleAfterMillis)

    override fun equals(other: Any?): Boolean =
        other is Staleness &&
            staleAfterMillis == other.staleAfterMillis &&
            rejectStaleAfterMillis == other.rejectStaleAfterMillis

    override fun hashCode(): Int = 31 * staleAfterMillis.hashCode() + rejectStaleAfterMillis.hashCode()

    override fun toString(): String =
        "Staleness(staleAfterMillis=$staleAfterMillis, rejectStaleAfterMillis=$rejectStaleAfterMillis)"

    public companion object {
        @JvmStatic
        public fun ofMillis(
            staleAfter: Long,
            rejectStaleAfter: Long?,
        ): Staleness = Staleness(staleAfter, rejectStaleAfter)

        /** [staleAfter] and [rejectStaleAfter] in whole milliseconds; `toMillis()` throws on overflow. */
        @JvmStatic
        public fun of(
            staleAfter: Duration,
            rejectStaleAfter: Duration?,
        ): Staleness = ofMillis(staleAfter.toMillis(), rejectStaleAfter?.toMillis())

        internal fun of(table: StalenessTable): Staleness =
            ofMillis(table.staleAfterMillis, table.rejectStaleAfterMillis)
    }
}

/** [staleAfter] and [rejectStaleAfter] in whole milliseconds (Kotlin only; Java uses the `java.time` overload). */
@JvmSynthetic
public fun Staleness.Companion.of(
    staleAfter: kotlin.time.Duration,
    rejectStaleAfter: kotlin.time.Duration?,
): Staleness = ofMillis(staleAfter.inWholeMilliseconds, rejectStaleAfter?.inWholeMilliseconds)
