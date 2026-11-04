// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.crlite.CrliteGeneration
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * The default [RevocationEngine] (spec §3.2, §6): the `clubcard` port over every filter of a generation, each consulted
 * by its own coverage. Reads [FilterFormat.V3] and [FilterFormat.V4] as served and never transcodes. A generation is
 * immutable once prepared, so a query holding the previous generation finishes on it after [activate] swaps it out.
 *
 * [prepare] throws [IllegalArgumentException] on a corrupt generation or a format outside [formats], and
 * [IllegalStateException] after [close]; [activate] throws [IllegalArgumentException] for a
 * prepared generation from another engine and [IllegalStateException] after [close] or for one already closed or
 * activated.
 */
@OptIn(ExperimentalAtomicApi::class)
public class KotlinRevocationEngine : RevocationEngine {
    private val live = AtomicReference<CrliteGeneration?>(null)
    private val closing = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val inFlight = AtomicInt(0)
    private val drained = CompletableDeferred<Unit>()

    override val formats: Set<FilterFormat> = setOf(FilterFormat.V3, FilterFormat.V4)

    override val coverageEndMillis: Long? get() = live.load()?.coverageEndMillis

    override fun prepare(generation: GenerationFiles): PreparedGeneration {
        check(!closing.load()) { "the engine is closed" }
        require(generation.format in formats) { "the engine does not read ${generation.format}" }
        return Prepared(this, CrliteGeneration.decode(generation))
    }

    override fun activate(prepared: PreparedGeneration) {
        check(!closing.load()) { "the engine is closed" }
        require(prepared is Prepared && prepared.engine === this) { "$prepared was not prepared by this engine" }
        check(prepared.state.compareAndSet(Prepared.READY, Prepared.ACTIVE)) {
            "${prepared.generationId} is already ${if (prepared.state.load() == Prepared.ACTIVE) "active" else "closed"}"
        }
        live.store(prepared.generation)
    }

    override fun clear() {
        live.store(null)
    }

    override fun query(q: CrliteQuery): CrliteQueryResult {
        inFlight.incrementAndFetch()
        try {
            if (closing.load()) return CrliteQueryResult.ENGINE_ERROR
            val generation = live.load() ?: return CrliteQueryResult.NO_DATA
            val result = evaluate(generation, q)
            // A query still running when close() stopped waiting answers ENGINE_ERROR (spec §3.2).
            return if (closed.load()) CrliteQueryResult.ENGINE_ERROR else result
        } finally {
            if (inFlight.decrementAndFetch() == 0 && closing.load()) drained.complete(Unit)
        }
    }

    /**
     * Idempotent. Refuses new queries at once, waits for in-flight ones at most [RevoktLimits.ENGINE_CLOSE_DRAIN], then
     * drops the generation.
     */
    override fun close() {
        if (!closing.compareAndSet(expectedValue = false, newValue = true)) return
        if (inFlight.load() > 0) runBlocking { withTimeoutOrNull(RevoktLimits.ENGINE_CLOSE_DRAIN) { drained.await() } }
        closed.store(true)
        live.store(null)
    }

    override fun toString(): String = "KotlinRevocationEngine(live=${live.load()?.generationId})"

    private class Prepared(
        val engine: KotlinRevocationEngine,
        val generation: CrliteGeneration,
    ) : PreparedGeneration {
        val state = AtomicInt(READY)

        override val generationId: String get() = generation.generationId

        override fun query(q: CrliteQuery): CrliteQueryResult =
            if (state.load() == DISCARDED) CrliteQueryResult.ENGINE_ERROR else evaluate(generation, q)

        /** Discards an unactivated generation; a no-op once it is active. */
        override fun close() {
            state.compareAndSet(READY, DISCARDED)
        }

        override fun toString(): String = "PreparedGeneration($generationId)"

        companion object {
            const val READY = 0
            const val ACTIVE = 1
            const val DISCARDED = 2
        }
    }

    private companion object {
        /** The aggregate, mapped so a throw from a filter is [CrliteQueryResult.ENGINE_ERROR]: query never throws. */
        @Suppress("TooGenericExceptionCaught") // The contract is "never throws"; any failure is an engine error.
        fun evaluate(
            generation: CrliteGeneration,
            q: CrliteQuery,
        ): CrliteQueryResult =
            try {
                generation.query(q)
            } catch (ignored: RuntimeException) {
                CrliteQueryResult.ENGINE_ERROR
            }
    }
}
