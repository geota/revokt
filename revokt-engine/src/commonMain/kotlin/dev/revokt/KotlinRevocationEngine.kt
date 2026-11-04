// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.crlite.AtomicInt32
import dev.revokt.engine.crlite.CrliteGeneration
import dev.revokt.engine.crlite.awaitDrain
import kotlinx.coroutines.CompletableDeferred
import kotlin.concurrent.Volatile

/**
 * The default [RevocationEngine] (spec §3.2, §6): the `clubcard` port over every filter of a generation, each consulted
 * by its own coverage. Reads [FilterFormat.V3] and [FilterFormat.V4] as served, detecting each filter's encoding from
 * its prefix (§6.3), and never transcodes. A generation is immutable once prepared, so a query holding the previous
 * generation finishes on it after [activate] swaps it out.
 *
 * [prepare] throws [IllegalArgumentException] on a corrupt generation or a format outside [formats], and
 * [IllegalStateException] after [close]; [activate] throws [IllegalArgumentException] for a prepared generation from
 * another engine, and [IllegalStateException] after [close] or for one already activated or discarded.
 *
 * The internal constructor is the tests' seam (a drain limit, and a hook run before evaluation). It is public in
 * bytecode, so Java can reach it; the hook runs inside evaluation's catch, so even then [query] never throws.
 */
public class KotlinRevocationEngine internal constructor(
    private val drainMillis: Long,
    private val beforeEvaluate: (() -> Unit)?,
) : RevocationEngine {
    public constructor() : this(RevoktLimits.ENGINE_CLOSE_DRAIN, null)

    @Volatile private var live: CrliteGeneration? = null

    /**
     * The number of queries and activations in flight, with [CLOSING] set once close() starts: one word, so nothing
     * slips between the flag and the count.
     */
    private val gate = AtomicInt32(0)

    /** Set by the first close() only, so close() is idempotent. */
    private val closeOnce = AtomicInt32(0)

    @Volatile private var closed = false
    private val drained = CompletableDeferred<Unit>()

    // Read-only (a Java caller cannot clear it), and explicit: a format added to the growable enum is not read here.
    override val formats: Set<FilterFormat> =
        buildSet {
            add(FilterFormat.V3)
            add(FilterFormat.V4)
        }

    private val closing: Boolean get() = gate.get() and CLOSING != 0

    override val coverageEndMillis: Long? get() = live?.coverageEndMillis

    override fun prepare(generation: GenerationFiles): PreparedGeneration {
        check(!closing) { "the engine is closed" }
        // §3.2: other formats are never offered; refuse one anyway, since the enum is growable and formats is not.
        require(generation.format in formats) { "the engine does not read ${generation.format}" }
        return Prepared(this, CrliteGeneration.decode(generation))
    }

    /** Admitted through the gate like a query, so a concurrent close() waits for the swap and then drops it. */
    override fun activate(prepared: PreparedGeneration) {
        require(prepared is Prepared && prepared.engine === this) { "$prepared was not prepared by this engine" }
        val entered = gate.incrementAndGet()
        try {
            check(entered and CLOSING == 0) { "the engine is closed" }
            check(prepared.state.compareAndSet(Prepared.READY, Prepared.ACTIVE)) {
                val why = if (prepared.state.get() == Prepared.ACTIVE) "has already been activated" else "was discarded"
                "${prepared.generationId} $why"
            }
            live = prepared.generation
            // Admitted before close() but stalled past its drain limit: close() has already dropped the generation.
            if (closed) live = null
        } finally {
            leave()
        }
    }

    override fun clear() {
        live = null
    }

    override fun query(q: CrliteQuery): CrliteQueryResult {
        val entered = gate.incrementAndGet()
        val result =
            try {
                answer(entered, q)
            } finally {
                leave()
            }
        return result
    }

    private fun answer(
        entered: Int,
        q: CrliteQuery,
    ): CrliteQueryResult {
        if (entered and CLOSING != 0) return CrliteQueryResult.ENGINE_ERROR
        val result = live?.let { evaluate(it, q, beforeEvaluate) } ?: CrliteQueryResult.NO_DATA
        // A query still running when close() stopped waiting answers ENGINE_ERROR, whatever it found (spec §3.2).
        return if (closed) CrliteQueryResult.ENGINE_ERROR else result
    }

    /** Leaves the gate; exactly CLOSING left means close() has started and nothing is in flight. */
    private fun leave() {
        if (gate.decrementAndGet() == CLOSING) drained.complete(Unit)
    }

    /**
     * Idempotent. Refuses new queries at once, waits for in-flight ones at most [RevoktLimits.ENGINE_CLOSE_DRAIN], then
     * drops the generation. On the JVM an interrupt ends the wait early and stays set on the thread; close() never
     * throws for it, and the engine is closed either way.
     */
    override fun close() {
        if (!closeOnce.compareAndSet(0, 1)) return
        val inFlight = gate.addAndGet(CLOSING) - CLOSING
        try {
            if (inFlight > 0) awaitDrain(drained, drainMillis)
        } finally {
            closed = true
            live = null
        }
    }

    override fun toString(): String = "KotlinRevocationEngine(live=${live?.generationId})"

    private class Prepared(
        val engine: KotlinRevocationEngine,
        val generation: CrliteGeneration,
    ) : PreparedGeneration {
        val state = AtomicInt32(READY)

        override val generationId: String get() = generation.generationId

        override fun query(q: CrliteQuery): CrliteQueryResult =
            if (state.get() == DISCARDED) CrliteQueryResult.ENGINE_ERROR else evaluate(generation, q, null)

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
        /** A bit above any realistic number of concurrent queries. */
        private const val CLOSING = 1 shl 30

        /**
         * The aggregate, mapped so a throw from a filter (or from the test seam's [hook]) is
         * [CrliteQueryResult.ENGINE_ERROR]: query never throws.
         */
        @Suppress("TooGenericExceptionCaught") // The contract is "never throws"; any failure is an engine error.
        fun evaluate(
            generation: CrliteGeneration,
            q: CrliteQuery,
            hook: (() -> Unit)?,
        ): CrliteQueryResult =
            try {
                hook?.invoke()
                generation.query(q)
            } catch (ignored: RuntimeException) {
                CrliteQueryResult.ENGINE_ERROR
            }
    }
}
