// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The seam a CRLite engine plugs into (spec §3.2), internal to revokt: revokt ships one engine
 * ([KotlinRevocationEngine]), and the CI-only upki engine implements it as the differential test (test-plan.md §9.3).
 * `Revokt` owns the engine, whether defaulted or injected, and closes it last; an instance may be injected into one
 * `Revokt` only. The seam carries [Dataset.CRLITE] only. [prepare] and [activate] are serialised by the caller and throw after [close]; [query] is
 * called concurrently from connection threads and observes either the previous or the new generation, never a mix.
 * [close] is idempotent and waits for in-flight queries at most [RevoktLimits.ENGINE_CLOSE_DRAIN]; a query that
 * returns later answers [CrliteQueryResult.ENGINE_ERROR].
 */
@RevoktInternalApi
public interface RevocationEngine : AutoCloseable {
    /** The formats this engine reads; a generation in any other format is never offered to [prepare]. */
    public val formats: Set<FilterFormat>

    /**
     * The engine's name, `Finding.EngineError.engineName` on every `ENGINE_ERROR` whose producer is the engine (spec
     * §3.2, §4, §5.5), so never null there: by default the class's simple name, or `"anonymous"` when the class has
     * none. It must not throw, and revokt reads it once per instance. On Android under R8, which renames classes, an
     * engine overrides it with a stable string.
     */
    public val name: String get() = this::class.simpleName ?: "anonymous"

    /**
     * Builds an inactive state from [generation] (decode, validate). Throws on a corrupt generation; the engine's live
     * generation is untouched.
     */
    public fun prepare(generation: GenerationFiles): PreparedGeneration

    /**
     * Makes [prepared] the live generation: an atomic swap with respect to concurrent [query] calls. The previous
     * generation is released once its in-flight queries drain. A throw leaves the live generation in place.
     */
    public fun activate(prepared: PreparedGeneration)

    /**
     * [prepare] then [activate], returning the generation id. A convenience: the loader never calls it, since it calls
     * the two as separate §6.5 stages, so a failure names its stage. An [activate] throw closes the prepared state.
     */
    public fun install(generation: GenerationFiles): String =
        prepare(generation).use {
            activate(it)
            it.generationId
        }

    /** Drops the live generation, after which [query] answers [CrliteQueryResult.NO_DATA]. A no-op by default. */
    public fun clear() {}

    /**
     * The only engine input, extracted by revokt's parser from the path-verified leaf and issuer (spec §5.1). Never
     * throws. Precedence, fixed for every engine: after [close], [CrliteQueryResult.ENGINE_ERROR]; with no generation,
     * [CrliteQueryResult.NO_DATA]; with no SCTs, [CrliteQueryResult.NO_SCTS]; else the §6.2 aggregate.
     */
    public fun query(q: CrliteQuery): CrliteQueryResult

    /** The end of the live generation's coverage in epoch milliseconds, or null when the engine cannot tell. */
    public val coverageEndMillis: Long?
}

/**
 * An inactive generation built by [RevocationEngine.prepare] (spec §3.2). [query] answers against it alone, before
 * activation; the cross-engine suite's engine probes use it (test-plan.md §9.3). [close] without
 * [RevocationEngine.activate] discards it; after activation the engine owns it and [close] is a no-op.
 */
@RevoktInternalApi
public interface PreparedGeneration : AutoCloseable {
    public val generationId: String

    public fun query(q: CrliteQuery): CrliteQueryResult
}
