// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class, dev.revokt.RevoktTestingApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.CrliteQuery
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.EvaluationRequest
import dev.revokt.EvaluatorRig
import dev.revokt.FilterFormat
import dev.revokt.LogLevel
import dev.revokt.RevocationEngine
import dev.revokt.RevoktLifecycle
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.SeedSource
import dev.revokt.Verdict
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.seed.SeedFixture
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.walker.FixtureCert
import dev.revokt.engine.walker.Honest
import dev.revokt.engine.walker.WalkerHarness
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The data side of `Revokt.start()` and `close()` (spec §4 S bullet, §5.1 "Lifecycle" and `close()`, §8 `pending`,
 * §11's 0.2 row) over the seed fixtures of #138: the sole-seed synchronous install and its throws, the loader's start
 * task, the S diagnostics, the cleared reference, and an evaluation end to end over the installed seed. The lifecycle,
 * the lock, the loader thread and the join are `RevoktLifecycleTest`'s (revokt-jsse).
 */
internal class CrliteRuntimeTest : SeedFixture() {
    private val now = ts + hour

    private fun source(seed: Seed): SeedSource {
        // Built once: each build signs afresh, and the runtime opens the archive twice (the header, then the load).
        val bytes = seed.bytes()
        return Counted { bytes }.source
    }

    private fun runtime(
        seed: SeedSource?,
        engine: RevocationEngine = TestEngine(),
        policy: RevoktPolicy = RevoktPolicy.DEFAULT,
        crlite: Boolean = true,
    ): CrliteRuntime =
        CrliteRuntime(
            seed = seed,
            channel = CrliteChannel.COMPAT,
            crlite = crlite,
            fetchingSource = false,
            engine = engine,
            verifier = verifier,
            policy = policy,
            pinnedRootSpkis = pinned,
            storage = storage,
            logger = logger,
        )

    private fun CrliteRuntime.crlite(): DatasetGeneration = assertNotNull(snapshot.snapshot.datasets[Dataset.CRLITE])

    private fun CrliteRuntime.epoch(): Long = snapshot.snapshot.generationEpoch

    private fun assertPendingUntouched(runtime: CrliteRuntime) {
        assertEquals(0, runtime.epoch())
        assertTrue(runtime.crlite().pending)
        assertNull(runtime.crlite().generationId)
    }

    @Test
    fun `the sole-seed configuration installs the seed on the calling thread, before any loader task`() {
        val runtime = runtime(source(Seed()))
        assertPendingUntouched(runtime)
        assertFalse(runtime.startSeed(soleSeed = true, nowMillis = now), "nothing left for the loader")
        val live = runtime.crlite()
        assertNotNull(live.generationId)
        assertTrue(live.fromSeed)
        assertFalse(live.pending, "the install publishes the generation out of pending")
        assertEquals(1, runtime.epoch())
        runtime.startTask(loadSeed = false) { now }
        assertEquals(1, runtime.epoch(), "nothing was pending, so the start task publishes nothing")
    }

    @Test
    fun `the sole-seed configuration throws SEED_UNREADABLE for a seed that does not load, and publishes nothing`() {
        val mutated = Seed().apply { index = ByteArray(2) }
        for (seed in listOf(source(mutated), Counted { byteArrayOf(1, 2) }.source, Counted { null }.source)) {
            val runtime = runtime(seed)
            val e = assertFailsWith<IllegalStateException> { runtime.startSeed(soleSeed = true, nowMillis = now) }
            assertTrue(e.message.orEmpty().startsWith("SEED_UNREADABLE"), e.message)
            assertPendingUntouched(runtime)
            assertNothingInstalled()
        }
    }

    @Test
    fun `fixture g a V4-only engine with the v3 seed throws SEED_UNREADABLE in the sole-seed configuration`() {
        val runtime = runtime(source(Seed()), engine = TestEngine(formats = setOf(FilterFormat.V4)))
        val e = assertFailsWith<IllegalStateException> { runtime.startSeed(soleSeed = true, nowMillis = now) }
        assertTrue(e.message.orEmpty().startsWith("SEED_UNREADABLE"), e.message)
        assertPendingUntouched(runtime)
    }

    @Test
    fun `a seed for another channel throws SEED_CHANNEL_MISMATCH in every configuration`() {
        for (sole in listOf(true, false)) {
            val seed = Seed().apply { header = header + ("channel" to "DEFAULT") }
            val runtime = runtime(source(seed))
            val e = assertFailsWith<IllegalStateException> { runtime.startSeed(soleSeed = sole, nowMillis = now) }
            assertTrue(e.message.orEmpty().startsWith("SEED_CHANNEL_MISMATCH"), e.message)
            assertFalse("DEFAULT" in e.message.orEmpty(), "the message holds none of the seed's contents")
        }
    }

    @Test
    fun `a store read that throws fails the sole-seed start, and outside it leaves the store read unresolved`() {
        storage.failRead = { if (it == updaterKey) IOException("disk") else null }
        val sole = runtime(source(Seed()))
        val e = assertFailsWith<IllegalStateException> { sole.startSeed(soleSeed = true, nowMillis = now) }
        assertTrue(e.message.orEmpty().startsWith("SEED_UNREADABLE"), e.message)
        assertFalse(sole.storeReadUnresolved)
        val loaded = runtime(source(Seed()))
        assertTrue(loaded.startSeed(soleSeed = false, nowMillis = now))
        loaded.startTask(loadSeed = true) { now }
        assertTrue(loaded.storeReadUnresolved, "a throwing read is not 'nothing loaded' (#273 review)")
        assertFalse(loaded.crlite().pending)
        assertNull(loaded.crlite().generationId)
    }

    @Test
    fun `outside the sole-seed configuration the header is read on the caller and the loader's start task installs`() {
        val counted = Seed().bytes().let { Counted { it } }
        val runtime = runtime(counted.source)
        assertTrue(runtime.startSeed(soleSeed = false, nowMillis = now), "the loader loads the seed")
        val header = counted.opens
        assertTrue(header > 0)
        assertPendingUntouched(runtime)
        runtime.startTask(loadSeed = true) { now }
        assertTrue(counted.opens > header, "the load opens the archive again")
        assertNotNull(runtime.crlite().generationId)
        assertFalse(runtime.crlite().pending)
        assertEquals(1, runtime.epoch(), "the install's publish; pending was cleared by it")
    }

    @Test
    fun `a start task that loads nothing clears pending with generationEpoch advanced, so NO_DATA can fire`() {
        for (seed in listOf(source(Seed().apply { index = ByteArray(2) }), Counted { null }.source)) {
            val runtime = runtime(seed)
            val loads = runtime.startSeed(soleSeed = false, nowMillis = now)
            runtime.startTask(loads) { now }
            assertFalse(runtime.crlite().pending)
            assertNull(runtime.crlite().generationId)
            assertEquals(1, runtime.epoch())
        }
    }

    @Test
    fun `an absent seed outside the sole-seed configuration is logged as SEED_UNREADABLE and left to the loader`() {
        val runtime = runtime(Counted { null }.source)
        assertFalse(runtime.startSeed(soleSeed = false, nowMillis = now))
        assertTrue(
            recording.messages.any { (level, message) ->
                level == LogLevel.WARN && "SEED_UNREADABLE" in message
            },
        )
    }

    @Test
    fun `the start task clears pending even when its seed step throws`() {
        val runtime = runtime(seed = null)
        runtime.startTask(loadSeed = true) { now }
        assertFalse(runtime.crlite().pending)
        assertEquals(1, runtime.epoch())
        assertTrue(recording.messages.any { (level, _) -> level == LogLevel.ERROR })
    }

    @Test
    fun `a start task rethrows a fatal error once pending is cleared`() {
        val runtime = runtime(source(Seed()))
        assertFailsWith<OutOfMemoryError> { runtime.startTask(loadSeed = true) { throw OutOfMemoryError("test") } }
        assertFalse(runtime.crlite().pending)
    }

    @Test
    fun `with no CRLite source nothing is pending and the start task publishes nothing`() {
        val runtime = runtime(seed = null, crlite = false)
        assertTrue(
            runtime.snapshot.snapshot.datasets
                .isEmpty(),
        )
        runtime.startTask(loadSeed = false) { now }
        assertEquals(0, runtime.epoch())
    }

    @Test
    fun `SEED_PAST_REJECT_THRESHOLD fires when STALE rejects and the seed is past rejectStaleAfter, logged`() {
        val past = now + 30 * day
        val runtime = runtime(source(Seed()), policy = RevoktPolicy.STRICT)
        assertEquals(
            listOf(),
            runtime.diagnostics(past).filter { it.code == DiagnosticCode.SEED_PAST_REJECT_THRESHOLD },
        )
        runtime.startSeed(soleSeed = false, nowMillis = now)
        runtime.startTask(loadSeed = true) { past }
        val fired = runtime.diagnostics(past).single { it.code == DiagnosticCode.SEED_PAST_REJECT_THRESHOLD }
        assertEquals(Dataset.CRLITE, fired.dataset)
        assertEquals(Rule.STALE, fired.rule)
        assertTrue(recording.messages.any { (level, message) -> level == LogLevel.WARN && "SEED_PAST" in message })
        assertEquals(
            listOf(),
            runtime.diagnostics(ts + 30 * day).filter {
                it.code ==
                    DiagnosticCode.SEED_PAST_REJECT_THRESHOLD
            },
        )
        // A fresh store, as at every 0.2 build: a stored generation not older than the seed would skip it.
        storage.inner.names().forEach(storage.inner::delete)
        val default = runtime(source(Seed()))
        default.startSeed(soleSeed = true, nowMillis = now)
        assertEquals(listOf(), default.diagnostics(past), "DEFAULT allows STALE and has no rejectStaleAfter")
    }

    @Test
    fun `clear publishes no generation and nothing pending at a new epoch`() {
        val runtime = runtime(source(Seed()))
        runtime.startSeed(soleSeed = true, nowMillis = now)
        runtime.clear()
        assertNull(runtime.crlite().generationId)
        assertFalse(runtime.crlite().pending)
        assertEquals(2, runtime.epoch())
    }

    @Test
    fun `end to end the installed seed's engine answer decides the verdict through the published generation`() {
        val h = Honest()
        val indexed = EvaluatorRig.indexed(listOf(h.root.der), WalkerHarness.SNAPSHOT_ID)
        for ((answer, revoked) in listOf(CrliteQueryResult.REVOKED to true, CrliteQueryResult.NOT_REVOKED to false)) {
            storage.inner.names().forEach(storage.inner::delete)
            // The live answer: the Kotlin engine holds the seed's generation, this one answers every query with [answer].
            val engine =
                object : RevocationEngine by TestEngine() {
                    override fun query(q: CrliteQuery): CrliteQueryResult = answer
                }
            val runtime = runtime(source(Seed()), engine = engine)
            var lifecycle = RevoktLifecycle.CREATED
            val evaluator = runtime.evaluator({ lifecycle }, { indexed }, null) { now }
            val request = EvaluationRequest.Builder().verifiedPath(h.path.map(FixtureCert::der)).build()
            assertFailsWith<IllegalStateException> { evaluator.evaluate(request) }
            runtime.startSeed(soleSeed = true, nowMillis = now)
            lifecycle = RevoktLifecycle.STARTED
            val verdict = evaluator.evaluate(request)
            val state = assertNotNull(verdict.dataStates[Dataset.CRLITE])
            assertEquals(runtime.crlite().generationId, state.generationId)
            assertTrue(state.fromSeed)
            if (revoked) {
                assertEquals(Rule.REVOKED, assertIs<Verdict.Rejected>(verdict).rule)
            } else {
                assertIs<Verdict.Accepted>(verdict)
            }
        }
    }

    @Test
    fun `the evaluator throws while no anchor index exists`() {
        val runtime = runtime(source(Seed()))
        runtime.startSeed(soleSeed = true, nowMillis = now)
        val evaluator = runtime.evaluator({ RevoktLifecycle.STARTED }, { null }, null) { now }
        val e =
            assertFailsWith<IllegalStateException> {
                evaluator.evaluate(EvaluationRequest.Builder().presented(listOf(ByteArray(1))).build())
            }
        assertTrue("no candidate index" in e.message.orEmpty())
    }
}
