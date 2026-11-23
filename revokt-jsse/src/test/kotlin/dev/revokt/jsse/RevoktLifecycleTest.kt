// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.DiagnosticCode
import dev.revokt.Enforcement
import dev.revokt.EvaluationRequest
import dev.revokt.FilterFormat
import dev.revokt.Outcome
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.verify.JcaSignatureVerifier
import org.junit.jupiter.api.Timeout
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * `Revokt.start()`, `close()` and `evaluator` (spec §4, §5.1 "Lifecycle" and `close()`, §11's 0.2 row; §9 data-path
 * (g)'s sole-seed item and (h)'s 0.2 items). The data paths over a signed seed are `CrliteRuntimeTest`'s (revokt-engine),
 * where the seed fixtures live; here a seed is a header only, or bytes that are not a seed. The timeout runs on a
 * separate thread, so a `close()` that waits uninterruptibly fails its test instead of hanging the run.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class RevoktLifecycleTest {
    private val engine = StubEngine()
    private val released = CountDownLatch(1)
    private val opened = ArrayList<Revokt>()

    @AfterTest
    fun release() {
        released.countDown()
        opened.forEach { it.close() }
    }

    /** Built over [with] (an engine goes into one `Revokt` only, so a loop passes a fresh one), closed after the test. */
    private fun Revokt.Builder.open(with: StubEngine = engine): Revokt =
        revocationEngine(with).build().also {
            opened +=
                it
        }

    /** A seed-only builder under [enforcement] whose seed is [seed]. */
    private fun seedOnly(
        seed: SeedSource,
        enforcement: Enforcement = Enforcement.ENFORCE,
    ): Revokt.Builder = bare().seed(seed).enforcement(enforcement)

    private fun request(): EvaluationRequest = EvaluationRequest.Builder().presented(listOf(ByteArray(1))).build()

    private fun loaderThreads(revokt: Revokt): List<Thread> =
        Thread.getAllStackTraces().keys.filter { it.name == "revokt-loader-${revokt.config.sequence}" }

    @Test
    fun `fixture h a seed-only start over an empty trust store succeeds and evaluate throws until an index exists`() {
        val stores = listOf<() -> List<X509Certificate>>({ emptyList() }, { error("store") })
        for (store in stores) {
            val builder = seedOnly(ScriptedSeed({ headerSeed() }).source, Enforcement.OBSERVE)
            builder.platformTrust = FakePlatformTrust(store)
            val revokt = builder.open(StubEngine())
            revokt.start()
            val e = assertFailsWith<IllegalStateException> { revokt.evaluator.evaluate(request()) }
            assertTrue("no candidate index" in e.message.orEmpty(), e.message)
        }
    }

    @Test
    fun `with the default trust store start publishes an index and evaluate returns a verdict`() {
        val revokt = bare().enforcement(Enforcement.OBSERVE).open()
        revokt.start()
        val verdict = revokt.evaluator.evaluate(request())
        assertEquals(dev.revokt.PathStatus.PARSE_FAILED, verdict.path.status, "$verdict")
    }

    @Test
    fun `fixture h evaluate throws in CREATED and after close`() {
        val revokt = bare().enforcement(Enforcement.OBSERVE).open()
        val created = assertFailsWith<IllegalStateException> { revokt.evaluator.evaluate(request()) }
        assertTrue("CREATED" in created.message.orEmpty(), created.message)
        revokt.start()
        revokt.close()
        val closed = assertFailsWith<IllegalStateException> { revokt.evaluator.evaluate(request()) }
        assertTrue("CLOSED" in closed.message.orEmpty(), closed.message)
    }

    @Test
    fun `fixture g a V4-only engine with the v3 seed and no fetching source throws SEED_UNREADABLE when sole`() {
        engine.advertised = setOf(FilterFormat.V4)
        val revokt = seedOnly(ScriptedSeed({ headerSeed(filterFormat = "V3") }).source).open()
        assertTrue(revokt.validate(Enforcement.ENFORCE).none { it.code == DiagnosticCode.FORMAT_UNSUPPORTED })
        repeat(2) {
            val e = assertFailsWith<IllegalStateException> { revokt.start() }
            assertTrue(e.message.orEmpty().startsWith("SEED_UNREADABLE"), e.message)
        }
        assertTrue(loaderThreads(revokt).isEmpty(), "a start() that throws starts no loader")
        val created = assertFailsWith<IllegalStateException> { revokt.evaluator.evaluate(request()) }
        assertTrue("CREATED" in created.message.orEmpty())
        assertEquals(0, engine.closes)
    }

    @Test
    fun `the sole-seed configuration throws SEED_UNREADABLE for bytes that are not a seed and for no archive`() {
        for (bytes in listOf<() -> ByteArray?>({ byteArrayOf(1, 2, 3) }, { null }, { headerSeed() })) {
            val revokt = seedOnly(ScriptedSeed(bytes).source).open(StubEngine())
            val e = assertFailsWith<IllegalStateException> { revokt.start() }
            assertTrue(e.message.orEmpty().startsWith("SEED_UNREADABLE"), e.message)
            assertFalse("1792587631204" in e.message.orEmpty(), "the message holds none of the seed's contents")
        }
    }

    @Test
    fun `outside the sole-seed configuration an unreadable or absent seed is logged and start succeeds`() {
        for (enforcement in listOf(Enforcement.OBSERVE, Enforcement.OFF)) {
            val seed = ScriptedSeed({ byteArrayOf(1, 2, 3) })
            val revokt = seedOnly(seed.source, enforcement).open(StubEngine())
            revokt.start()
            assertEquals(1, seed.opens, "the header read ended the load; the loader does not try again")
        }
        val allowing =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.NO_DATA, Outcome.ALLOW)
                .build()
        val revokt = seedOnly(ScriptedSeed({ null }).source).policy(allowing).open()
        revokt.start()
    }

    @Test
    fun `a seed for another channel throws SEED_CHANNEL_MISMATCH under every enforcement`() {
        for (enforcement in Enforcement.entries) {
            val revokt =
                seedOnly(
                    ScriptedSeed({ headerSeed(channel = "DEFAULT") }).source,
                    enforcement,
                ).open(StubEngine())
            val e = assertFailsWith<IllegalStateException> { revokt.start() }
            assertTrue(e.message.orEmpty().startsWith("SEED_CHANNEL_MISMATCH"), e.message)
            assertTrue(loaderThreads(revokt).isEmpty())
        }
    }

    @Test
    fun `a V4-only engine with remote settings under ENFORCE throws FORMAT_UNSUPPORTED from start`() {
        engine.advertised = setOf(FilterFormat.V4)
        val revokt = bare().remoteSettings(remoteSettings()).open()
        val e = assertFailsWith<IllegalStateException> { revokt.start() }
        assertTrue("FORMAT_UNSUPPORTED" in e.message.orEmpty(), e.message)
        assertTrue(loaderThreads(revokt).isEmpty())
    }

    @Test
    fun `start and close are idempotent, start after close throws, and the engine closes once`() {
        val revokt = bare().enforcement(Enforcement.OBSERVE).open()
        val first = revokt.start()
        assertEquals(first, revokt.start())
        revokt.close()
        revokt.close()
        assertEquals(1, engine.closes)
        val e = assertFailsWith<IllegalStateException> { revokt.start() }
        assertTrue("closed" in e.message.orEmpty())
    }

    @Test
    fun `close in CREATED closes the engine, and start then throws`() {
        val revokt = bare().enforcement(Enforcement.OBSERVE).open()
        revokt.close()
        assertEquals(1, engine.closes)
        assertFailsWith<IllegalStateException> { revokt.start() }
        assertTrue(loaderThreads(revokt).isEmpty())
    }

    @Test
    fun `the start task runs on one daemon loader thread named by the build sequence`() {
        val seed = ScriptedSeed({ headerSeed() })
        val revokt = seedOnly(seed.source, Enforcement.OBSERVE).open()
        val caller = Thread.currentThread()
        revokt.start()
        val loader = assertNotNull(seed.openedOn)
        assertTrue(seed.opens >= 2, "the header on the caller, then the load on the loader")
        assertTrue(loader !== caller)
        assertEquals("revokt-loader-${revokt.config.sequence}", loader.name)
        assertTrue(loader.isDaemon)
        val next = bare().enforcement(Enforcement.OBSERVE).revocationEngine(StubEngine()).build()
        assertEquals(revokt.config.sequence + 1, next.config.sequence)
        next.close()
    }

    @Test
    fun `close on the loader thread throws, before doing anything`() {
        val thrown = AtomicReference<Throwable>()
        lateinit var revokt: Revokt
        val seed =
            ScriptedSeed({ headerSeed() }) {
                if (Thread.currentThread().name.startsWith("revokt-loader-")) {
                    thrown.set(runCatching { revokt.close() }.exceptionOrNull())
                }
            }
        revokt = seedOnly(seed.source, Enforcement.OBSERVE).open()
        revokt.start()
        val e = assertNotNull(thrown.get())
        assertTrue(e is IllegalStateException && "loader thread" in e.message.orEmpty(), "$e")
        assertEquals(0, engine.closes)
        revokt.close()
        assertEquals(1, engine.closes)
    }

    @Test
    fun `start and close from the start thread's seed step throw instead of re-entering`() {
        val thrown = ArrayList<Throwable?>()
        lateinit var revokt: Revokt
        val seed =
            ScriptedSeed({ headerSeed() }) {
                thrown += runCatching { revokt.start() }.exceptionOrNull()
                thrown += runCatching { revokt.close() }.exceptionOrNull()
            }
        revokt = seedOnly(seed.source).open()
        assertFailsWith<IllegalStateException> { revokt.start() }
        assertTrue(thrown.size >= 2, "the header read and the load each called back")
        for (e in thrown) {
            assertTrue(e is IllegalStateException && "re-entrant" in e.message.orEmpty(), "$e")
        }
        assertEquals(0, engine.closes, "the re-entrant close() closed nothing")
    }

    /** A seed-only instance under OBSERVE whose loader blocks in the seed's open until [released]. */
    private fun blocked(awaitMillis: Long): Pair<Revokt, CountDownLatch> {
        val entered = CountDownLatch(1)
        val seed =
            ScriptedSeed({ headerSeed() }) {
                if (Thread.currentThread().name.startsWith("revokt-loader-")) {
                    entered.countDown()
                    // Uninterruptibly, as an install in progress is: close()'s cancel does not cut it short.
                    var interrupted = false
                    while (true) {
                        try {
                            released.await()
                            break
                        } catch (e: InterruptedException) {
                            interrupted = true
                        }
                    }
                    if (interrupted) Thread.currentThread().interrupt()
                }
            }
        return seedOnly(seed.source, Enforcement.OBSERVE).awaitDataMillis(awaitMillis).open() to entered
    }

    @Test
    fun `start waits for the start task up to awaitData, then returns STARTED`() {
        val (revokt, entered) = blocked(300)
        val began = System.nanoTime()
        revokt.start()
        val waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began)
        assertTrue(entered.await(0, TimeUnit.SECONDS), "the task is still running")
        assertTrue(waited >= 250, "waited $waited ms")
    }

    @Test
    fun `awaitData 0 returns at once and a second start does not wait`() {
        val (revokt, _) = blocked(0)
        val began = System.nanoTime()
        revokt.start()
        revokt.start()
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - began) < 1_000)
    }

    @Test
    fun `a start interrupted in its wait returns STARTED with the interrupt kept`() {
        val (revokt, entered) = blocked(10_000)
        val outcome = AtomicReference<Pair<Boolean, Throwable?>>()
        val starter =
            thread {
                val e = runCatching { revokt.start() }.exceptionOrNull()
                outcome.set(Thread.currentThread().isInterrupted to e)
            }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        starter.interrupt()
        starter.join(5_000)
        assertEquals(true to null, outcome.get())
    }

    @Test
    fun `close during the start wait lets start return, and awaits the in-flight task before closing the engine`() {
        val (revokt, entered) = blocked(10_000)
        val started = CountDownLatch(1)
        val starter =
            thread {
                revokt.start()
                started.countDown()
            }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val closer = thread { revokt.close() }
        assertTrue(started.await(5, TimeUnit.SECONDS), "start() returned once close() flipped")
        closer.join(300)
        assertTrue(closer.isAlive, "close() waits for the in-flight task")
        assertEquals(0, engine.closes)
        closer.interrupt()
        closer.join(300)
        assertTrue(closer.isAlive, "an interrupt does not cut close()'s wait short")
        released.countDown()
        closer.join(5_000)
        starter.join(5_000)
        assertFalse(closer.isAlive)
        assertEquals(1, engine.closes)
    }

    @Test
    fun `a second close waits for the first to finish`() {
        val (revokt, entered) = blocked(0)
        revokt.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val first = thread { revokt.close() }
        first.join(300)
        assertTrue(first.isAlive, "the first close() waits for the in-flight task")
        val second = thread { revokt.close() }
        second.join(300)
        assertTrue(second.isAlive, "the second close() waits")
        released.countDown()
        second.join(5_000)
        first.join(5_000)
        assertFalse(second.isAlive)
        assertEquals(1, engine.closes)
    }

    @Test
    fun `close cancels a start task that is waiting, interrupting it, and returns once it ended`() {
        val entered = CountDownLatch(1)
        val interrupted = AtomicReference<Boolean>()
        val seed =
            ScriptedSeed({ headerSeed() }) {
                // The loader's first open only: the archive is opened again by the same load, which then goes on.
                if (Thread.currentThread().name.startsWith("revokt-loader-") && interrupted.get() == null) {
                    entered.countDown()
                    interrupted.set(runCatching { released.await() }.exceptionOrNull() is InterruptedException)
                }
            }
        val revokt = seedOnly(seed.source, Enforcement.OBSERVE).awaitDataMillis(0).open()
        revokt.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        revokt.close()
        assertEquals(true, interrupted.get())
        assertEquals(1, engine.closes)
    }

    @Test
    fun `an engine close throw is rethrown after every other step, and a second close is a no-op`() {
        val (revokt, entered) = blocked(0)
        revokt.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        released.countDown()
        engine.closeThrows = IllegalStateException("engine")
        val e = assertFailsWith<IllegalStateException> { revokt.close() }
        assertEquals("engine", e.message)
        val closed = assertFailsWith<IllegalStateException> { revokt.evaluator.evaluate(request()) }
        assertTrue("CLOSED" in closed.message.orEmpty())
        revokt.close()
        assertEquals(1, engine.closes)
    }

    @Test
    fun `use attaches an engine close throw as suppressed to the body's own`() {
        engine.closeThrows = IllegalStateException("engine")
        val revokt = bare().enforcement(Enforcement.OBSERVE).revocationEngine(engine).build()
        val body =
            assertFailsWith<IllegalArgumentException> {
                revokt.use {
                    it.start()
                    throw IllegalArgumentException("body")
                }
            }
        assertEquals("engine", body.suppressed.single().message)
        assertEquals(1, engine.closes)
    }

    @Test
    fun `a validate ERROR throws from start, leaves CREATED and starts no loader`() {
        val revokt = bare().open()
        repeat(2) {
            val e = assertFailsWith<IllegalStateException> { revokt.start() }
            assertTrue("NO_DATA_REJECTS_WITHOUT_LOCAL_DATA" in e.message.orEmpty(), e.message)
        }
        assertTrue(loaderThreads(revokt).isEmpty())
    }

    @Test
    fun `start returns validate's WARNINGs then the S diagnostics`() {
        val probe = setOf("1.2.840.10045.4.3.2")
        val verifier =
            object : SignatureVerifier by JcaSignatureVerifier() {
                override fun unsupportedOids(): Set<String> = probe
            }
        val builder = bare().enforcement(Enforcement.OBSERVE).policy(RevoktPolicy.STRICT).signatureVerifier(verifier)
        val revokt = builder.open()
        val expected =
            revokt.validate(Enforcement.OBSERVE).map { it.code } + DiagnosticCode.UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP
        assertEquals(expected, revokt.start().map { it.code })
        assertTrue(revokt.validate(Enforcement.OBSERVE).isNotEmpty())
    }

    @Test
    fun `a verifier probe without a classical gap and DEFAULT give no S diagnostic`() {
        val revokt = bare().enforcement(Enforcement.OBSERVE).open()
        assertEquals(revokt.validate(Enforcement.OBSERVE), revokt.start())
    }
}
