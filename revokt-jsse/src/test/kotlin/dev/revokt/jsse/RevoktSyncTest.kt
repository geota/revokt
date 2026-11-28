// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.Enforcement
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLogger
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.SyncResult
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Timeout
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * The public `sync()`, `syncAsync()` and `syncBlocking()` (spec §4 `sync`, §5.1 "Lifecycle", "The sync schedule" and
 * `close()`; test-plan.md "0.3 API rows", `RevoktSyncTest`): `IllegalStateException` outside `STARTED`; a call that
 * arrives while a sync is queued or running, the start task's first sync included, gets that sync's result with one
 * fetch; the persisted backoff honoured; the next poll rescheduled from an explicit sync's outcome as from a scheduled
 * one's; the futures completed on the I/O executor and isolated from each other; `close()` failing a pending one. Every
 * sync here fails or is skipped, as a feed with no signer does; the timer is a test seam that records each delay and runs
 * a task on the real loader thread when the test fires it, and the clock is fake. The equality of two results that
 * differ only in `cause` is `DiagnosticsTest`'s (revokt-engine). Each test times out on a separate thread, since
 * `close()` waits uninterruptibly.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class RevoktSyncTest {
    private val minute = 60_000L
    private val opened = ArrayList<Revokt>()
    private val ioThreads = AtomicInteger()
    private val io: ExecutorService =
        Executors.newCachedThreadPool { Thread(it, "test-io-${ioThreads.incrementAndGet()}").apply { isDaemon = true } }
    private val timer = RecordingTimer()
    private val clock = FakeClock(1_792_587_631_204)
    private val engine = StubEngine()

    @AfterTest
    fun release() {
        opened.forEach { it.close() }
        io.shutdownNow()
    }

    /** Records each scheduled sync with a cancellable handle; a fired task runs on its loader, as the timer's would. */
    private class RecordingTimer : PollTimer {
        class Entry(
            val delayMillis: Long,
            val handle: CompletableFuture<Unit>,
            val loader: ScheduledExecutorService,
            val run: () -> Unit,
        )

        val entries = CopyOnWriteArrayList<Entry>()

        override fun schedule(
            loader: ScheduledExecutorService,
            delayMillis: Long,
            task: Runnable,
        ): Future<*> {
            if (loader.isShutdown) throw RejectedExecutionException("the loader is shut down")
            val handle = CompletableFuture<Unit>()
            entries += Entry(delayMillis, handle, loader) { loader.execute(task) }
            return handle
        }

        /** Waits for the [n]-th schedule (a bound, never a wait for a delay). */
        fun awaitCount(n: Int) {
            repeat(1_000) {
                if (entries.size >= n) return
                Thread.sleep(10)
            }
            error("only ${entries.size} of $n syncs were scheduled")
        }

        /** The schedules not cancelled by a later reschedule. */
        val live: List<Entry> get() = entries.filterNot { it.handle.isCancelled }
    }

    private class FakeClock(
        @Volatile var millis: Long,
    ) : Clock {
        override fun now(): Instant = Instant.fromEpochMilliseconds(millis)
    }

    /**
     * A Remote Settings fetcher answering each request with the next of [answers], then 503; [holdNext] makes the next
     * request wait until [releaseHeld], after counting down [entered].
     */
    private class Feed(
        vararg answers: FetchResponse,
    ) : HttpFetcher {
        private val queue = LinkedBlockingQueue(answers.toList())
        val requests = AtomicInteger()

        /** The latch the next request waits on; taken by that request. */
        @Volatile private var hold: CountDownLatch? = null

        /** The latch [releaseHeld] opens: the held request's. */
        @Volatile private var held: CountDownLatch? = null

        @Volatile var entered = CountDownLatch(1)
            private set

        fun holdNext() {
            entered = CountDownLatch(1)
            held = CountDownLatch(1).also { hold = it }
        }

        fun releaseHeld() {
            held?.countDown()
        }

        override fun fetch(request: FetchRequest): FetchResponse {
            requests.incrementAndGet()
            hold?.let {
                hold = null
                entered.countDown()
                it.await()
            }
            return queue.poll() ?: status(503)
        }

        fun awaitEntered() = check(entered.await(10, TimeUnit.SECONDS)) { "no request was held" }
    }

    private fun Revokt.Builder.open(
        http: HttpFetcher,
        engine: StubEngine = this@RevoktSyncTest.engine,
    ): Revokt {
        pollTimer = timer
        clock = this@RevoktSyncTest.clock
        random = Random(SEED)
        logger = RevoktLogger { _, _, _ -> }
        return remoteSettings(remoteSettings())
            .enforcement(Enforcement.OBSERVE)
            .ioExecutor(io)
            .http(http)
            .revocationEngine(engine)
            .build()
            .also { opened += it }
    }

    /** A started instance over [feed] whose first sync, in the start task, has ended and scheduled the next. */
    private fun started(feed: Feed): Revokt =
        bare().open(feed).also {
            it.start()
            timer.awaitCount(1)
        }

    @Test
    fun `every form throws in CREATED and after close`() {
        val revokt = bare().open(Feed())
        assertFailsWith<IllegalStateException> { revokt.syncBlocking() }
        assertFailsWith<IllegalStateException> { revokt.syncAsync() }
        assertFailsWith<IllegalStateException> { runBlocking { revokt.sync() } }
        revokt.start()
        revokt.close()
        assertFailsWith<IllegalStateException> { revokt.syncBlocking() }
        assertFailsWith<IllegalStateException> { revokt.syncAsync() }
        assertFailsWith<IllegalStateException> { runBlocking { revokt.sync() } }
    }

    @Test
    fun `a sync during the start task's first sync gets its result, after the start task, with one fetch`() {
        val feed = Feed(status(503, "Retry-After" to "120"))
        feed.holdNext()
        val revokt = bare().awaitDataMillis(0).open(feed)
        revokt.start()
        feed.awaitEntered()
        val joined = revokt.syncAsync()
        assertFalse(joined.isDone)
        feed.releaseHeld()
        val result = joined.get(10, TimeUnit.SECONDS)
        assertEquals(SyncOutcome.FAILED, result.outcome)
        assertEquals(SyncFailure.CHANGESET_FETCH, result.failure)
        assertEquals(503, result.httpStatus)
        assertEquals(1, feed.requests.get(), "one fetch: the start task's")
        assertEquals(listOf(2 * minute), timer.entries.map { it.delayMillis }, "the start task's Retry-After")
    }

    @Test
    fun `a sync while the start task's first sync is queued behind the seed load joins it`() {
        val loading = CountDownLatch(1)
        val release = CountDownLatch(1)
        val seed =
            ScriptedSeed({ headerSeed() }) {
                // The second open is the start task's load, on the loader: held while the test calls sync().
                if (Thread.currentThread().name.startsWith("revokt-loader")) {
                    loading.countDown()
                    release.await()
                }
            }
        val feed = Feed()
        val revokt = bare().seed(seed.source).awaitDataMillis(0).open(feed)
        revokt.start()
        assertTrue(loading.await(10, TimeUnit.SECONDS))
        val joined = revokt.syncAsync()
        assertEquals(0, feed.requests.get(), "nothing fetched while the seed loads")
        release.countDown()
        assertEquals(SyncOutcome.FAILED, joined.get(10, TimeUnit.SECONDS).outcome)
        assertEquals(1, feed.requests.get(), "the start task's first sync, and no other")
        timer.awaitCount(1)
        Thread.sleep(QUIET_MILLIS)
        assertEquals(1, feed.requests.get())
        assertEquals(1, timer.entries.size)
    }

    @Test
    fun `calls during a running explicit sync get its result, and no further sync runs`() {
        val feed = Feed(status(503))
        val revokt = started(feed)
        clock.millis += 15 * minute
        feed.holdNext()
        val first = revokt.syncAsync()
        feed.awaitEntered()
        val second = revokt.syncAsync()
        val blocking = CompletableFuture.supplyAsync({ revokt.syncBlocking() }, io)
        feed.releaseHeld()
        val result = first.get(10, TimeUnit.SECONDS)
        assertSame(result, second.get(10, TimeUnit.SECONDS))
        assertSame(result, blocking.get(10, TimeUnit.SECONDS))
        assertEquals(SyncOutcome.FAILED, result.outcome)
        Thread.sleep(QUIET_MILLIS)
        assertEquals(2, feed.requests.get(), "the start task's, then one explicit sync")
        assertEquals(2, timer.entries.size, "one reschedule per sync")
        assertEquals(1, timer.live.size, "one sync scheduled at a time")
    }

    @Test
    fun `a call during a running scheduled sync gets its result`() {
        val feed = Feed(status(503))
        val revokt = started(feed)
        clock.millis += 15 * minute
        feed.holdNext()
        timer.entries.single().run()
        feed.awaitEntered()
        val joined = revokt.syncAsync()
        feed.releaseHeld()
        val result = joined.get(10, TimeUnit.SECONDS)
        assertEquals(SyncFailure.CHANGESET_FETCH, result.failure)
        assertEquals(clock.millis, result.atMillis)
        Thread.sleep(QUIET_MILLIS)
        assertEquals(2, feed.requests.get())
        assertEquals(listOf(15 * minute, 30 * minute), timer.entries.map { it.delayMillis })
    }

    @Test
    fun `a call queued behind a scheduled sync that fired first gets that sync's result`() {
        val feed = Feed(status(503))
        val revokt = started(feed)
        clock.millis += 15 * minute
        // The loader held, so the fired timer's sync and then the call's queue behind each other, in that order.
        val busy = CountDownLatch(1)
        val entry = timer.entries.single()
        entry.loader.execute { busy.await() }
        entry.run()
        val queued = revokt.syncAsync()
        busy.countDown()
        assertEquals(SyncFailure.CHANGESET_FETCH, queued.get(10, TimeUnit.SECONDS).failure)
        Thread.sleep(QUIET_MILLIS)
        assertEquals(
            2,
            feed.requests.get(),
            "the scheduled sync ran as the call's, and the call's own task ran nothing",
        )
        assertEquals(2, timer.entries.size)
    }

    @Test
    fun `under the persisted backoff a sync is SKIPPED with BACKOFF and fetches nothing`() {
        val feed = Feed(status(503))
        val revokt = started(feed)
        clock.millis += 5 * minute
        val result = revokt.syncBlocking()
        assertEquals(SyncOutcome.SKIPPED, result.outcome)
        assertEquals(SyncFailure.BACKOFF, result.failure)
        assertNull(result.httpStatus)
        assertEquals(1, feed.requests.get(), "nothing fetched")
        // The next sync waits the backoff it honoured: 15 min from the first sync, 10 from this one.
        assertEquals(10 * minute, timer.live.single().delayMillis)
    }

    @Test
    fun `the next poll is rescheduled from an explicit sync's outcome as from a scheduled one's`() {
        val answers = arrayOf(status(503, "Retry-After" to "60"), status(503, "Retry-After" to "7200"), status(503))
        val scheduledFeed = Feed(*answers)
        val scheduled = started(scheduledFeed)
        clock.millis += minute
        timer.entries.last().run()
        timer.awaitCount(2)
        val byTimer = timer.entries.map { it.delayMillis }
        scheduled.close()

        val explicitTimer = timer.entries.size
        val explicitFeed = Feed(*answers)
        clock.millis -= minute
        val explicit = bare().open(explicitFeed, StubEngine())
        explicit.start()
        timer.awaitCount(explicitTimer + 1)
        clock.millis += minute
        explicit.syncBlocking()
        val byCall = timer.entries.drop(explicitTimer)
        assertEquals(byTimer, byCall.map { it.delayMillis }, "1 min (Retry-After 60), then 2 h (Retry-After 7200)")
        assertTrue(byCall.first().handle.isCancelled, "the explicit sync's reschedule cancelled the one it found")

        // A superseded timer that fires anyway (its cancel raced) runs nothing and schedules nothing.
        byCall.first().run()
        Thread.sleep(QUIET_MILLIS)
        assertEquals(2, explicitFeed.requests.get())
        assertEquals(explicitTimer + 2, timer.entries.size)
    }

    @Test
    fun `syncAsync completes on the io executor, and a cancel touches only its own future`() {
        val feed = Feed(status(503))
        val revokt = started(feed)
        clock.millis += 15 * minute
        feed.holdNext()
        val cancelled = revokt.syncAsync()
        feed.awaitEntered()
        val other = revokt.syncAsync()
        val completedOn = other.thenApply { Thread.currentThread().name }
        assertTrue(cancelled.cancel(true))
        feed.releaseHeld()
        assertTrue(completedOn.get(10, TimeUnit.SECONDS).startsWith("test-io-"), completedOn.get())
        assertEquals(SyncOutcome.FAILED, other.get().outcome)
        assertEquals(2, feed.requests.get(), "the cancel did not cancel the sync, which ran once")
        // A later call is a sync of its own, unaffected by the cancelled future: under the new backoff, SKIPPED.
        val later = revokt.syncAsync().get(10, TimeUnit.SECONDS)
        assertEquals(SyncFailure.BACKOFF, later.failure)
    }

    @Test
    fun `close with a pending syncAsync completes it exceptionally`() {
        val feed = Feed(status(503))
        val revokt = started(feed)
        clock.millis += 15 * minute
        feed.holdNext()
        val pending = revokt.syncAsync()
        val blocked = CompletableFuture.supplyAsync({ runCatching { revokt.syncBlocking() } }, io)
        feed.awaitEntered()
        revokt.close()
        val failure = assertFailsWith<ExecutionException> { pending.get(10, TimeUnit.SECONDS) }
        assertIs<IllegalStateException>(failure.cause)
        assertEquals("closed", failure.cause?.message)
        assertIs<IllegalStateException>(blocked.get(10, TimeUnit.SECONDS).exceptionOrNull())
        assertFailsWith<IllegalStateException> { revokt.syncAsync() }
        feed.releaseHeld()
    }

    @Test
    fun `the suspend form returns the sync's result`() {
        val feed = Feed(status(503))
        val revokt = started(feed)
        clock.millis += 15 * minute
        val result: SyncResult = runBlocking { revokt.sync() }
        assertEquals(SyncFailure.CHANGESET_FETCH, result.failure)
        assertEquals(2, feed.requests.get())
    }

    @Test
    fun `with no fetching source a sync is UNCHANGED and schedules nothing`() {
        val revokt =
            bare()
                .also {
                    it.pollTimer = timer
                    it.clock = clock
                }.enforcement(Enforcement.OBSERVE)
                .ioExecutor(io)
                .revocationEngine(engine)
                .build()
                .also { opened += it }
        revokt.start()
        val result = revokt.syncBlocking()
        assertEquals(SyncOutcome.UNCHANGED, result.outcome)
        assertEquals(clock.millis, result.atMillis)
        assertNull(result.failure)
        assertNull(result.sourceId)
        assertEquals(0, timer.entries.size)
    }

    @Test
    fun `syncBlocking on the loader thread throws instead of waiting for itself`() {
        val thrown = AtomicReference<Throwable?>()
        val box = AtomicReference<Revokt>()
        val revokt =
            bare()
                .also {
                    it.pollTimer = timer
                    it.clock = clock
                    it.logger =
                        RevoktLogger { _, _, _ ->
                            val self = box.get()
                            if (self != null && Thread.currentThread().name.startsWith("revokt-loader")) {
                                thrown.compareAndSet(null, runCatching { self.syncBlocking() }.exceptionOrNull())
                            }
                        }
                }.remoteSettings(remoteSettings())
                .enforcement(Enforcement.OBSERVE)
                .ioExecutor(io)
                .http(Feed())
                .revocationEngine(engine)
                .build()
                .also { opened += it }
        box.set(revokt)
        revokt.start()
        timer.awaitCount(1)
        val error = assertIs<IllegalStateException>(thrown.get())
        assertTrue("loader thread" in error.message.orEmpty(), error.message)
    }

    private companion object {
        const val SEED = 7

        /** How long a negative check waits for a sync that must not run. */
        const val QUIET_MILLIS = 200L
    }
}

/** A response with [status], [headers] and an empty body. */
private fun status(
    status: Int,
    vararg headers: Pair<String, String>,
): FetchResponse =
    FetchResponse
        .Builder()
        .status(status)
        .apply { headers.forEach { (name, value) -> header(name, value) } }
        .body(ByteArray(0))
        .build()
