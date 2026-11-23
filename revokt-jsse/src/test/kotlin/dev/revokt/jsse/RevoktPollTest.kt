// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.Enforcement
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.RevoktInternalApi
import org.junit.jupiter.api.Timeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * #147's loader schedule in the JVM binding (spec §5.1 "Lifecycle" and `close()`, §7.1, §11's 0.2 row): the first sync
 * in the start task, each next sync waited on the loader's timer with the delay the runtime computed (60 s to 24 h),
 * nothing run after `close()`, a sync in flight cancelled by `close()`, and the schedule kept through a fatal error.
 * The timer is a test seam that records each delay and runs the task on the real loader thread when the test fires
 * it, and the clock is fake, so no test waits real time for a sync. The delays of syncs that did not fail, and the
 * data paths over a signed feed, are `CrliteRuntimePollTest`'s and `PollScheduleTest`'s (revokt-engine), where the
 * signed fixtures live; here every sync fails, as a feed with no signer does. Each `close()` test times out on a
 * separate thread, since `close()` waits uninterruptibly.
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class RevoktPollTest {
    private val minute = 60_000L
    private val hour = 60 * minute
    private val opened = ArrayList<Revokt>()
    private val io: ExecutorService = Executors.newCachedThreadPool { Thread(it).apply { isDaemon = true } }
    private val timer = ManualTimer()
    private val clock = FakeClock(1_792_587_631_204)
    private val engine = StubEngine()

    @AfterTest
    fun release() {
        opened.forEach { it.close() }
        io.shutdownNow()
    }

    /** Records each scheduled sync; [fire] runs the oldest on its loader, as the loader's timer would at its delay. */
    private class ManualTimer : PollTimer {
        private val scheduled = LinkedBlockingQueue<Pair<Long, () -> Unit>>()
        val count = AtomicInteger()

        /** As the loader's timer does; false records a schedule after the shutdown too, to see that none is asked. */
        @Volatile var rejectWhenShutdown = true

        override fun schedule(
            loader: ScheduledExecutorService,
            delayMillis: Long,
            task: Runnable,
        ) {
            if (rejectWhenShutdown && loader.isShutdown) throw RejectedExecutionException("the loader is shut down")
            count.incrementAndGet()
            scheduled.put(delayMillis to { loader.execute(task) })
        }

        /** The next delay requested, waiting for the loader to request it (a bound, never a wait for the delay). */
        fun next(): Long = checkNotNull(scheduled.peekWait()) { "no sync was scheduled" }.first

        /** Runs the oldest scheduled sync on its loader. */
        fun fire() = checkNotNull(scheduled.poll()) { "nothing to fire" }.second()

        val queued: Int get() = scheduled.size

        private fun <T> LinkedBlockingQueue<T>.peekWait(): T? {
            repeat(1_000) {
                peek()?.let { return it }
                Thread.sleep(10)
            }
            return null
        }
    }

    private class FakeClock(
        @Volatile var millis: Long,
    ) : Clock {
        @Volatile var throwOnce: Throwable? = null

        override fun now(): Instant {
            throwOnce?.let {
                throwOnce = null
                throw it
            }
            return Instant.fromEpochMilliseconds(millis)
        }
    }

    /** A Remote Settings fetcher that answers each `monitor/changes` request with the next of [answers]. */
    private class Feed(
        vararg answers: FetchResponse,
    ) : HttpFetcher {
        private val queue = LinkedBlockingQueue(answers.toList())
        val requests = AtomicInteger()

        override fun fetch(request: FetchRequest): FetchResponse {
            requests.incrementAndGet()
            return queue.poll() ?: status(503)
        }
    }

    private fun Revokt.Builder.open(http: HttpFetcher): Revokt {
        pollTimer = timer
        clock = this@RevoktPollTest.clock
        return remoteSettings(remoteSettings())
            .enforcement(Enforcement.OBSERVE)
            .ioExecutor(io)
            .http(http)
            .revocationEngine(engine)
            .build()
            .also { opened += it }
    }

    private fun loaderThreads(revokt: Revokt): List<Thread> =
        Thread.getAllStackTraces().keys.filter { it.name == "revokt-loader-${revokt.config.sequence}" && it.isAlive }

    @Test
    fun `the first sync runs in the start task, and each next one waits the delay of its backoff`() {
        val feed =
            Feed(
                status(503, "Retry-After" to "60"),
                status(503),
                status(503, "Retry-After" to "0"),
                status(503, "Backoff" to "100000000"),
            )
        val revokt = bare().open(feed)
        revokt.start()
        assertEquals(minute, timer.next(), "Retry-After: 60 on the first sync, in the start task")
        assertEquals(1, feed.requests.get())
        for ((advance, expected) in listOf(minute to 30 * minute, 30 * minute to minute, minute to 24 * hour)) {
            clock.millis += advance
            timer.fire()
            assertEquals(expected, timer.next())
        }
        // 30 min: the second consecutive failure's computed backoff; 60 s: Retry-After 0 at the floor; 24 h: the cap.
        assertEquals(4, feed.requests.get())
        assertEquals(1, timer.queued, "one sync scheduled at a time")
    }

    @Test
    fun `with no fetching source nothing is scheduled`() {
        bare()
            .also { it.pollTimer = timer }
            .enforcement(Enforcement.OBSERVE)
            .revocationEngine(engine)
            .build()
            .also { opened += it }
            .start()
        assertEquals(0, timer.count.get())
    }

    @Test
    fun `close cancels a sync in flight, and nothing runs after it returns`() {
        val entered = CountDownLatch(1)
        val requests = AtomicInteger()
        val blocking =
            HttpFetcher {
                requests.incrementAndGet()
                entered.countDown()
                // Never answers: only the loader's interrupt (close) ends the sync's wait for it.
                CountDownLatch(1).await()
                status(503)
            }
        val revokt = bare().awaitDataMillis(0).open(blocking)
        timer.rejectWhenShutdown = false
        revokt.start()
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        revokt.close()
        assertEquals(0, timer.count.get(), "the cancelled sync, which ended after close's flip, asked for no next sync")
        assertTrue(loaderThreads(revokt).isEmpty(), "the loader has ended")
        assertEquals(1, engine.closes)
        assertEquals(1, requests.get())
    }

    @Test
    fun `a sync scheduled before close never runs`() {
        val feed = Feed(status(503))
        val revokt = bare().open(feed)
        revokt.start()
        assertEquals(15 * minute, timer.next())
        revokt.close()
        assertFailsWith<RejectedExecutionException> { timer.fire() }
        assertEquals(1, feed.requests.get())
        assertEquals(1, engine.closes)
    }

    @Test
    fun `a fatal error in a scheduled sync is rethrown after the next sync is scheduled`() {
        val feed = Feed(status(503), status(503))
        val revokt = bare().open(feed)
        revokt.start()
        assertEquals(15 * minute, timer.next())
        // The scheduled sync's clock read throws: the next one is scheduled in 15 min, then the error propagates.
        clock.millis += 15 * minute
        clock.throwOnce = OutOfMemoryError("clock")
        timer.fire()
        assertEquals(15 * minute, timer.next())
        assertEquals(1, feed.requests.get(), "that sync never ran")
        // The loader survived and the schedule goes on.
        clock.millis += 15 * minute
        timer.fire()
        assertEquals(30 * minute, timer.next(), "the second consecutive failure")
        assertEquals(2, feed.requests.get())
        assertTrue(loaderThreads(revokt).isNotEmpty())
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
