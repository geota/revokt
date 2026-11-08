// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.Dataset
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.MozillaRemoteSettings
import dev.revokt.SyncStage
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import java.lang.reflect.Proxy
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.LockSupport
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Spec §3 `FetchRequest.timeoutMillis`: "each fetch runs under `Future.get(timeoutMillis)` on `ioDispatcher`; expiry is
 * FAILED and the next sync proceeds, so a hung injected fetcher cannot block later syncs", and the fetcher's other ways
 * to fail (#129).
 */
class TimedFetchTest {
    private val monitor =
        """{"changes":[{"bucket":"security-state","collection":"cert-revocations","last_modified":42}]}"""

    private fun client(
        fetcher: HttpFetcher,
        timeoutMillis: Long = 200,
        io: CoroutineDispatcher = Dispatchers.IO,
    ) = RemoteSettingsClient(
        MozillaRemoteSettings.DEFAULT,
        Dataset.CRLITE,
        fetcher,
        io,
        FetchLimits(fetchTimeoutMillis = timeoutMillis),
    )

    @Test
    fun `a fetcher that hangs is FAILED after the timeout, its thread is interrupted, and the next call proceeds`() {
        val hang = AtomicBoolean(true)
        val interrupted = CountDownLatch(1)
        val fetcher =
            HttpFetcher {
                if (hang.get()) {
                    try {
                        CountDownLatch(1).await()
                    } catch (e: InterruptedException) {
                        interrupted.countDown()
                        throw e
                    }
                }
                ok(monitor)
            }
        val c = client(fetcher)
        val started = System.nanoTime()
        c.pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.TIMEOUT)
        val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertTrue(elapsedMillis in 200..10_000, "returned after $elapsedMillis ms")
        assertTrue(interrupted.await(10, TimeUnit.SECONDS), "the hung fetch was interrupted")
        hang.set(false)
        assertEquals(42, c.pollChanges().assertOk())
    }

    @Test
    fun `a fetcher that ignores interruption does not block the next call`() {
        val release = CountDownLatch(1)
        val first = AtomicBoolean(true)
        val fetcher =
            HttpFetcher {
                if (first.getAndSet(false)) {
                    // Ignores interrupts until the test releases it.
                    while (release.count > 0) {
                        try {
                            release.await()
                        } catch (ignored: InterruptedException) {
                            // keep hanging
                        }
                    }
                }
                ok(monitor)
            }
        try {
            val c = client(fetcher)
            c.pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.TIMEOUT)
            assertEquals(42, c.pollChanges().assertOk())
        } finally {
            release.countDown()
        }
    }

    @Test
    fun `a timed-out fetch that ignored its interrupt leaves no interrupt for the next task on its worker`() {
        // One worker that, like Dispatchers.IO's and unlike a ThreadPoolExecutor's, does not clear the interrupt
        // between tasks.
        // Its idle wait neither throws on nor clears an interrupt.
        val queue = ConcurrentLinkedQueue<Runnable>()
        val stop = AtomicBoolean(false)
        val worker =
            Thread {
                while (!stop.get()) queue.poll()?.run() ?: LockSupport.parkNanos(1_000_000)
            }.apply {
                isDaemon = true
                start()
            }
        val executor = Executor { queue.add(it) }
        val release = CountDownLatch(1)
        val first = AtomicBoolean(true)
        val nextSawInterrupt = AtomicBoolean(true)
        val fetcher =
            HttpFetcher {
                if (first.getAndSet(false)) {
                    // Spins without reading the interrupt, so cancel(true)'s interrupt stays set on the worker.
                    while (release.count > 0) Thread.onSpinWait()
                } else {
                    nextSawInterrupt.set(Thread.currentThread().isInterrupted)
                }
                ok(monitor)
            }
        try {
            val c = client(fetcher, timeoutMillis = 500, io = executor.asCoroutineDispatcher())
            c.pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.TIMEOUT)
            release.countDown()
            assertEquals(42, c.pollChanges().assertOk())
            assertEquals(false, nextSawInterrupt.get(), "the next task on the one worker saw a stale interrupt")
        } finally {
            release.countDown()
            stop.set(true)
            worker.join()
        }
    }

    @Test
    fun `an inline dispatcher keeps an interrupt meant for the caller`() = inlineCallerKeepsInterrupt()

    /** The dispatcher is injected, as the engine's is: [inline] runs the fetch on the calling thread. */
    private fun inlineCallerKeepsInterrupt(inline: CoroutineDispatcher = Dispatchers.Unconfined) {
        val fetcher =
            HttpFetcher {
                // The fetch runs on the caller's thread: this is the caller being interrupted, by close() say.
                Thread.currentThread().interrupt()
                ok(monitor)
            }
        try {
            assertEquals(42, client(fetcher, io = inline).pollChanges().assertOk())
            assertTrue(Thread.currentThread().isInterrupted, "the caller's interrupt was cleared")
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `an executor that throws on execute is FAILED with its throwable`() {
        val refused = IllegalStateException("no threads")
        val io = Executor { throw refused }.asCoroutineDispatcher()
        val failed = client(HttpFetcher { ok(monitor) }, io = io).pollChanges()
        assertSame(refused, failed.assertFailed(SyncStage.CHANGESET, ClientFailure.FETCHER_THREW).cause)
    }

    @Test
    fun `a Java fetcher that returns null is FAILED`() {
        val nullFetcher =
            Proxy.newProxyInstance(
                HttpFetcher::class.java.classLoader,
                arrayOf(HttpFetcher::class.java),
            ) { _, _, _ -> null }
                as HttpFetcher
        client(nullFetcher).pollChanges().assertFailed(SyncStage.CHANGESET, ClientFailure.FETCHER_THREW)
    }

    @Test
    fun `a shut-down executor is FAILED with its rejection as the cause, and nothing is fetched`() {
        val executor = Executors.newSingleThreadExecutor()
        executor.shutdown()
        val fetched = AtomicBoolean(false)
        val failed =
            client(
                HttpFetcher {
                    fetched.set(true)
                    ok(monitor)
                },
                io = executor.asCoroutineDispatcher(),
            ).pollChanges()
                .assertFailed(SyncStage.CHANGESET, ClientFailure.FETCHER_THREW)
        assertIs<RejectedExecutionException>(failed.cause)
        assertEquals(false, fetched.get())
    }

    @Test
    fun `an interrupt of the waiting thread is FAILED, cancels the fetch and keeps the interrupt`() {
        val started = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        val fetcher =
            HttpFetcher { _: FetchRequest ->
                started.countDown()
                try {
                    CountDownLatch(1).await()
                } catch (e: InterruptedException) {
                    cancelled.countDown()
                    throw e
                }
                error("unreachable")
            }
        val waiter = Thread.currentThread()
        val interrupter =
            Thread {
                started.await()
                waiter.interrupt()
            }.apply { start() }
        try {
            val failed = client(fetcher, timeoutMillis = 30_000).pollChanges()
            assertIs<InterruptedException>(failed.assertFailed(SyncStage.CHANGESET, ClientFailure.FETCHER_THREW).cause)
            assertTrue(Thread.currentThread().isInterrupted, "the interrupt is restored")
        } finally {
            Thread.interrupted()
            interrupter.join()
        }
        assertTrue(cancelled.await(10, TimeUnit.SECONDS), "the fetch was cancelled")
    }

    @Test
    fun `an executor-backed dispatcher runs the fetch on its own threads`() {
        val executor = Executors.newFixedThreadPool(2) { Thread(it, "revokt-io-test") }
        try {
            var thread: String? = null
            val fetcher =
                HttpFetcher {
                    thread = Thread.currentThread().name
                    FetchResponse.of(200, emptyMap(), monitor.encodeToByteArray())
                }
            assertEquals(42, client(fetcher, io = executor.asCoroutineDispatcher()).pollChanges().assertOk())
            assertEquals("revokt-io-test", thread)
        } finally {
            executor.shutdownNow()
        }
    }
}
