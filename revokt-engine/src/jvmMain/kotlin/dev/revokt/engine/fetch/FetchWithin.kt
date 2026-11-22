// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchResponse
import dev.revokt.engine.walker.isFatal
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.asExecutor
import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Runs [fetch] on [io] and waits at most [timeoutMillis] for it (spec §3 `FetchRequest.timeoutMillis`: "each fetch runs
 * under `Future.get(timeoutMillis)` on `ioDispatcher`; expiry is FAILED and the next sync proceeds"). Never throws:
 * every throwable of [fetch] is [Timed.Threw] (§3: "any `Throwable` = `SyncOutcome.FAILED`"). On a timeout the fetch is
 * not waited for, so a hung fetcher cannot block the next call. An inline [io] (`Dispatchers.Unconfined`, or an
 * `ioExecutor` that runs the task on the calling thread, such as `Runnable::run` or Guava's `directExecutor()`)
 * defeats the timeout: the fetch blocks the caller before the wait starts. A refusal by the executor is [Timed.Threw].
 */
@Suppress("TooGenericExceptionCaught") // "never throws": any non-fatal refusal of an injected executor is FAILED
internal fun fetchWithin(
    io: CoroutineDispatcher,
    timeoutMillis: Long,
    fetch: () -> FetchResponse?,
): Timed {
    val task = FutureTask(fetch)
    val caller = Thread.currentThread()
    try {
        io.asExecutor().execute {
            // A cancel(true) the fetcher ignored leaves the worker interrupted; clear it so the next task on the
            // worker does not inherit it. FutureTask.run returns only after a cancelling interrupt was delivered.
            // An inline executor runs the task on the caller, whose interrupt (from close(), say) is not ours to clear.
            try {
                task.run()
            } finally {
                if (Thread.currentThread() !== caller) Thread.interrupted()
            }
        }
    } catch (t: Throwable) {
        // A shut-down executor's RejectedExecutionException, or any other refusal of an injected executor.
        if (isFatal(t)) throw t
        return Timed.Threw(t)
    }
    return try {
        Timed.Done(task.get(timeoutMillis, TimeUnit.MILLISECONDS))
    } catch (e: ExecutionException) {
        Timed.Threw(e.cause ?: e)
    } catch (ignored: TimeoutException) {
        // Interrupts the fetcher's thread (§3: a fetcher must honour interruption, so timed-out fetches do not pile up).
        task.cancel(true)
        Timed.TimedOut
    } catch (e: InterruptedException) {
        task.cancel(true)
        Thread.currentThread().interrupt()
        Timed.Threw(e)
    }
}
