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

@Suppress("TooGenericExceptionCaught") // "never throws": any non-fatal refusal of an injected executor is FAILED
internal actual fun fetchWithin(
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
