// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchResponse
import kotlinx.coroutines.CoroutineDispatcher

/** How one [fetchWithin] call ended. */
internal sealed class Timed {
    /** The fetcher returned; [response] is null when a Java fetcher returned null. */
    class Done(
        val response: FetchResponse?,
    ) : Timed()

    /** The fetcher threw [cause], the executor refused the task, or the waiting thread was interrupted. */
    class Threw(
        val cause: Throwable,
    ) : Timed()

    /** The deadline passed; the fetch was cancelled and, on the JVM, its thread interrupted. */
    data object TimedOut : Timed()
}

/**
 * Runs [fetch] on [io] and waits at most [timeoutMillis] for it (spec §3 `FetchRequest.timeoutMillis`: "each fetch runs
 * under `Future.get(timeoutMillis)` on `ioDispatcher`; expiry is FAILED and the next sync proceeds"). Never throws:
 * every throwable of [fetch] is [Timed.Threw] (§3: "any `Throwable` = `SyncOutcome.FAILED`"). On a timeout the fetch is
 * not waited for, so a hung fetcher cannot block the next call. An inline [io] (`Dispatchers.Unconfined`, or an
 * `ioExecutor` that runs the task on the calling thread, such as `Runnable::run` or Guava's `directExecutor()`)
 * defeats the timeout: the fetch blocks the caller before the wait starts. A refusal by the executor is [Timed.Threw].
 */
internal expect fun fetchWithin(
    io: CoroutineDispatcher,
    timeoutMillis: Long,
    fetch: () -> FetchResponse?,
): Timed
