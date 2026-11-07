// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.FetchResponse
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

// The linuxX64 purity gate only compiles; native threads have no interrupt, so a timed-out fetch is cancelled only.
internal actual fun fetchWithin(
    io: CoroutineDispatcher,
    timeoutMillis: Long,
    fetch: () -> FetchResponse?,
): Timed =
    runBlocking {
        val running = CoroutineScope(io).async { runCatching(fetch) }
        val ended = withTimeoutOrNull(timeoutMillis) { running.await() }
        if (ended == null) {
            running.cancel()
            Timed.TimedOut
        } else {
            ended.fold({ Timed.Done(it) }, { Timed.Threw(it) })
        }
    }
