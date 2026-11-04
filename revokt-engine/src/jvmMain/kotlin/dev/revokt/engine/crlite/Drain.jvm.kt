// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

internal actual fun awaitDrain(
    drained: CompletableDeferred<Unit>,
    timeoutMillis: Long,
) {
    try {
        runBlocking { withTimeoutOrNull(timeoutMillis) { drained.await() } }
    } catch (ignored: InterruptedException) {
        // A shutdown on an interrupted thread: stop waiting and keep the interrupt for the caller.
        Thread.currentThread().interrupt()
    }
}
