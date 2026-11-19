// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Blocks until [drained] completes or [timeoutMillis] passes, for `RevocationEngine.close()` (spec §3.2). Never throws:
 * an interrupt ends the wait early and the thread's interrupt status is restored.
 */
internal fun awaitDrain(
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
