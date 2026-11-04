// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

// The linuxX64 purity gate only compiles; native threads have no interrupt to preserve.
internal actual fun awaitDrain(
    drained: CompletableDeferred<Unit>,
    timeoutMillis: Long,
) {
    runBlocking { withTimeoutOrNull(timeoutMillis) { drained.await() } }
}
