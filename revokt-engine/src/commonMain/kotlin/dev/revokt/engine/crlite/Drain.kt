// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

import kotlinx.coroutines.CompletableDeferred

/**
 * Blocks until [drained] completes or [timeoutMillis] passes, for `RevocationEngine.close()` (spec §3.2). Never throws:
 * on the JVM an interrupt ends the wait early and the thread's interrupt status is restored.
 */
internal expect fun awaitDrain(
    drained: CompletableDeferred<Unit>,
    timeoutMillis: Long,
)
