// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

/**
 * Spec §5.5's catch rule: true for a `VirtualMachineError` other than `StackOverflowError`, the only throwables a catch
 * of consumer or server-driven code rethrows. Everything else, a `StackOverflowError` or a consumer's
 * `NotImplementedError` included, is caught.
 */
internal expect fun isFatal(t: Throwable): Boolean

/**
 * On the JVM, sets the current thread's interrupt flag again when [t] is an `InterruptedException`: the code that threw
 * it cleared the flag, and a catch that absorbs the throw would lose it for good. A no-op elsewhere.
 */
internal expect fun restoreInterrupt(t: Throwable)

/**
 * §5.5's catch rule at a catch of consumer code (a verifier, canonicaliser, fallback or exemption) and at the
 * boundary: rethrows [t] when it [isFatal], and otherwise [restoreInterrupt]s, so the caller still sees the interrupt.
 */
internal fun absorb(t: Throwable) {
    if (isFatal(t)) throw t
    restoreInterrupt(t)
}
