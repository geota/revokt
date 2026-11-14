// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

internal actual fun isFatal(t: Throwable): Boolean = t is VirtualMachineError && t !is StackOverflowError

internal actual fun restoreInterrupt(t: Throwable) {
    if (t is InterruptedException) Thread.currentThread().interrupt()
}
