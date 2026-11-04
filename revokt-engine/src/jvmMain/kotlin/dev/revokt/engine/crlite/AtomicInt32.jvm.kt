// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

import java.util.concurrent.atomic.AtomicInteger

internal actual class AtomicInt32 actual constructor(
    initial: Int,
) {
    private val value = AtomicInteger(initial)

    actual fun get(): Int = value.get()

    actual fun incrementAndGet(): Int = value.incrementAndGet()

    actual fun decrementAndGet(): Int = value.decrementAndGet()

    actual fun addAndGet(delta: Int): Int = value.addAndGet(delta)

    actual fun compareAndSet(
        expected: Int,
        update: Int,
    ): Boolean = value.compareAndSet(expected, update)
}
