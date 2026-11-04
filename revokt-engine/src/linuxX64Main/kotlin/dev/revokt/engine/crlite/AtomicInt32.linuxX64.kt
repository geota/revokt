// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

// The linuxX64 purity gate only compiles and is never published, so the experimental atomics are acceptable here.
@OptIn(ExperimentalAtomicApi::class)
internal actual class AtomicInt32 actual constructor(
    initial: Int,
) {
    private val value = AtomicInt(initial)

    actual fun get(): Int = value.load()

    actual fun incrementAndGet(): Int = value.incrementAndFetch()

    actual fun decrementAndGet(): Int = value.decrementAndFetch()

    actual fun addAndGet(delta: Int): Int = value.addAndFetch(delta)

    actual fun compareAndSet(
        expected: Int,
        update: Int,
    ): Boolean = value.compareAndSet(expected, update)
}
