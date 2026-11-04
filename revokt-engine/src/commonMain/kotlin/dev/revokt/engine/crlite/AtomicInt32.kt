// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.crlite

/**
 * An atomic `Int` for the engine's query path. A small expect class rather than `kotlin.concurrent.atomics`, which is
 * experimental and so carries no binary-compatibility promise for a library a consumer's newer stdlib runs against.
 * The JVM actual is `java.util.concurrent.atomic.AtomicInteger`.
 */
internal expect class AtomicInt32(
    initial: Int,
) {
    fun get(): Int

    fun incrementAndGet(): Int

    fun decrementAndGet(): Int

    fun addAndGet(delta: Int): Int

    fun compareAndSet(
        expected: Int,
        update: Int,
    ): Boolean
}
