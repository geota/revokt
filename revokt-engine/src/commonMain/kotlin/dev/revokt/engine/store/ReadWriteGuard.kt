// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

/**
 * A reader-writer lock for the in-memory store: any number of [read] blocks run together, a [write] block runs alone.
 * The JVM actual is a `ReentrantReadWriteLock`.
 */
internal expect class ReadWriteGuard() {
    fun <T> read(block: () -> T): T

    fun <T> write(block: () -> T): T
}
