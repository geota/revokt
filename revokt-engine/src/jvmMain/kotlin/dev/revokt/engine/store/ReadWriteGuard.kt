// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * A reader-writer lock for the in-memory store: any number of [read] blocks run together, a [write] block runs alone.
 */
internal class ReadWriteGuard {
    private val lock = ReentrantReadWriteLock()

    fun <T> read(block: () -> T): T = lock.read(block)

    fun <T> write(block: () -> T): T = lock.write(block)
}
