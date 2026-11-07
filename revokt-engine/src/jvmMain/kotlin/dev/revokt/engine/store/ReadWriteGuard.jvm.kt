// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

internal actual class ReadWriteGuard actual constructor() {
    private val lock = ReentrantReadWriteLock()

    actual fun <T> read(block: () -> T): T = lock.read(block)

    actual fun <T> write(block: () -> T): T = lock.write(block)
}
