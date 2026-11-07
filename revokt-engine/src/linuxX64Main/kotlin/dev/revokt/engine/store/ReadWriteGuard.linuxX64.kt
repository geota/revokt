// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

// The linuxX64 purity gate only compiles (spec §3), so this actual is single-threaded and holds no lock.
internal actual class ReadWriteGuard actual constructor() {
    actual fun <T> read(block: () -> T): T = block()

    actual fun <T> write(block: () -> T): T = block()
}
