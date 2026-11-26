// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import java.nio.file.Path

/**
 * The other process of `JvmStorageTest`'s lock tests: takes the lock of the store at `args[0]` through `JvmStorage`,
 * prints `locked`, and holds it until its standard input closes or it is killed. With `try` as `args[1]` it tries once,
 * prints `locked` or `busy`, and exits.
 */
object LockHolder {
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.getOrNull(1) == "try") {
            val result = runCatching { JvmStorage(Path.of(args[0]), lockWaitMillis = 0).lock().close() }
            println(if (result.isSuccess) LOCKED else BUSY)
            return
        }
        val held = JvmStorage(Path.of(args[0])).lock()
        println(LOCKED)
        System.out.flush()
        while (System.`in`.read() >= 0) {
            // Hold until the parent closes our standard input.
        }
        held.close()
    }

    const val LOCKED: String = "locked"
    const val BUSY: String = "busy"
}
