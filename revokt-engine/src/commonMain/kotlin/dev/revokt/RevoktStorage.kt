// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.store.InMemoryStorage
import kotlin.jvm.JvmStatic

/**
 * A flat key space the engine keeps its store in; the engine owns the layout (spec §3, §6.5). A key is segments of
 * `[A-Za-z0-9._-]{1,96}` joined by `/`, never `.` or `..`, so no key resolves outside the root; every method throws
 * [IllegalArgumentException] for any other name, and for the reserved key `.lock`, which only [lock] uses. Methods
 * are thread-safe, reads concurrently.
 */
public interface RevoktStorage {
    /** The content of [name], or null when no file has that key. */
    public fun read(name: String): ByteArray?

    /** Replaces [name] with [bytes] atomically and durably before returning; [read] sees it only when complete. */
    public fun write(
        name: String,
        bytes: ByteArray,
    )

    /** Removes [name] and any directory it leaves empty; a key that holds nothing is a no-op. */
    public fun delete(name: String)

    /** Every key that holds a file, excluding the lock and temporary keys. */
    public fun names(): Set<String>

    /** The key for the per-process single-instance registry; null means not registered ([inMemory]). */
    public fun identity(): String? = null

    /**
     * Takes the store's exclusive lock, held until the result is closed: acquired in `start()` and held to `close()`,
     * never per write. Waits at most 1 s, then throws [StoreLockedException].
     */
    public fun lock(): AutoCloseable

    public companion object {
        /**
         * A store held in memory for the process's lifetime (the builder default; meant for tests and 0.2): nothing is
         * durable, [identity] is null and [lock] holds nothing.
         */
        @JvmStatic
        public fun inMemory(): RevoktStorage = InMemoryStorage()
    }
}
