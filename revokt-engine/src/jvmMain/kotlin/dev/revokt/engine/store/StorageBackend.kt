// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.RevoktInternalApi

/**
 * The members of a `RevoktStorage` (spec §3, §6.5), which wraps one: a flat key space the engine keeps its store in,
 * the engine owning the layout. A key is segments of `[a-z0-9._-]{1,96}` joined by `/`, never `.` or `..`, so no key
 * resolves outside the root; every method throws [IllegalArgumentException] for any other name, and for the reserved
 * key `.lock`, which only [lock] uses. Methods are thread-safe, reads concurrently.
 *
 * `@RevoktInternalApi` so that revokt-jsse's tests can wrap a recording one (`RevoktStorage.of`); a consumer builds
 * storage only through `RevoktStorage.inMemory()` and `JvmStorage.directory(…)`.
 */
@RevoktInternalApi
public interface StorageBackend {
    /**
     * The content of [name], or null when no file has that key. A read that fails throws; it never returns null, which
     * the loader takes to mean the file is absent (spec §6.5, #236).
     */
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

    /**
     * Whether the store holds nothing (spec §6.5 "empty"): no key, and for a directory no entry at all but the lock and
     * temp files, so a directory holding files that are not keys is not empty. A read that fails throws.
     */
    public fun isEmpty(): Boolean = names().isEmpty()

    /**
     * The key for the per-process single-instance registry, read by `start()`, never by `build()`; null means not
     * registered. One store reached through two paths has one key; `inMemory()`'s is the instance itself. A read that
     * fails throws.
     */
    public fun identity(): Any? = null

    /**
     * Takes the store's exclusive lock, held until the result is closed: acquired in `start()` and held to `close()`,
     * never per write. The durable store bounds the wait (spec §3); `inMemory()` holds nothing.
     */
    public fun lock(): AutoCloseable
}
