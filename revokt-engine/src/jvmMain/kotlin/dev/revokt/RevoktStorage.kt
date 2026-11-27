// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt

import dev.revokt.engine.store.InMemoryStorage
import dev.revokt.engine.store.StorageBackend
import kotlin.jvm.JvmStatic

/**
 * Where an instance keeps its store (spec §3, §6.5): built only by [inMemory] and `JvmStorage.directory(…)`, never
 * implemented by a consumer. The engine owns the layout inside it. Set it with `Revokt.Builder.storage`; one storage
 * serves one started instance at a time, and a second `start()` on it in the process throws.
 */
public sealed class RevoktStorage {
    /** The key space this storage is. */
    internal abstract val backend: StorageBackend

    /** Whether this is an [inMemory] store, for revokt-jsse's `IN_MEMORY_STORE_WITH_FETCHING_SOURCE` check (spec §4). */
    @RevoktInternalApi
    public abstract val isInMemory: Boolean

    public companion object {
        /**
         * A store held in memory for as long as this value is reachable (the builder default, meant for tests): nothing
         * is durable, so every restart downloads the data again. Its identity is the instance, so two started instances
         * cannot share one.
         */
        @JvmStatic
        public fun inMemory(): RevoktStorage = BackedStorage(InMemoryStorage(), isInMemory = true)

        /** A storage over [backend], for revokt's own tests across modules; in memory only when it is one. */
        @RevoktInternalApi
        @JvmStatic
        public fun of(backend: StorageBackend): RevoktStorage =
            BackedStorage(backend, isInMemory = backend is InMemoryStorage)
    }
}

/** The one shape of [RevoktStorage]: a [backend] and whether it is in memory. */
internal class BackedStorage(
    override val backend: StorageBackend,
    override val isInMemory: Boolean,
) : RevoktStorage() {
    override fun toString(): String = "RevoktStorage($backend)"
}
