// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

// The linuxX64 purity gate only compiles (spec §3), so this actual is single-threaded: an access order kept by
// re-inserting on each touch, over Kotlin/Native's insertion-ordered LinkedHashMap.
internal actual class LruMap<K, V> actual constructor(
    private val capacity: Int,
) {
    init {
        require(capacity >= 1) { "capacity must be at least 1, got $capacity" }
    }

    private val map = LinkedHashMap<K, V>()

    actual operator fun get(key: K): V? {
        if (key !in map) return null
        @Suppress("UNCHECKED_CAST") // the key is present, so the removed value is a V even when V is nullable
        val value = map.remove(key) as V
        map[key] = value
        return value
    }

    actual fun put(
        key: K,
        value: V,
    ) {
        map.remove(key)
        map[key] = value
        if (map.size > capacity) map.remove(map.keys.first())
    }

    actual val size: Int get() = map.size
}
