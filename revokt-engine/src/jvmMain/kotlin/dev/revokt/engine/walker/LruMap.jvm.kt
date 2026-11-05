// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

internal actual class LruMap<K, V> actual constructor(
    capacity: Int,
) {
    init {
        require(capacity >= 1) { "capacity must be at least 1, got $capacity" }
    }

    private val map =
        object : LinkedHashMap<K, V>(16, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?): Boolean = size > capacity
        }

    actual operator fun get(key: K): V? = synchronized(map) { map[key] }

    actual fun put(
        key: K,
        value: V,
    ) {
        synchronized(map) { map[key] = value }
    }

    actual val size: Int get() = synchronized(map) { map.size }
}
