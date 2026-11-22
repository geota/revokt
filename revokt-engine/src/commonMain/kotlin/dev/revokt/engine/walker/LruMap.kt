// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

/**
 * A bounded, access-ordered map (spec §5.1 declarations): [get] and [put] refresh an entry, and a [put] that would hold
 * more than `capacity` entries evicts the least recently used one. Safe for concurrent handshake threads (the cross-call
 * memo, `CROSS_CALL_MEMO_ENTRIES`, and the per-trust-manager caches). Made by [lruMap].
 */
internal interface LruMap<K, V> {
    operator fun get(key: K): V?

    fun put(
        key: K,
        value: V,
    )

    /** The number of entries, at most `capacity`. */
    val size: Int
}

/**
 * A fresh [LruMap] of at most [capacity] entries; [capacity] must be at least 1. The JVM's is a synchronized
 * access-ordered `LinkedHashMap`.
 */
internal expect fun <K, V> lruMap(capacity: Int): LruMap<K, V>
