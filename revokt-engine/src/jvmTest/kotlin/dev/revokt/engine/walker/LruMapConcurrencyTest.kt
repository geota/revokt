// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Spec §5.1: the cross-call memo is shared by concurrent handshake threads. */
class LruMapConcurrencyTest {
    @Test
    fun `lru map stays bounded and consistent under concurrent use`() {
        val capacity = 64
        val m = LruMap<Int, Int>(capacity)
        val threads = 8
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        try {
            val futures =
                (0 until threads).map { t ->
                    pool.submit<Unit> {
                        start.await()
                        for (i in 0 until 20_000) {
                            val k = (i * 31 + t) % 500
                            m.put(k, k * 2)
                            m[(k * 7) % 500]?.let { v ->
                                check(v == (k * 7) % 500 * 2) { "value $v for ${(k * 7) % 500}" }
                            }
                            check(m.size <= capacity) { "size ${m.size}" }
                        }
                    }
                }
            start.countDown()
            futures.forEach { it.get(60, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }
        assertEquals(capacity, m.size)
        assertTrue((0 until 500).count { m[it] != null } == capacity)
    }
}
