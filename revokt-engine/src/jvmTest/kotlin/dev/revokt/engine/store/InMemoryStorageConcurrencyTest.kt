// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.RevoktStorage
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** `RevoktStorage.inMemory()` is thread-safe: concurrent readers see each write whole, never a mix (spec §3, #109). */
class InMemoryStorageConcurrencyTest {
    @Test
    fun `concurrent readers see each write whole while writers replace and add keys`() {
        val store = RevoktStorage.inMemory()
        val size = 64 * 1024
        store.write("shared", ByteArray(size))
        val threads = 8
        val rounds = 500
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        try {
            val tasks =
                (0 until threads).map { t ->
                    pool.submit<Int> {
                        start.await()
                        var torn = 0
                        for (r in 0 until rounds) {
                            if (t % 2 == 0) {
                                store.write("shared", ByteArray(size) { (t * rounds + r).toByte() })
                                store.write("t$t/k$r", byteArrayOf(t.toByte()))
                            } else {
                                val bytes = checkNotNull(store.read("shared"))
                                if (bytes.size != size || bytes.any { it != bytes[0] }) torn++
                                store.names()
                            }
                        }
                        torn
                    }
                }
            start.countDown()
            assertEquals(0, tasks.sumOf { it.get(60, TimeUnit.SECONDS) })
        } finally {
            pool.shutdownNow()
        }
        assertEquals(1 + threads / 2 * rounds, store.names().size)
        assertTrue(store.names().all { it == "shared" || it.startsWith("t") })
    }
}
