// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.Enforcement
import dev.revokt.LogLevel
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLogger
import dev.revokt.RevoktStorage
import org.junit.jupiter.api.Timeout
import java.io.IOException
import java.util.Collections
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.TimeSource

/**
 * Where `start()` and `close()` open and release the store (spec §5.1, §6.5), through the builder's internal `storage`
 * seam: the registry and the lock before the seed's header, held to `close()` and released there after the loader has
 * stopped and before `engine.close()`, released by a `start()` that throws, a second instance on one store refused, and
 * a lock that fails running the instance in memory. `JvmStorage` itself and `store.version` are revokt-engine's
 * (`StoreOpenTest`, `CrliteRuntimeStoreTest`); here the store is [Tracked].
 */
@Timeout(value = 60, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class RevoktStoreTest {
    private val events: MutableList<String> = Collections.synchronizedList(ArrayList())
    private val opened = ArrayList<Revokt>()

    @AfterTest
    fun closeAll() {
        opened.forEach { it.close() }
    }

    /** An in-memory store with [id] as its identity, whose lock records each take and release in [events]. */
    private inner class Tracked(
        private val id: Any?,
        private val failLock: Throwable? = null,
        val inner: RevoktStorage = RevoktStorage.inMemory(),
    ) : RevoktStorage by inner {
        @Volatile var held = 0
        var onRelease: () -> Unit = {}

        override fun identity(): Any? = id.also { events += "identity" }

        override fun lock(): AutoCloseable {
            events += "lock"
            failLock?.let { throw it }
            held++
            return AutoCloseable {
                onRelease()
                held--
                events += "release"
            }
        }
    }

    private fun build(
        storage: RevoktStorage,
        seed: ScriptedSeed = ScriptedSeed({ headerSeed() }) { events += "seed" },
        engine: StubEngine = StubEngine(),
        logger: RevoktLogger? = null,
        timeSource: TimeSource? = null,
    ): Revokt =
        bare()
            .seed(seed.source)
            .enforcement(Enforcement.OBSERVE)
            .also {
                it.storage = storage
                if (logger != null) it.logger = logger
                if (timeSource != null) it.timeSource = timeSource
            }.revocationEngine(engine)
            .build()
            .also { opened += it }

    private fun loaderThreads(revokt: Revokt): List<Thread> =
        Thread.getAllStackTraces().keys.filter { it.name == "revokt-loader-${revokt.config.sequence}" }

    @Test
    fun `start locks before the seed's header, and close releases after the loader and before the engine`() {
        val storage = Tracked("a")
        val engine = StubEngine()
        val revokt = build(storage, engine = engine)
        val atRelease = ArrayList<String>()
        storage.onRelease = {
            atRelease += "engine closes ${engine.closes}"
            atRelease += "loader threads ${loaderThreads(revokt).size}"
        }
        revokt.start()
        assertEquals(listOf("identity", "lock", "seed"), events.take(3))
        assertEquals(1, storage.held)
        revokt.close()
        assertEquals(0, storage.held)
        assertEquals(listOf("engine closes 0", "loader threads 0"), atRelease)
        assertEquals(1, engine.closes)
        revokt.close()
        assertEquals(1, events.count { it == "release" }, "released once")
    }

    @Test
    fun `a start that throws once its loader runs leaves the store to the loader, and close releases it after`() {
        val storage = Tracked("e")
        val throwing =
            object : TimeSource {
                override fun markNow(): TimeSource.Monotonic.ValueTimeMark = throw StackOverflowError()
            }
        val revokt = build(storage, timeSource = throwing)
        val atRelease = ArrayList<Int>()
        storage.onRelease = { atRelease += loaderThreads(revokt).size }
        assertFailsWith<StackOverflowError> { revokt.start() }
        assertEquals(1, storage.held, "held while the loader may write")
        assertEquals(1, loaderThreads(revokt).size)
        revokt.close()
        assertEquals(0, storage.held)
        assertEquals(listOf(0), atRelease, "released once the loader is gone")
    }

    @Test
    fun `a start that throws after the store step releases it, and a retry takes it again`() {
        val storage = Tracked("b")
        val revokt = build(storage, ScriptedSeed({ headerSeed(channel = "DEFAULT") }))
        repeat(2) {
            val e = assertFailsWith<IllegalStateException> { revokt.start() }
            assertTrue(e.message.orEmpty().startsWith("SEED_CHANNEL_MISMATCH"), e.message)
            assertEquals(0, storage.held)
            assertTrue(loaderThreads(revokt).isEmpty(), "still CREATED")
        }
        assertEquals(listOf("identity", "lock", "release", "identity", "lock", "release"), events)
        // Deregistered too: another instance on the same store starts.
        build(Tracked("b")).start()
    }

    @Test
    fun `a second instance on one store throws from start and takes no lock, then starts once the first closes`() {
        val first = build(Tracked("c"))
        first.start()
        val storage = Tracked("c")
        val second = build(storage)
        events.clear()
        val e = assertFailsWith<IllegalStateException> { second.start() }
        assertTrue("another Revokt in this process" in e.message.orEmpty(), e.message)
        assertEquals(listOf("identity"), events, "no lock taken")
        first.close()
        second.start()
        assertEquals(1, storage.held)
    }

    @Test
    fun `a lock that fails runs the instance in memory, with STORE_UNREADABLE logged, and start succeeds`() {
        val lines = Collections.synchronizedList(ArrayList<Pair<LogLevel, String>>())
        val storage = Tracked("d", failLock = IOException("no"))
        val revokt = build(storage, logger = { level, message, _ -> lines += level to message })
        revokt.start()
        assertTrue(lines.any { it.first == LogLevel.WARN && it.second.startsWith("STORE_UNREADABLE: ") }, "$lines")
        assertTrue(storage.inner.names().isEmpty(), "nothing written to the configured store")
        revokt.close()
        // Deregistered at the fallback: another instance on the same store starts.
        build(Tracked("d")).start()
    }
}
