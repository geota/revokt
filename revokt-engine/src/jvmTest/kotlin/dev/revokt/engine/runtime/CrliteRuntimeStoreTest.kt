// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.runtime

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.LogLevel
import dev.revokt.RevoktPolicy
import dev.revokt.WarningCode
import dev.revokt.engine.generation.DatasetGeneration
import dev.revokt.engine.seed.SeedFixture
import dev.revokt.engine.store.DirectoryStorage
import dev.revokt.engine.store.StorageBackend
import dev.revokt.engine.store.StoreKeys
import dev.revokt.engine.store.StoreLockedException
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.deleteRecursively
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The runtime's store step over `DirectoryStorage` on a real directory (spec §5.1, §6.5; test-plan.md (e)): `openStore()`
 * before the seed steps and `closeStore()` at close, a seed installed into the directory and served from it after a
 * restart, and the in-memory fallback, where the seed installs in memory, the directory is untouched and unlocked, and
 * the lock is never tried again.
 */
@OptIn(ExperimentalPathApi::class)
internal class CrliteRuntimeStoreTest : SeedFixture() {
    private val now = ts + 2 * hour

    private fun withRoot(block: (Path) -> Unit) {
        val dir = Files.createTempDirectory("revokt-runtime-store")
        try {
            block(dir.resolve("s"))
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun runtime(
        storage: StorageBackend,
        engine: TestEngine = TestEngine(),
    ): CrliteRuntime {
        val bytes = Seed(ts = ts).bytes()
        return CrliteRuntime(
            seed = Counted { bytes }.source,
            channel = CrliteChannel.COMPAT,
            crlite = true,
            fetchingSource = false,
            engine = engine,
            verifier = verifier,
            policy = RevoktPolicy.DEFAULT,
            pinnedRootSpkis = pinned,
            storage = storage,
            logger = logger,
        )
    }

    /** `start()`'s runtime steps in order: the store, the seed's, then the start task. */
    private fun CrliteRuntime.start() {
        openStore()
        val load = startSeed(soleSeed = false, nowMillis = now)
        startTask(load) { now }
    }

    private fun CrliteRuntime.crlite(): DatasetGeneration = assertNotNull(snapshot.snapshot.datasets[Dataset.CRLITE])

    /** Every regular file under [root] but `.lock`, by relative path. */
    private fun tree(root: Path): Map<String, List<Byte>> =
        if (!Files.exists(root)) {
            emptyMap()
        } else {
            Files.walk(root).use { s ->
                s
                    .filter { Files.isRegularFile(it) && it.fileName.toString() != StoreKeys.LOCK }
                    .toList()
                    .associate { root.relativize(it).joinToString("/") to Files.readAllBytes(it).toList() }
            }
        }

    private fun locked(root: Path): Boolean =
        try {
            DirectoryStorage(root, lockWaitMillis = 0).lock().close()
            false
        } catch (_: StoreLockedException) {
            true
        }

    private fun warned(code: WarningCode): Boolean =
        recording.messages.any { it.first == LogLevel.WARN && it.second.startsWith("$code: ") }

    @Test
    fun `the seed installs into the directory under the lock, and a restart serves it from there`() =
        withRoot { root ->
            val first = runtime(DirectoryStorage(root))
            first.start()
            assertFalse(first.storageFallback)
            assertTrue(locked(root), "held from openStore() to closeStore()")
            val files = tree(root)
            assertEquals("1", files["store.version"]?.toByteArray()?.decodeToString())
            assertTrue("crlite/compat/current" in files, "${files.keys}")
            val served = first.crlite().generationFile
            first.closeStore()
            assertFalse(locked(root))

            val engine = TestEngine()
            val second = runtime(DirectoryStorage(root), engine)
            second.start()
            assertEquals(served, second.crlite().generationFile)
            assertEquals(files, tree(root), "a live not older than the seed is served, and nothing is written")
            assertEquals(listOf("$ts/${delta.id}"), engine.prepared)
            second.closeStore()
            assertFalse(locked(root))
        }

    @Test
    fun `a newer layout runs in memory, where the seed installs, and the directory is untouched and unlocked`() =
        withRoot { root ->
            Files.createDirectories(root.resolve("crlite/compat"))
            Files.write(root.resolve("store.version"), "2".encodeToByteArray())
            Files.write(root.resolve("crlite/compat/current"), byteArrayOf(1))
            val before = tree(root)
            val runtime = runtime(DirectoryStorage(root))
            runtime.start()
            assertTrue(runtime.storageFallback)
            assertTrue(warned(WarningCode.STORE_NEWER_LAYOUT), "${recording.messages}")
            assertEquals("$ts/${delta.id}", runtime.crlite().generationId, "the seed is live, in memory")
            assertEquals(before, tree(root))
            assertFalse(locked(root))
            runtime.closeStore()
        }

    @Test
    fun `a lock another holder has runs in memory with STORE_LOCKED, never tried again`() =
        withRoot { root ->
            val runtime = runtime(DirectoryStorage(root, lockWaitMillis = 0))
            DirectoryStorage(root).lock().use { runtime.start() }
            assertTrue(runtime.storageFallback)
            assertTrue(warned(WarningCode.STORE_LOCKED), "${recording.messages}")
            assertTrue(runtime.crlite().generationId != null, "the seed is live, in memory")
            // The holder has gone; a second openStore() (a start() retried) keeps the in-memory store.
            runtime.openStore()
            runtime.closeStore()
            runtime.openStore()
            assertTrue(runtime.storageFallback)
            assertEquals(emptyMap(), tree(root), "nothing written")
            assertFalse(locked(root))
        }

    @Test
    fun `closeStore releases the lock and the registry, so a start retried opens the store again`() =
        withRoot { root ->
            val runtime = runtime(DirectoryStorage(root, lockWaitMillis = 0))
            runtime.openStore()
            assertFailsWith<IllegalStateException> { runtime.openStore() }
            val other = runtime(DirectoryStorage(root, lockWaitMillis = 0))
            assertFailsWith<IllegalStateException> { other.openStore() }
            runtime.closeStore()
            runtime.closeStore()
            assertFalse(locked(root))
            runtime.openStore()
            assertTrue(locked(root))
            assertFalse(runtime.storageFallback)
            runtime.closeStore()
            other.openStore()
            other.closeStore()
        }
}
