// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import org.junit.jupiter.api.Assumptions
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStreamReader
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.deleteRecursively
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * `JvmStorage.lock()` on real directories (spec §3; test-plan.md (e)): the bounded wait against this JVM and a child
 * JVM ([LockHolder]), one table entry per `.lock` file key, a FIFO at `.lock`, and the check of every directory at open.
 */
@OptIn(ExperimentalPathApi::class)
class JvmStorageLockTest {
    private val posix =
        Path
            .of(".")
            .fileSystem
            .supportedFileAttributeViews()
            .contains("posix")

    private fun withDir(block: (Path) -> Unit) {
        val dir = Files.createTempDirectory("revokt-jvm-storage")
        try {
            block(dir)
        } finally {
            if (posix) restoreModes(dir)
            dir.deleteRecursively()
        }
    }

    /** Gives the owner every bit back, so a test that removed them can still delete its directory. */
    private fun restoreModes(dir: Path) {
        val mode = PosixFilePermissions.fromString("rwx------")
        Files.walk(dir).use { s -> s.forEach { runCatching { Files.setPosixFilePermissions(it, mode) } } }
    }

    @Test
    fun `a second lock in this JVM waits its bound and is locked, then succeeds once the first is closed`() =
        withDir { dir ->
            val first = JvmStorage(dir.resolve("s")).lock()
            val second = JvmStorage(dir.resolve("s/../s"))
            val started = System.nanoTime()
            assertFailsWith<StoreLockedException> { second.lock() }
            val waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(waited >= JvmStorage.LOCK_WAIT_MILLIS - 50, "waited only $waited ms")
            assertTrue(waited < 3_000, "waited $waited ms, past the 1 s bound")
            // The failed attempt closed its own channel on `.lock`: the first instance's lock must survive it.
            assertEquals(LockHolder.BUSY, tryFromAnotherProcess(dir.resolve("s")))
            first.close()
            first.close()
            assertEquals(LockHolder.LOCKED, tryFromAnotherProcess(dir.resolve("s")))
            second.lock().close()
        }

    private fun tryFromAnotherProcess(root: Path): String {
        val child = holderProcess(root, "try")
        try {
            val line = BufferedReader(InputStreamReader(child.inputStream)).readLine()
            assertTrue(child.waitFor(30, TimeUnit.SECONDS))
            return line
        } finally {
            child.destroyForcibly()
        }
    }

    private fun holderProcess(
        root: Path,
        vararg extra: String,
    ): Process {
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        return ProcessBuilder(
            listOf(java, "-cp", System.getProperty("java.class.path"), LockHolder::class.java.name, root.toString()) +
                extra,
        ).redirectError(ProcessBuilder.Redirect.INHERIT)
            .start()
    }

    @Test
    fun `a lock held through another link to the same lock file is locked`() =
        withDir { dir ->
            JvmStorage(dir.resolve("a")).lock().close()
            Files.createDirectory(dir.resolve("b"))
            try {
                Files.createLink(dir.resolve("b/.lock"), dir.resolve("a/.lock"))
            } catch (e: IOException) {
                Assumptions.abort<Unit>("cannot create hard links here: $e")
            } catch (e: UnsupportedOperationException) {
                Assumptions.abort<Unit>("cannot create hard links here: $e")
            }
            JvmStorage(dir.resolve("a")).lock().use {
                assertFailsWith<StoreLockedException> { JvmStorage(dir.resolve("b"), lockWaitMillis = 200).lock() }
                // One entry per file key: the attempt through `b` never opened its own channel, so its failure cannot
                // drop the holder's fcntl lock.
                assertEquals(LockHolder.BUSY, tryFromAnotherProcess(dir.resolve("a")))
            }
            assertEquals(LockHolder.LOCKED, tryFromAnotherProcess(dir.resolve("b")))
        }

    @Test
    fun `a lock released during the wait is taken within one poll`() =
        withDir { dir ->
            val held = JvmStorage(dir.resolve("s")).lock()
            val releaser =
                Thread {
                    Thread.sleep(300)
                    held.close()
                }
            val started = System.nanoTime()
            releaser.start()
            try {
                JvmStorage(dir.resolve("s"), lockWaitMillis = 5_000).lock().close()
            } finally {
                releaser.join()
            }
            val waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(waited in 250 until 900, "took $waited ms for a lock released at 300 ms; the poll is 100 ms")
        }

    @Test
    fun `closing a lock from two threads at once closes it once`() =
        withDir { dir ->
            repeat(20) {
                val held = JvmStorage(dir.resolve("s")).lock()
                val start = java.util.concurrent.CountDownLatch(1)
                val failures = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
                val closers =
                    (1..2).map {
                        Thread {
                            start.await()
                            runCatching { held.close() }.exceptionOrNull()?.let(failures::add)
                        }.apply { start() }
                    }
                start.countDown()
                closers.forEach { it.join() }
                // Only one close() runs: a second would release a closed lock (ClosedChannelException) and leave the
                // table a second time, which could let a newer holder's entry go.
                assertEquals(emptyList(), failures.toList())
                JvmStorage(dir.resolve("s"), lockWaitMillis = 0).lock().use {
                    assertFailsWith<StoreLockedException> { JvmStorage(dir.resolve("s"), lockWaitMillis = 0).lock() }
                }
            }
        }

    @Test
    fun `a FIFO at the lock file is unreadable within the bound, never a hang`() =
        withDir { dir ->
            Assumptions.assumeTrue(posix, "POSIX FIFOs")
            Files.createDirectory(dir.resolve("s"))
            val fifo = dir.resolve("s/.lock")
            val made =
                try {
                    ProcessBuilder("mkfifo", fifo.toString()).start().waitFor(10, TimeUnit.SECONDS)
                } catch (e: IOException) {
                    Assumptions.abort<Boolean>("no mkfifo here: $e")
                }
            Assumptions.assumeTrue(made && Files.exists(fifo, java.nio.file.LinkOption.NOFOLLOW_LINKS), "mkfifo failed")
            val pool = Executors.newSingleThreadExecutor()
            val started = System.nanoTime()
            val attempt =
                pool.submit<Throwable?> {
                    runCatching {
                        JvmStorage(
                            dir.resolve("s"),
                        ).lock().close()
                    }.exceptionOrNull()
                }
            try {
                val thrown = attempt.get(5, TimeUnit.SECONDS)
                assertTrue(thrown is StoreUnreadableException, "got $thrown")
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 3_000)
            } finally {
                // A blocked open (a mutant's) waits for a reader: give it one, so the pool can stop. A reader with no
                // writer would block as well, so only then.
                if (!attempt.isDone) runCatching { FileInputStream(fifo.toFile()).close() }
                pool.shutdownNow()
            }
        }

    @Test
    fun `every directory under the root is checked at open - other-writable, group-writable under STRICT, owner`() =
        withDir { dir ->
            Assumptions.assumeTrue(posix, "POSIX permissions")
            val root = dir.resolve("s")
            JvmStorage(root).write("crlite/compat/current", byteArrayOf(1))
            val sub = root.resolve("crlite")
            val temp = Files.write(sub.resolve(JvmStorage.tempName("current")), byteArrayOf(9))
            Files.setPosixFilePermissions(sub, PosixFilePermissions.fromString("rwxrwxrwx"))
            assertFailsWith<StoreUnreadableException> { JvmStorage(root).lock() }
            // The directory is checked before its temp files are swept: nothing in a directory that fails is deleted.
            assertTrue(Files.exists(temp), "the sweep ran in a directory that failed its check")
            assertFailsWith<StoreUnreadableException> { JvmStorage(root, OwnershipCheck.OWNER_OR_GROUP).lock() }
            assertEquals("rwxrwxrwx", PosixFilePermissions.toString(Files.getPosixFilePermissions(sub)), "never chmod")
            Files.setPosixFilePermissions(sub, PosixFilePermissions.fromString("rwxrwx---"))
            assertFailsWith<StoreUnreadableException> { JvmStorage(root).lock() }
            JvmStorage(root, OwnershipCheck.OWNER_OR_GROUP).lock().close()
            Files.setPosixFilePermissions(sub, PosixFilePermissions.fromString("rwx------"))
            val deep = root.resolve("crlite/compat").toRealPath()
            assertFailsWith<StoreUnreadableException> { JvmStorage(root, owner = { if (it == deep) 0 else 1 }).lock() }
            JvmStorage(root, lockWaitMillis = 0).lock().close()
        }

    @Test
    fun `a lock wait that is interrupted is locked and keeps the interrupt`() =
        withDir { dir ->
            JvmStorage(dir.resolve("s")).lock().use {
                val waiter = JvmStorage(dir.resolve("s"), lockWaitMillis = 60_000)
                Thread.currentThread().interrupt()
                assertFailsWith<StoreLockedException> { waiter.lock() }
                assertTrue(Thread.interrupted())
            }
        }

    @Test
    fun `another process's lock is held until it exits, and a killed holder leaves no stale lock`() =
        withDir { dir ->
            val root = dir.resolve("s")
            for (kill in listOf(false, true)) {
                val child = startHolder(root)
                try {
                    val started = System.nanoTime()
                    assertFailsWith<StoreLockedException> { JvmStorage(root).lock() }
                    val waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                    assertTrue(waited >= JvmStorage.LOCK_WAIT_MILLIS - 50, "waited only $waited ms")
                    assertTrue(waited < 3_000, "waited $waited ms, past the 1 s bound")
                    if (kill) child.destroyForcibly() else child.outputStream.close()
                    assertTrue(child.waitFor(30, TimeUnit.SECONDS))
                } finally {
                    child.destroyForcibly()
                }
                JvmStorage(root, lockWaitMillis = 5_000).lock().close()
            }
        }

    private fun startHolder(root: Path): Process {
        val child = holderProcess(root)
        val line = BufferedReader(InputStreamReader(child.inputStream)).readLine()
        if (line != LockHolder.LOCKED) {
            child.destroyForcibly()
            error("the lock holder printed $line")
        }
        return child
    }
}
