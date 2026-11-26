// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import org.junit.jupiter.api.Assumptions
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStreamReader
import java.nio.channels.FileChannel
import java.nio.file.AccessDeniedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.deleteRecursively
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * `JvmStorage` on real directories (spec §3, §6.5; test-plan.md (e)): the fsyncs of a write, of a created directory
 * and of the open, the temp sweep, what `names()` lists, the lock against this JVM and another process, and the
 * ownership check. [Recording] wraps the real [SystemFsync], so every fsync also runs against the file system.
 */
@OptIn(ExperimentalPathApi::class)
class JvmStorageTest {
    private val posix =
        Path
            .of(".")
            .fileSystem
            .supportedFileAttributeViews()
            .contains("posix")

    /** Each fsync in order, as `file:<path>` or `dir:<path>`, paths relative to the test directory's real path. */
    private class Recording(
        private val base: Path,
        private val delegate: Fsync,
    ) : Fsync {
        val events = ArrayList<String>()

        /** For each forced file, whether its temp's target key existed at that moment. */
        val targetExisted = ArrayList<Boolean>()

        /** For each forced directory, whether it held a temp file at that moment. */
        val heldTemp = ArrayList<Boolean>()

        var failFile: IOException? = null
        var failDirectory: IOException? = null

        override fun file(
            path: Path,
            channel: FileChannel,
        ) {
            events += "file:" + rel(path)
            targetExisted += Files.exists(path.resolveSibling(path.fileName.toString().substringBefore('~')))
            failFile?.let { throw it }
            delegate.file(path, channel)
        }

        override fun directory(dir: Path) {
            events += "dir:" + rel(dir)
            heldTemp += Files.list(dir).use { s -> s.anyMatch { JvmStorage.TEMP.matches(it.fileName.toString()) } }
            failDirectory?.let { throw it }
            delegate.directory(dir)
        }

        private fun rel(p: Path): String =
            base.toRealPath().relativize(p.toAbsolutePath().normalize().let { real(it) }).joinToString("/")

        private fun real(p: Path): Path =
            if (Files.exists(p)) p.toRealPath() else p.parent.toRealPath().resolve(p.fileName)
    }

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

    private fun recording(dir: Path) = Recording(dir, SystemFsync(posix))

    @Test
    fun `a write forces its temp file, renames it into place, then fsyncs the key's directory, new key or not`() =
        withDir { dir ->
            val store = JvmStorage(dir.resolve("s"))
            store.write("a/x", byteArrayOf(0))
            val fsync = recording(dir)
            val recorded = JvmStorage(dir.resolve("s"), fsync = fsync)
            recorded.write("a/k", byteArrayOf(1, 2))
            recorded.write("a/k", byteArrayOf(3))
            assertEquals(2, fsync.events.size / 2)
            assertTrue(fsync.events[0].matches(Regex("file:s/a/k~[0-9a-f]{32}")), fsync.events.toString())
            assertEquals("dir:s/a", fsync.events[1])
            assertTrue(fsync.events[2].startsWith("file:s/a/k~"))
            assertEquals("dir:s/a", fsync.events[3])
            // The new key was absent when its temp was forced, the replaced one still held its old bytes: the rename
            // comes after the force, and the directory fsync after the rename.
            assertEquals(listOf(false, true), fsync.targetExisted)
            assertEquals(listOf(false, false), fsync.heldTemp)
            assertContentEquals(byteArrayOf(3), recorded.read("a/k"))
            assertEquals(
                listOf("k", "x"),
                Files.list(dir.resolve("s/a")).use { s ->
                    s.map { it.fileName.toString() }.sorted().toList()
                },
            )
        }

    @Test
    fun `every directory a write creates is created rwx------ and its parent fsynced, one at a time`() =
        withDir { dir ->
            val fsync = recording(dir)
            val store = JvmStorage(dir.resolve("s"), fsync = fsync)
            store.write("crlite/compat/blobs/b", byteArrayOf(1))
            assertEquals(
                listOf("dir:", "dir:s", "dir:s/crlite", "dir:s/crlite/compat"),
                fsync.events.filter { it.startsWith("dir:") }.dropLast(1),
            )
            assertEquals("dir:s/crlite/compat/blobs", fsync.events.last())
            if (posix) {
                for (d in listOf("s", "s/crlite", "s/crlite/compat", "s/crlite/compat/blobs")) {
                    assertEquals(
                        "rwx------",
                        PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve(d))),
                    )
                }
                assertEquals(
                    "rw-------",
                    PosixFilePermissions.toString(
                        Files.getPosixFilePermissions(dir.resolve("s/crlite/compat/blobs/b")),
                    ),
                )
            }
            fsync.events.clear()
            store.write("crlite/compat/blobs/c", byteArrayOf(2))
            assertEquals(listOf("dir:s/crlite/compat/blobs"), fsync.events.filter { it.startsWith("dir:") })
        }

    @Test
    fun `lock creates the root and fsyncs its parent, then fsyncs every directory under the root after the sweep`() =
        withDir { dir ->
            val plain = JvmStorage(dir.resolve("s"))
            plain.write("crlite/compat/blobs/b", byteArrayOf(1))
            plain.write("crlite/compat/generations/g", byteArrayOf(2))
            plain.write("store.version", byteArrayOf('1'.code.toByte()))
            val temps = listOf("s/store.version", "s/crlite/compat/blobs/b", "s/crlite/compat/generations/h")
            for (t in temps) {
                Files.write(
                    dir.resolve(
                        JvmStorage.tempName(t.substringAfterLast('/')).let {
                            t.substringBeforeLast('/') +
                                "/" +
                                it
                        },
                    ),
                    byteArrayOf(9),
                )
            }
            val kept =
                listOf(
                    "s/crlite/notes.txt",
                    "s/crlite/a~b",
                    "s/crlite/x~${"0".repeat(31)}",
                    "s/crlite/x~${"A".repeat(32)}",
                )
            for (k in kept) Files.write(dir.resolve(k), byteArrayOf(8))
            val fsync = recording(dir)
            val store = JvmStorage(dir.resolve("s"), fsync = fsync)
            store.lock().use {
                assertEquals(
                    setOf(
                        "dir:s",
                        "dir:s/crlite",
                        "dir:s/crlite/compat",
                        "dir:s/crlite/compat/blobs",
                        "dir:s/crlite/compat/generations",
                    ),
                    fsync.events.toSet(),
                )
                assertEquals(5, fsync.events.size)
                assertTrue(fsync.heldTemp.none { it }, "a directory was fsynced before its temp files were deleted")
                for (k in kept) assertTrue(Files.exists(dir.resolve(k)), k)
                // A key-shaped file is a key, whoever wrote it; the other kept entries are not.
                assertEquals(
                    setOf("crlite/compat/blobs/b", "crlite/compat/generations/g", "crlite/notes.txt", "store.version"),
                    store.names(),
                )
                Files.walk(dir).use { s -> assertTrue(s.noneMatch { JvmStorage.TEMP.matches(it.fileName.toString()) }) }
            }
            withDir { other ->
                val created = recording(other)
                JvmStorage(other.resolve("a/b"), fsync = created).lock().close()
                // The root and its missing parent are created one at a time, each parent fsynced; then the open's walk.
                assertEquals(listOf("dir:", "dir:a", "dir:a/b"), created.events)
            }
        }

    @Test
    fun `names lists only keys, never the lock, temp files, other entries or links`() =
        withDir { dir ->
            val store = JvmStorage(dir.resolve("s"))
            store.write("a/k", byteArrayOf(1))
            store.lock().use {
                val temp = Files.write(dir.resolve("s/a/" + JvmStorage.tempName("k")), byteArrayOf(2))
                Files.write(dir.resolve("s/a b"), byteArrayOf(3))
                Files.createDirectories(dir.resolve("s/d/sub"))
                try {
                    Files.createSymbolicLink(dir.resolve("s/link"), dir.resolve("s/a/k"))
                    Files.createSymbolicLink(dir.resolve("s/dirlink"), dir.resolve("s/a"))
                } catch (_: IOException) {
                    // No symbolic links here (Windows without the privilege): the rest still holds.
                } catch (_: UnsupportedOperationException) {
                    // Likewise.
                }
                assertEquals(setOf("a/k"), store.names())
                assertNull(store.read("d"))
                assertNull(store.read("a/k/x"))
                store.delete("d")
                store.delete("a/k/x")
                assertTrue(Files.isDirectory(dir.resolve("s/d/sub")))
                assertTrue(Files.exists(dir.resolve("s/.lock")))
                Files.delete(temp)
            }
            assertTrue(Files.exists(dir.resolve("s/.lock")), "closing the lock never deletes .lock")
            store.delete("a/k")
            assertFalse(Files.exists(dir.resolve("s/a")), "a directory left empty is removed")
            assertTrue(Files.isDirectory(dir.resolve("s")), "the root stays")
            assertEquals(emptySet(), JvmStorage(dir.resolve("absent")).names())
        }

    @Test
    fun `a root that is a symbolic link is walked through it`() =
        withDir { dir ->
            val target = Files.createDirectories(dir.resolve("real"))
            val link =
                try {
                    Files.createSymbolicLink(dir.resolve("link"), target)
                } catch (e: IOException) {
                    Assumptions.abort<Path>("cannot create symbolic links here: $e")
                }
            val store = JvmStorage(link)
            store.write("a/k", byteArrayOf(1))
            assertEquals(setOf("a/k"), store.names())
            store.lock().close()
        }

    @Test
    fun `a failed fsync fails the write, leaves the key as it was and no temp file`() =
        withDir { dir ->
            val fsync = recording(dir)
            val store = JvmStorage(dir.resolve("s"), fsync = fsync)
            store.write("a/k", byteArrayOf(1))
            fsync.failFile = IOException("injected file fsync")
            assertFailsWith<IOException> { store.write("a/k", byteArrayOf(2)) }
            assertContentEquals(byteArrayOf(1), store.read("a/k"))
            assertEquals(
                listOf("k"),
                Files.list(dir.resolve("s/a")).use { s ->
                    s.map { it.fileName.toString() }.toList()
                },
            )
            fsync.failFile = null
            fsync.failDirectory = IOException("injected directory fsync")
            assertFailsWith<IOException> { store.write("a/k", byteArrayOf(3)) }
            assertEquals(
                listOf("k"),
                Files.list(dir.resolve("s/a")).use { s ->
                    s.map { it.fileName.toString() }.toList()
                },
            )
        }

    @Test
    fun `a read that fails throws, it never returns null`() =
        withDir { dir ->
            Assumptions.assumeTrue(posix, "POSIX permissions")
            val store = JvmStorage(dir.resolve("s"))
            store.write("k", byteArrayOf(1))
            val file = dir.resolve("s/k")
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("---------"))
            Assumptions.assumeFalse(Files.isReadable(file), "running as a user who can read anything")
            assertFailsWith<AccessDeniedException> { store.read("k") }
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
            }
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
                    assertTrue(
                        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) >= JvmStorage.LOCK_WAIT_MILLIS - 50,
                    )
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

    @Test
    fun `ownership on POSIX - group-writable only under OWNER_OR_GROUP, never other-writable, never chmod`() =
        withDir { dir ->
            Assumptions.assumeTrue(posix, "POSIX permissions")
            val root = Files.createDirectory(dir.resolve("s"))
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxrwx---"))
            assertFailsWith<StoreUnreadableException> { JvmStorage(root).lock() }
            JvmStorage(root, OwnershipCheck.OWNER_OR_GROUP).lock().close()
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx---rwx"))
            assertFailsWith<StoreUnreadableException> { JvmStorage(root, OwnershipCheck.OWNER_OR_GROUP).lock() }
            assertEquals("rwx---rwx", PosixFilePermissions.toString(Files.getPosixFilePermissions(root)))
            // The failed opens released the lock.
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            JvmStorage(root, lockWaitMillis = 0).lock().close()
        }

    @Test
    fun `ownership on POSIX - a root owned by another uid than a probe file's is unreadable, and the probe goes`() =
        withDir { dir ->
            Assumptions.assumeTrue(posix, "POSIX permissions")
            val root = dir.resolve("s")
            val probes = ArrayList<Path>()
            val owner = { p: Path -> if (p == root.toAbsolutePath().normalize()) 0 else 1.also { probes.add(p) } }
            assertFailsWith<StoreUnreadableException> { JvmStorage(root, owner = owner).lock() }
            assertEquals(1, probes.size)
            assertTrue(JvmStorage.TEMP.matches(probes.single().fileName.toString()))
            assertFalse(Files.exists(probes.single()))
            JvmStorage(root, owner = { 7 }).lock().close()
            JvmStorage(root, owner = null).lock().close()
            JvmStorage(root).lock().close()
        }

    @Test
    fun `an I-O failure while opening is unreadable and releases the lock`() =
        withDir { dir ->
            val fsync = recording(dir)
            fsync.failDirectory = IOException("injected directory fsync")
            assertFailsWith<StoreUnreadableException> { JvmStorage(dir.resolve("s"), fsync = fsync).lock() }
            JvmStorage(dir.resolve("s"), lockWaitMillis = 0).lock().close()
            fsync.events.clear()
            assertFailsWith<StoreUnreadableException> { JvmStorage(dir.resolve("s"), fsync = fsync).lock() }
            assertEquals(listOf("dir:s"), fsync.events)
            JvmStorage(dir.resolve("s"), lockWaitMillis = 0).lock().close()
            Files.createDirectory(dir.resolve("d"))
            Files.createDirectory(dir.resolve("d/.lock"))
            assertFailsWith<StoreUnreadableException> { JvmStorage(dir.resolve("d")).lock() }
            Files.delete(dir.resolve("d/.lock"))
            JvmStorage(dir.resolve("d"), lockWaitMillis = 0).lock().close()
            Files.write(dir.resolve("file"), byteArrayOf(1))
            assertFailsWith<StoreUnreadableException> { JvmStorage(dir.resolve("file")).lock() }
            assertFailsWith<StoreUnreadableException> { JvmStorage(dir.resolve("file/s")).lock() }
        }

    @Test
    fun `identity is the absolute normalised root and building one touches no file`() =
        withDir { dir ->
            val store = JvmStorage(dir.resolve("a/../s"))
            assertEquals(
                dir
                    .resolve("s")
                    .toAbsolutePath()
                    .normalize()
                    .toString(),
                store.identity(),
            )
            assertFalse(Files.exists(dir.resolve("s")))
            assertFalse(Files.exists(dir.resolve("a")))
        }

    @Test
    fun `off POSIX no mode is set and no directory is fsynced`() =
        withDir { dir ->
            val fsync = recording(dir)
            val store = JvmStorage(dir.resolve("s"), posix = false, fsync = fsync, owner = null)
            store.write("a/k", byteArrayOf(1))
            store.lock().close()
            assertContentEquals(byteArrayOf(1), store.read("a/k"))
            SystemFsync(posix = false).directory(dir.resolve("absent"))
        }

    @Test
    fun `the Windows rename retries a target held open, within its bound`() =
        withDir { dir ->
            Assumptions.assumeFalse(posix, "Windows only")
            val store = JvmStorage(dir.resolve("s"))
            store.write("current", byteArrayOf(1))
            val open = FileInputStream(dir.resolve("s/current").toFile())
            val closer =
                Thread {
                    Thread.sleep(200)
                    open.close()
                }
            closer.start()
            try {
                store.write("current", byteArrayOf(2))
            } finally {
                closer.join()
                open.close()
            }
            assertContentEquals(byteArrayOf(2), store.read("current"))
        }

    @Test
    fun `moveWithRetry retries only access denied, every poll, until its bound`() {
        var clock = 0L
        var calls = 0
        val sleeps = ArrayList<Long>()
        val denied = AccessDeniedException("current")

        fun move(failures: Int): (Path, Path) -> Unit = { _, _ -> if (calls++ < failures) throw denied }
        val sleep = { ms: Long ->
            sleeps += ms
            clock += ms * 1_000_000
        }
        val p = Path.of("x")
        JvmStorage.moveWithRetry(p, p, 1_000, move(3), sleep) { clock }
        assertEquals(4, calls)
        assertEquals(listOf(10L, 10L, 10L), sleeps)
        calls = 0
        clock = 0
        sleeps.clear()
        assertSame(
            denied,
            assertFailsWith<AccessDeniedException> {
                JvmStorage.moveWithRetry(p, p, 1_000, move(Int.MAX_VALUE), sleep) { clock }
            },
        )
        assertEquals(100, sleeps.size)
        calls = 0
        assertFailsWith<AccessDeniedException> { JvmStorage.moveWithRetry(p, p, 0, move(1), sleep) { clock } }
        assertEquals(1, calls)
        val other = IOException("other")
        assertSame(
            other,
            assertFailsWith<IOException> {
                JvmStorage.moveWithRetry(p, p, 1_000, { _, _ -> throw other }, sleep) { clock }
            },
        )
        calls = 0
        val interrupting = { _: Long -> throw InterruptedException() }
        val thrown =
            assertFailsWith<AccessDeniedException> {
                JvmStorage.moveWithRetry(
                    p,
                    p,
                    1_000,
                    move(1),
                    interrupting,
                ) { clock }
            }
        assertTrue(thrown.suppressed.single() is InterruptedException)
        assertTrue(Thread.interrupted())
    }

    @Test
    fun `temp names are a key segment, a tilde and 32 hex digits, never a key, never twice the same`() {
        val names = (1..100).map { JvmStorage.tempName("x".repeat(96)) }
        assertEquals(100, names.toSet().size)
        for (n in names) {
            assertTrue(JvmStorage.TEMP.matches(n))
            assertFalse(StoreKeys.isKey(n))
        }
    }
}
