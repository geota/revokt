// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import org.junit.jupiter.api.Assumptions
import java.io.FileInputStream
import java.io.IOException
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

    private fun recording(dir: Path) = Recording(dir, SystemFsync(StoragePlatform.of(dir.fileSystem)))

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
            // A content-addressed key is 64 hex digits, as long as a temp's tail and more: the sweep must keep it.
            val hexKey = "crlite/compat/blobs/" + "0123456789abcdef".repeat(4)
            plain.write(hexKey, byteArrayOf(3))
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
                assertContentEquals(byteArrayOf(3), store.read(hexKey))
                // A key-shaped file is a key, whoever wrote it; the other kept entries are not.
                assertEquals(
                    setOf(
                        "crlite/compat/blobs/b",
                        "crlite/compat/generations/g",
                        hexKey,
                        "crlite/notes.txt",
                        "store.version",
                    ),
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
            // A fresh instance over the existing root reads before it writes or locks.
            assertContentEquals(byteArrayOf(1), JvmStorage(dir.resolve("s")).read("a/k"))
            store.delete("a/k")
            assertFalse(Files.exists(dir.resolve("s/a")), "a directory left empty is removed")
            assertTrue(Files.isDirectory(dir.resolve("s")), "the root stays")
            assertEquals(emptySet(), JvmStorage(dir.resolve("absent")).names())
            val absent = JvmStorage(dir.resolve("absent"))
            assertNull(absent.read("k"))
            absent.delete("k")
            assertFalse(Files.exists(dir.resolve("absent")), "a read or a delete creates no root")
        }

    private fun linkOrAbort(
        link: Path,
        target: Path,
    ): Path =
        try {
            Files.createSymbolicLink(link, target)
        } catch (e: IOException) {
            Assumptions.abort<Path>("cannot create symbolic links here: $e")
        } catch (e: UnsupportedOperationException) {
            Assumptions.abort<Path>("cannot create symbolic links here: $e")
        }

    @Test
    fun `a key file that is a symbolic link is not a key - never listed, never followed, every access throws`() =
        withDir { dir ->
            val outside = Files.write(dir.resolve("outside"), byteArrayOf(7))
            val store = JvmStorage(dir.resolve("s"))
            store.lock().use {
                store.write("a/k", byteArrayOf(1))
                linkOrAbort(dir.resolve("s/a/current"), outside)
                assertEquals(setOf("a/k"), store.names())
                assertFailsWith<IOException> { store.read("a/current") }
                assertFailsWith<IOException> { store.write("a/current", byteArrayOf(2)) }
                assertFailsWith<IOException> { store.delete("a/current") }
                assertContentEquals(byteArrayOf(7), Files.readAllBytes(outside))
                assertTrue(Files.isSymbolicLink(dir.resolve("s/a/current")), "the link itself stays")
                assertEquals(
                    listOf("current", "k"),
                    Files.list(dir.resolve("s/a")).use { l ->
                        l.map { it.fileName.toString() }.sorted().toList()
                    },
                )
            }
        }

    @Test
    fun `a directory segment that is a symbolic link is not followed - its keys are not keys`() =
        withDir { dir ->
            val outside = Files.createDirectory(dir.resolve("outside"))
            Files.write(outside.resolve("b"), byteArrayOf(7))
            val store = JvmStorage(dir.resolve("s"))
            store.lock().use {
                store.write("x", byteArrayOf(1))
                linkOrAbort(dir.resolve("s/blobs"), outside)
                assertEquals(setOf("x"), store.names())
                assertFailsWith<IOException> { store.read("blobs/b") }
                assertFailsWith<IOException> { store.read("blobs/new") }
                assertFailsWith<IOException> { store.write("blobs/new", byteArrayOf(2)) }
                assertFailsWith<IOException> { store.write("blobs/deeper/new", byteArrayOf(2)) }
                assertFailsWith<IOException> { store.delete("blobs/b") }
                assertEquals(listOf("b"), Files.list(outside).use { l -> l.map { it.fileName.toString() }.toList() })
                assertContentEquals(byteArrayOf(7), Files.readAllBytes(outside.resolve("b")))
            }
            // The open's sweep and directory walk do not follow it either.
            Files.write(outside.resolve(JvmStorage.tempName("b")), byteArrayOf(8))
            store.lock().close()
            assertEquals(2L, Files.list(outside).use { it.count() })
        }

    @Test
    fun `a lock file that is a symbolic link is unreadable and is not followed`() =
        withDir { dir ->
            val outside = Files.write(dir.resolve("outside"), byteArrayOf(7))
            Files.createDirectory(dir.resolve("s"))
            linkOrAbort(dir.resolve("s/.lock"), outside)
            assertFailsWith<StoreUnreadableException> { JvmStorage(dir.resolve("s")).lock() }
            assertContentEquals(byteArrayOf(7), Files.readAllBytes(outside))
            // A dangling link is not created through either.
            Files.delete(dir.resolve("s/.lock"))
            linkOrAbort(dir.resolve("s/.lock"), dir.resolve("made"))
            assertFailsWith<StoreUnreadableException> { JvmStorage(dir.resolve("s")).lock() }
            assertFalse(Files.exists(dir.resolve("made"), java.nio.file.LinkOption.NOFOLLOW_LINKS))
            // Released: once the link goes, the store opens.
            Files.delete(dir.resolve("s/.lock"))
            JvmStorage(dir.resolve("s"), lockWaitMillis = 0).lock().close()
        }

    @Test
    fun `ownership is checked before the lock file is opened`() =
        withDir { dir ->
            Assumptions.assumeTrue(posix, "POSIX permissions")
            val root = Files.createDirectory(dir.resolve("s"))
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx---rwx"))
            assertFailsWith<StoreUnreadableException> { JvmStorage(root).lock() }
            assertFalse(Files.exists(root.resolve(".lock"), java.nio.file.LinkOption.NOFOLLOW_LINKS))
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
    fun `a failed file fsync fails the write with the key as it was, a failed directory fsync after the rename`() =
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
            // The directory fsync comes after the rename: the key holds the new bytes, only their durability is unknown.
            assertContentEquals(byteArrayOf(3), store.read("a/k"))
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
            val owner = { p: Path -> if (p == root.toRealPath()) 0 else 1.also { probes.add(p) } }
            assertFailsWith<StoreUnreadableException> { JvmStorage(root, owner = owner).lock() }
            assertEquals(1, probes.size)
            assertTrue(JvmStorage.TEMP.matches(probes.single().fileName.toString()))
            assertFalse(Files.exists(probes.single()))
            JvmStorage(root, owner = { 7 }).lock().close()
            JvmStorage(root, owner = { null }).lock().close()
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
            val store = JvmStorage(dir.resolve("s"), platform = StoragePlatform.OTHER, fsync = fsync, owner = { null })
            store.write("a/k", byteArrayOf(1))
            store.lock().close()
            assertContentEquals(byteArrayOf(1), store.read("a/k"))
            SystemFsync(StoragePlatform.OTHER).directory(dir.resolve("absent"))
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
            val started = System.nanoTime()
            closer.start()
            try {
                store.write("current", byteArrayOf(2))
            } finally {
                closer.join()
                open.close()
            }
            // The rename waited for the reader to close at 200 ms: it was retried, within the 1 s bound.
            val waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrue(waited in 150 until JvmStorage.MOVE_RETRY_MILLIS, "the write took $waited ms")
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
    fun `the ownership rule - never other-writable, group-writable only under OWNER_OR_GROUP, the process's uid`() {
        fun mode(text: String) = PosixFilePermissions.fromString(text)
        val strict = OwnershipCheck.STRICT
        val group = OwnershipCheck.OWNER_OR_GROUP
        assertNull(StoragePlatform.ownershipFault(mode("rwx------"), strict, 501, 501))
        assertNull(StoragePlatform.ownershipFault(mode("rwxrwx---"), group, 501, 501))
        assertTrue(StoragePlatform.ownershipFault(mode("rwxrwx---"), strict, 501, 501)!!.startsWith("group-writable"))
        assertTrue(
            StoragePlatform.ownershipFault(mode("rwx---rwx"), group, 501, 501)!!.startsWith("writable by others"),
        )
        assertTrue(
            StoragePlatform.ownershipFault(mode("rwx----w-"), strict, 501, 501)!!.startsWith("writable by others"),
        )
        assertEquals("owned by uid 0, not 501", StoragePlatform.ownershipFault(mode("rwx------"), strict, 501, 0))
        assertEquals("owned by uid 0, not 501", StoragePlatform.ownershipFault(mode("rwxr-xr-x"), group, 501, 0))
        assertNull(StoragePlatform.OTHER.directoryFault(Path.of("anywhere"), strict, 1) { 2 })
        assertNull(StoragePlatform.OTHER.processOwner(Path.of("anywhere")) { 1 })
        assertEquals(
            if (posix) StoragePlatform.POSIX else StoragePlatform.OTHER,
            StoragePlatform.of(Path.of(".").fileSystem),
        )
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
