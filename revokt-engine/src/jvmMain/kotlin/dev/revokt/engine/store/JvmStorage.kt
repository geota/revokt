// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.store

import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktStorage
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.AccessDeniedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom

/** Which group bits `JvmStorage`'s ownership check tolerates on the store's root (spec §3); growable. */
internal enum class OwnershipCheck {
    /** The root is owned by the process's uid and neither group- nor other-writable. */
    STRICT,

    /** As [STRICT], but group-writable is tolerated: the Kubernetes `fsGroup` case. */
    OWNER_OR_GROUP,
}

/** Why `lock()` could not open the store (spec §3); never an [IOException], which `lock()` maps to the second kind. */
internal sealed class StoreOpenException(
    message: String,
    cause: Throwable?,
) : Exception(message, cause)

/** `lock()` found the store's lock held by another process, or by this one through another path (spec §3). */
internal class StoreLockedException(
    message: String,
    cause: Throwable? = null,
) : StoreOpenException(message, cause)

/**
 * `lock()` could not open the store: an ownership or permission failure, or an I/O error creating the root or `.lock`,
 * sweeping or syncing (spec §3). The instance runs on `inMemory()` for the life of the process (`STORE_UNREADABLE`).
 */
internal class StoreUnreadableException(
    message: String,
    cause: Throwable? = null,
) : StoreOpenException(message, cause)

/**
 * The durability operations `JvmStorage` performs, a seam so that tests over a real directory can record which paths
 * were forced and in what order. [SystemFsync] is the real one.
 */
internal interface Fsync {
    /** Forces [channel], open on [path], to the device. */
    fun file(
        path: Path,
        channel: FileChannel,
    )

    /** Forces directory [dir]'s entries to the device. */
    fun directory(dir: Path)
}

/**
 * `FileChannel.force(true)` for a file, and for a directory a read-only channel forced the same way, which the JDK
 * maps to fsync(2). Where the file system is not POSIX (Windows), a directory cannot be opened as a channel and its
 * fsync is skipped (spec §3).
 */
internal class SystemFsync(
    private val posix: Boolean,
) : Fsync {
    override fun file(
        path: Path,
        channel: FileChannel,
    ) {
        channel.force(true)
    }

    override fun directory(dir: Path) {
        if (!posix) return
        FileChannel.open(dir, StandardOpenOption.READ).use { it.force(true) }
    }
}

/**
 * The durable `RevoktStorage` over directory [root] (spec §3, §6.5). A key's segments are its path under the root.
 *
 * - [write] writes a temp file in the key's directory, forces it, renames it over the key ([Files.move] with
 *   `ATOMIC_MOVE`), then fsyncs the key's directory, new key or not; every directory it creates is created rwx------ and
 *   its parent fsynced. A temp name is the key's last segment, `~` and 32 random hex digits: `~` is outside the key
 *   alphabet, so no temp name is a key.
 * - [names] lists the regular files whose path is a key, so the lock, temp files and anything else are never listed and
 *   so never deleted by prune; symbolic links are not followed.
 * - [lock] creates the root (its parent fsynced), opens `.lock` (rw-------, never deleted) and takes a
 *   [FileChannel.tryLock] on it, tried every [lockPollMillis] for [lockWaitMillis]; then it checks ownership, deletes
 *   every temp file under the root and fsyncs every directory under the root, the root included, so a key another
 *   process renamed into place before its parent's fsync is durable before a pointer names it.
 * - [identity] is the absolute normalised root, computed with no I/O: the constructor touches no file.
 *
 * Reads run concurrently; [write], [delete] and [lock]'s sweep run alone. [fsync], [posix], [owner] and the lock timings
 * are test seams.
 */
internal class JvmStorage(
    dir: Path,
    private val ownership: OwnershipCheck = OwnershipCheck.STRICT,
    private val posix: Boolean = dir.fileSystem.supportedFileAttributeViews().contains("posix"),
    private val fsync: Fsync = SystemFsync(posix),
    private val owner: ((Path) -> Any?)? = defaultOwner(dir),
    private val lockWaitMillis: Long = LOCK_WAIT_MILLIS,
    private val lockPollMillis: Long = LOCK_POLL_MILLIS,
    private val moveRetryMillis: Long = if (posix) 0 else MOVE_RETRY_MILLIS,
) : RevoktStorage {
    private val root: Path = dir.toAbsolutePath().normalize()
    private val guard = ReadWriteGuard()

    override fun identity(): String = root.toString()

    override fun read(name: String): ByteArray? {
        StoreKeys.requireKey(name)
        return guard.read {
            val path = resolve(name)
            if (underFile(name) || Files.isDirectory(path)) {
                null
            } else {
                try {
                    Files.readAllBytes(path)
                } catch (_: NoSuchFileException) {
                    null
                }
            }
        }
    }

    override fun write(
        name: String,
        bytes: ByteArray,
    ) {
        StoreKeys.requireKey(name)
        guard.write {
            require(!underFile(name)) { "'$name' is under a file" }
            val target = resolve(name)
            require(!Files.isDirectory(target, LinkOption.NOFOLLOW_LINKS)) { "'$name' is a directory" }
            val parent = target.parent
            ensureDirectory(parent)
            val temp = parent.resolve(tempName(target.fileName.toString()))
            try {
                openFile(temp, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)).use {
                    val buffer = ByteBuffer.wrap(bytes)
                    while (buffer.hasRemaining()) it.write(buffer)
                    fsync.file(temp, it)
                }
                moveWithRetry(temp, target, moveRetryMillis)
                fsync.directory(parent)
            } finally {
                deleteQuietly(temp)
            }
        }
    }

    override fun delete(name: String) {
        StoreKeys.requireKey(name)
        guard.write {
            val path = resolve(name)
            if (underFile(name) || Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return@write
            Files.deleteIfExists(path)
            var dir = path.parent
            while (dir != root) {
                try {
                    Files.delete(dir)
                } catch (_: IOException) {
                    // Not empty (or already gone): the directories above it are not empty either.
                    break
                }
                dir = dir.parent
            }
        }
    }

    override fun names(): Set<String> =
        guard.read {
            val keys = HashSet<String>()
            if (Files.isDirectory(root)) walk { _, relative -> keyOf(relative)?.let(keys::add) }
            keys
        }

    override fun lock(): AutoCloseable {
        val lockFile =
            try {
                ensureDirectory(root)
                root.toRealPath().resolve(StoreKeys.LOCK)
            } catch (e: IOException) {
                throw unreadable(e)
            }
        val deadline = System.nanoTime() + lockWaitMillis * NANOS_PER_MILLI
        // One channel per `.lock` in the process: closing any descriptor of the file drops the process's fcntl lock, so
        // a second lock() here waits for the first to close instead of opening `.lock` itself.
        awaitTurn(lockFile, deadline)
        var channel: FileChannel? = null
        var held: Held? = null
        try {
            val open = openFile(lockFile, setOf(StandardOpenOption.CREATE, StandardOpenOption.WRITE))
            channel = open
            val lock = acquire(open, deadline)
            guard.write {
                checkOwnership()
                val dirs = ArrayList<Path>()
                walk(dirs::add) { file, _ -> if (TEMP.matches(file.fileName.toString())) deleteQuietly(file) }
                for (d in dirs) fsync.directory(d)
            }
            held = Held(lock, open, lockFile)
            return held
        } catch (e: IOException) {
            throw unreadable(e)
        } finally {
            if (held == null) {
                channel?.let(::closeQuietly)
                leave(lockFile)
            }
        }
    }

    private fun unreadable(cause: Throwable?) = StoreUnreadableException("cannot open the store at $root", cause)

    /** The lock until closed; closing twice is a no-op. Closing the channel releases the lock with it. */
    private class Held(
        private val lock: FileLock,
        private val channel: FileChannel,
        private val lockFile: Path,
    ) : AutoCloseable {
        @Volatile private var closed = false

        override fun close() {
            if (closed) return
            closed = true
            try {
                lock.release()
            } finally {
                try {
                    channel.close()
                } finally {
                    leave(lockFile)
                }
            }
        }
    }

    /** Waits, polling every [lockPollMillis] until [deadline], until no other lock() in this process holds [lockFile]. */
    private fun awaitTurn(
        lockFile: Path,
        deadline: Long,
    ) {
        while (true) {
            synchronized(OPEN) { if (OPEN.add(lockFile)) return }
            pause(deadline)
        }
    }

    private fun acquire(
        channel: FileChannel,
        deadline: Long,
    ): FileLock {
        while (true) {
            val lock =
                try {
                    channel.tryLock()
                } catch (_: OverlappingFileLockException) {
                    // Held in this JVM through a path whose real path differs (a bind mount, a hard link).
                    null
                }
            if (lock != null) return lock
            pause(deadline)
        }
    }

    /** Sleeps one [lockPollMillis], or throws [StoreLockedException] once [deadline] has passed or on an interrupt. */
    private fun pause(deadline: Long) {
        if (System.nanoTime() - deadline >= 0) throw StoreLockedException("the store at $root is locked")
        try {
            Thread.sleep(lockPollMillis)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw StoreLockedException("interrupted waiting for the lock of $root", e)
        }
    }

    /**
     * On POSIX, the root must be owned by the process's uid, read from a probe file this call creates under a temp name
     * and deletes (the JVM has no getuid), and must not be other-writable, nor group-writable under
     * [OwnershipCheck.STRICT]. Never chmods. Skipped where the file system is not POSIX.
     */
    private fun checkOwnership() {
        if (!posix) return
        val mode = Files.getPosixFilePermissions(root)
        if (PosixFilePermission.OTHERS_WRITE in mode ||
            (ownership == OwnershipCheck.STRICT && PosixFilePermission.GROUP_WRITE in mode)
        ) {
            throw StoreUnreadableException(
                "the store at $root is writable by others: ${PosixFilePermissions.toString(mode)}",
            )
        }
        val uid = owner ?: return
        val probe = root.resolve(tempName("probe"))
        Files.createFile(probe, FILE_MODE)
        try {
            val mine = uid(probe)
            val theirs = uid(root)
            if (mine != theirs) throw StoreUnreadableException("the store at $root is owned by uid $theirs, not $mine")
        } finally {
            deleteQuietly(probe)
        }
    }

    /** Creates [dir] and any missing ancestor rwx------, one at a time, fsyncing the parent of each it creates. */
    private fun ensureDirectory(dir: Path) {
        if (Files.isDirectory(dir)) return
        val parent = checkNotNull(dir.parent) { "no parent for $dir" }
        ensureDirectory(parent)
        try {
            if (posix) Files.createDirectory(dir, DIRECTORY_MODE) else Files.createDirectory(dir)
        } catch (e: FileAlreadyExistsException) {
            if (Files.isDirectory(dir)) return
            throw e
        }
        fsync.directory(parent)
    }

    /** Visits every directory under the root, the root first, with [onDirectory] and every regular file with [onFile]. */
    private fun walk(
        onDirectory: (Path) -> Unit = {},
        onFile: (Path, Path) -> Unit,
    ) {
        // From the real root, so a root that is itself a symbolic link is walked; links below it are not followed.
        val base = root.toRealPath()
        Files.walkFileTree(
            base,
            object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(
                    dir: Path,
                    attrs: BasicFileAttributes,
                ): FileVisitResult {
                    onDirectory(dir)
                    return FileVisitResult.CONTINUE
                }

                override fun visitFile(
                    file: Path,
                    attrs: BasicFileAttributes,
                ): FileVisitResult {
                    if (attrs.isRegularFile) onFile(file, base.relativize(file))
                    return FileVisitResult.CONTINUE
                }
            },
        )
    }

    private fun keyOf(relative: Path): String? {
        val key = relative.joinToString("/")
        return if (StoreKeys.isKey(key)) key else null
    }

    private fun resolve(name: String): Path = name.split('/').fold(root, Path::resolve)

    /** Whether a proper prefix of [name] is a regular file, so [name] cannot exist. */
    private fun underFile(name: String): Boolean {
        var slash = name.indexOf('/')
        while (slash >= 0) {
            if (Files.isRegularFile(resolve(name.substring(0, slash)), LinkOption.NOFOLLOW_LINKS)) return true
            slash = name.indexOf('/', slash + 1)
        }
        return false
    }

    /** Opens [path] with [options], created rw------- on POSIX. */
    private fun openFile(
        path: Path,
        options: Set<StandardOpenOption>,
    ): FileChannel = if (posix) FileChannel.open(path, options, FILE_MODE) else FileChannel.open(path, options)

    internal companion object {
        const val LOCK_WAIT_MILLIS: Long = 1_000
        const val LOCK_POLL_MILLIS: Long = 100
        const val MOVE_RETRY_MILLIS: Long = 1_000
        const val MOVE_POLL_MILLIS: Long = 10
        private const val NANOS_PER_MILLI = 1_000_000L
        private const val TEMP_HEX = 32

        /** A temp file's name: a key segment, `~` and 32 lowercase hex digits. */
        val TEMP: Regex = Regex("[A-Za-z0-9._-]{1,${StoreKeys.MAX_SEGMENT}}~[0-9a-f]{$TEMP_HEX}")

        private val FILE_MODE = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
        private val DIRECTORY_MODE = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        private val random = SecureRandom()

        /** The real `.lock` paths a lock() in this process holds or is taking; guarded by itself. */
        private val OPEN = HashSet<Path>()

        private fun leave(lockFile: Path) {
            synchronized(OPEN) { OPEN.remove(lockFile) }
        }

        fun tempName(segment: String): String {
            val bytes = ByteArray(TEMP_HEX / 2).also(random::nextBytes)
            return segment + "~" + bytes.joinToString("") { "%02x".format(it) }
        }

        /** `unix:uid` where the file system has the `unix` view; null (no uid check) elsewhere. */
        fun defaultOwner(dir: Path): ((Path) -> Any?)? =
            if (dir.fileSystem.supportedFileAttributeViews().contains("unix")) {
                { p: Path -> Files.getAttribute(p, "unix:uid") }
            } else {
                null
            }

        /**
         * Renames [source] over [target] atomically. Where [retryMillis] is positive (Windows), a rename that meets an
         * open target ([AccessDeniedException]) is retried every [MOVE_POLL_MILLIS] for up to [retryMillis], then the
         * last failure is thrown (spec §3).
         */
        fun moveWithRetry(
            source: Path,
            target: Path,
            retryMillis: Long,
            move: (Path, Path) -> Unit = { s, t ->
                Files.move(s, t, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            },
            sleep: (Long) -> Unit = Thread::sleep,
            nanoTime: () -> Long = System::nanoTime,
        ) {
            val deadline = nanoTime() + retryMillis * NANOS_PER_MILLI
            while (true) {
                try {
                    move(source, target)
                    return
                } catch (e: AccessDeniedException) {
                    if (nanoTime() - deadline >= 0) throw e
                    try {
                        sleep(MOVE_POLL_MILLIS)
                    } catch (interrupted: InterruptedException) {
                        Thread.currentThread().interrupt()
                        e.addSuppressed(interrupted)
                        throw e
                    }
                }
            }
        }

        private fun deleteQuietly(path: Path) {
            try {
                Files.deleteIfExists(path)
            } catch (_: IOException) {
                // A temp file that stays is invisible to names(); the next lock() sweeps it.
            }
        }

        private fun closeQuietly(channel: FileChannel) {
            try {
                channel.close()
            } catch (_: IOException) {
                // Closing releases the lock; nothing more to undo.
            }
        }
    }
}
