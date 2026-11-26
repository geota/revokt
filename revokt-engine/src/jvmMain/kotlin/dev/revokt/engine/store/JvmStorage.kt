// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.store

import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktStorage
import okio.buffer
import okio.source
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
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

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
 * `FileChannel.force(true)` for a file, and for a directory [StoragePlatform.syncDirectory]: a read-only channel forced
 * the same way, which the JDK maps to fsync(2), and nothing where the file system is not POSIX (spec §3).
 */
internal class SystemFsync(
    private val platform: StoragePlatform,
) : Fsync {
    override fun file(
        path: Path,
        channel: FileChannel,
    ) {
        channel.force(true)
    }

    override fun directory(dir: Path) {
        platform.syncDirectory(dir)
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
 *   so never deleted by prune.
 * - Below the real root no symbolic link is followed: a link anywhere in a key's path makes it not a key, so [names]
 *   skips it and [read], [write] and [delete] of it throw (fail closed). The root itself may be a link the caller chose.
 * - [lock] creates the root (its parent fsynced), resolves its real path, checks ownership, then opens `.lock`
 *   (rw-------, never deleted) with no link followed, requires a regular file, and takes a [FileChannel.tryLock] on it,
 *   tried every [lockPollMillis] for [lockWaitMillis]; then it deletes every temp file under the root and fsyncs every
 *   directory under the root, the root included, so a key another process renamed into place before its parent's fsync
 *   is durable before a pointer names it.
 * - [identity] is the absolute normalised root, computed with no I/O: the constructor touches no file.
 *
 * Reads run concurrently; [write], [delete] and [lock]'s sweep run alone. [platform], [fsync], [owner] and the lock
 * timings are test seams.
 */
internal class JvmStorage(
    dir: Path,
    private val ownership: OwnershipCheck = OwnershipCheck.STRICT,
    private val platform: StoragePlatform = StoragePlatform.of(dir.fileSystem),
    private val fsync: Fsync = SystemFsync(platform),
    private val owner: (Path) -> Any? = defaultOwner(dir),
    private val lockWaitMillis: Long = LOCK_WAIT_MILLIS,
    private val lockPollMillis: Long = LOCK_POLL_MILLIS,
    private val moveRetryMillis: Long = platform.moveRetryMillis,
) : RevoktStorage {
    private val root: Path = dir.toAbsolutePath().normalize()
    private val guard = ReadWriteGuard()

    /** The root's real path, resolved once it exists and again by every [lock]; below it, no link is followed. */
    @Volatile private var real: Path? = null

    override fun identity(): String = root.toString()

    override fun read(name: String): ByteArray? {
        StoreKeys.requireKey(name)
        return guard.read {
            val base = existingBase()
            if (base == null || kindOf(base, name) != Kind.FILE) {
                null
            } else {
                try {
                    readFile(resolve(base, name))
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
            val base = createdBase()
            val kind = kindOf(base, name)
            require(kind != Kind.UNDER_FILE) { "'$name' is under a file" }
            require(kind != Kind.DIRECTORY) { "'$name' is a directory" }
            val target = resolve(base, name)
            val parent = target.parent
            createBelow(base, parent)
            val temp = parent.resolve(tempName(target.fileName.toString()))
            try {
                platform.open(temp, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)).use {
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
            val base = existingBase() ?: return@write
            if (kindOf(base, name) != Kind.FILE) return@write
            val path = resolve(base, name)
            Files.deleteIfExists(path)
            var dir = path.parent
            while (dir != base) {
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
            existingBase()?.let { base -> walk(base) { _, relative -> keyOf(relative)?.let(keys::add) } }
            keys
        }

    override fun lock(): AutoCloseable {
        val base: Path
        val mine: Any?
        try {
            ensureDirectory(root)
            base = resolveBase()
            mine = platform.processOwner(base, owner)
            checkDirectory(base, mine)
        } catch (e: IOException) {
            throw unreadable(e)
        }
        val lockFile = base.resolve(StoreKeys.LOCK)
        val deadline = System.nanoTime() + lockWaitMillis * NANOS_PER_MILLI
        // One channel per `.lock` file in the process, keyed on its file key: closing any descriptor of the file drops
        // the process's fcntl lock, so a second lock() here, through any path, waits for the first to close instead of
        // opening `.lock` itself.
        val key =
            try {
                awaitTurn(lockFile, deadline)
            } catch (e: IOException) {
                throw unreadable(e)
            }
        var channel: FileChannel? = null
        var held: Held? = null
        try {
            // READ and WRITE: O_RDWR does not block on a FIFO swapped in since awaitTurn's lstat; the check after refuses it.
            val open = platform.open(lockFile, LOCK_OPTIONS)
            channel = open
            requireRegular(lockFile)
            val lock = acquire(open, deadline)
            guard.write {
                val dirs = ArrayList<Path>()
                walk(base, dirs::add) { file, _ -> if (TEMP.matches(file.fileName.toString())) deleteQuietly(file) }
                for (d in dirs) {
                    checkDirectory(d, mine)
                    fsync.directory(d)
                }
            }
            held = Held(lock, open, key)
            return held
        } catch (e: IOException) {
            throw unreadable(e)
        } finally {
            if (held == null) {
                channel?.let(::closeQuietly)
                leave(key)
            }
        }
    }

    /**
     * [dir] must be the process's ([mine]) and pass the mode rule ([StoragePlatform.directoryFault]): the root before
     * `.lock` is opened, then every directory under it in the open's walk, so no one but the owner can swap a directory
     * on a key's path for a link between the checks and the use. Never chmods.
     */
    private fun checkDirectory(
        dir: Path,
        mine: Any?,
    ) {
        platform.directoryFault(dir, ownership, mine, owner)?.let {
            throw StoreUnreadableException("the store at $root is not this process's: $dir is $it")
        }
    }

    /** The root's real path, or null while the root does not exist. */
    private fun existingBase(): Path? = real ?: if (Files.isDirectory(root)) resolveBase() else null

    /** The root's real path, creating the root first when it does not exist. */
    private fun createdBase(): Path = real ?: ensureDirectory(root).let { resolveBase() }

    private fun resolveBase(): Path = root.toRealPath().also { real = it }

    private fun unreadable(cause: Throwable?) = StoreUnreadableException("cannot open the store at $root", cause)

    /** The lock until closed; closing twice, even at once, closes once. Closing the channel releases the lock with it. */
    private class Held(
        private val lock: FileLock,
        private val channel: FileChannel,
        private val key: Any,
    ) : AutoCloseable {
        private val closed = AtomicBoolean(false)

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            try {
                lock.release()
            } finally {
                try {
                    channel.close()
                } finally {
                    leave(key)
                }
            }
        }
    }

    /**
     * Waits, polling every [lockPollMillis] until [deadline], until no other lock() in this process holds [lockFile], and
     * returns the key it took. Under the table's monitor it creates `.lock` when absent, lstats it with no link followed
     * and refuses anything but a regular file (a FIFO would block the open), and keys on its file key, the (device,
     * inode) pair the JDK's own lock table uses, so two paths to one file (a hard link, a bind mount) share one entry.
     */
    private fun awaitTurn(
        lockFile: Path,
        deadline: Long,
    ): Any {
        while (true) {
            synchronized(OPEN) {
                val key = lockKey(lockFile)
                if (OPEN.add(key)) return key
            }
            pause(deadline)
        }
    }

    private fun lockKey(lockFile: Path): Any {
        try {
            platform.createFile(lockFile)
        } catch (_: FileAlreadyExistsException) {
            // Already there, as it is after the first open: it is never deleted.
        }
        return requireRegular(lockFile).fileKey() ?: lockFile
    }

    /** [path]'s own attributes, which must be a regular file's; a link, a FIFO or a directory throws. */
    private fun requireRegular(path: Path): BasicFileAttributes {
        val attrs = Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        if (!attrs.isRegularFile) throw IOException("$path is not a regular file")
        return attrs
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
     * Creates the root and any missing ancestor rwx------, one at a time, fsyncing the parent of each it creates. Links
     * above and at the root are the caller's choice and are followed.
     */
    private fun ensureDirectory(dir: Path) {
        if (Files.isDirectory(dir)) return
        val parent = checkNotNull(dir.parent) { "no parent for $dir" }
        ensureDirectory(parent)
        try {
            platform.createDirectory(dir)
        } catch (e: FileAlreadyExistsException) {
            if (Files.isDirectory(dir)) return
            throw e
        }
        fsync.directory(parent)
    }

    /**
     * Creates the missing directories from [base] down to [dir], one at a time, rwx------, fsyncing each one's parent.
     * [kindOf] has already refused a link on the way, and `mkdir` follows none, so one that appears meanwhile fails.
     */
    private fun createBelow(
        base: Path,
        dir: Path,
    ) {
        if (dir == base || Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) return
        createBelow(base, dir.parent)
        platform.createDirectory(dir)
        fsync.directory(dir.parent)
    }

    /** Visits every directory under [base], [base] first, with [onDirectory] and every regular file with [onFile]. */
    private fun walk(
        base: Path,
        onDirectory: (Path) -> Unit = {},
        onFile: (Path, Path) -> Unit,
    ) {
        // Links below the root are not followed: a link to a file or a directory is neither visited through nor listed.
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

    internal companion object {
        private fun keyOf(relative: Path): String? {
            val key = relative.joinToString("/")
            return if (StoreKeys.isKey(key)) key else null
        }

        /** What a key's path holds, read segment by segment with no link followed. */
        private enum class Kind { ABSENT, UNDER_FILE, DIRECTORY, FILE }

        /**
         * What [name] names under [base], each segment's attributes read without following a link. A symbolic link, or
         * anything but a directory or a regular file, anywhere on the path makes [name] not a key: this throws, so a read
         * fails rather than reading as absent, and a write or a delete fails (spec §6.5, the store trusted at the OS level).
         */
        private fun kindOf(
            base: Path,
            name: String,
        ): Kind {
            val segments = name.split('/')
            var path = base
            for (segment in segments.subList(0, segments.size - 1)) {
                path = path.resolve(segment)
                val attrs = attributes(path) ?: return Kind.ABSENT
                if (attrs.isRegularFile) return Kind.UNDER_FILE
                if (!attrs.isDirectory) throw notAKey(name, path)
            }
            path = path.resolve(segments.last())
            val attrs = attributes(path) ?: return Kind.ABSENT
            return when {
                attrs.isDirectory -> Kind.DIRECTORY
                attrs.isRegularFile -> Kind.FILE
                else -> throw notAKey(name, path)
            }
        }

        /** [path]'s own attributes, a link's rather than its target's; null when nothing is there. */
        private fun attributes(path: Path): BasicFileAttributes? =
            try {
                Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
            } catch (_: NoSuchFileException) {
                null
            }

        private fun notAKey(
            name: String,
            path: Path,
        ) = IOException("'$name' is not a key here: $path is a link or a special file")

        private fun resolve(
            base: Path,
            name: String,
        ): Path = name.split('/').fold(base, Path::resolve)

        /** Reads [path] whole, opened with no link followed. */
        private fun readFile(path: Path): ByteArray =
            Files
                .newInputStream(path, LinkOption.NOFOLLOW_LINKS)
                .source()
                .buffer()
                .use { it.readByteArray() }

        const val LOCK_WAIT_MILLIS: Long = 1_000
        const val LOCK_POLL_MILLIS: Long = 100
        const val MOVE_RETRY_MILLIS: Long = 1_000
        const val MOVE_POLL_MILLIS: Long = 10
        private const val NANOS_PER_MILLI = 1_000_000L
        private const val TEMP_HEX = 32

        /** A temp file's name: a key segment, `~` and 32 lowercase hex digits. */
        val TEMP: Regex = Regex("[a-z0-9._-]{1,${StoreKeys.MAX_SEGMENT}}~[0-9a-f]{$TEMP_HEX}")

        private val random = SecureRandom()

        private val LOCK_OPTIONS: Set<OpenOption> =
            setOf(
                StandardOpenOption.CREATE,
                StandardOpenOption.READ,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            )

        /** The `.lock` file keys a lock() in this process holds or is taking; guarded by itself. */
        private val OPEN = HashSet<Any>()

        private fun leave(key: Any) {
            synchronized(OPEN) { OPEN.remove(key) }
        }

        fun tempName(segment: String): String {
            val bytes = ByteArray(TEMP_HEX / 2).also(random::nextBytes)
            return segment + "~" + bytes.joinToString("") { "%02x".format(it) }
        }

        /** `unix:uid` where the file system has the `unix` view; elsewhere no uid, so every owner compares equal. */
        fun defaultOwner(dir: Path): (Path) -> Any? =
            if (dir.fileSystem.supportedFileAttributeViews().contains("unix")) {
                { p: Path -> Files.getAttribute(p, "unix:uid") }
            } else {
                { _: Path -> null }
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
