// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.OwnershipCheck
import java.nio.channels.FileChannel
import java.nio.file.FileSystem
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

/**
 * What `DirectoryStorage` does differently where the file system is POSIX (spec §3), chosen once per store, so that the
 * decisions themselves ([ownershipFault]) are plain functions tested on every OS.
 */
internal enum class StoragePlatform {
    /** Modes rw------- and rwx------, a directory fsync through a read-only channel, and the ownership check. */
    POSIX {
        override fun createDirectory(dir: Path) {
            Files.createDirectory(dir, DIRECTORY_MODE)
        }

        override fun createFile(path: Path) {
            Files.createFile(path, FILE_MODE)
        }

        override fun open(
            path: Path,
            options: Set<OpenOption>,
        ): FileChannel = FileChannel.open(path, options, FILE_MODE)

        override fun syncDirectory(dir: Path) {
            FileChannel.open(dir, StandardOpenOption.READ).use { it.force(true) }
        }

        override val moveRetryMillis: Long = 0

        override fun processOwner(
            base: Path,
            owner: (Path) -> Any?,
        ): Any? {
            val probe = base.resolve(DirectoryStorage.tempName("probe"))
            createFile(probe)
            try {
                return owner(probe)
            } finally {
                Files.deleteIfExists(probe)
            }
        }

        override fun directoryFault(
            dir: Path,
            ownership: OwnershipCheck,
            mine: Any?,
            owner: (Path) -> Any?,
        ): String? =
            ownershipFault(Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS), ownership, mine, owner(dir))

        override fun modeFault(
            dir: Path,
            ownership: OwnershipCheck,
        ): String? = modeFault(Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS), ownership)
    },

    /** Windows: default modes, no directory fsync (a directory cannot be opened), no ownership check. */
    OTHER {
        override fun createDirectory(dir: Path) {
            Files.createDirectory(dir)
        }

        override fun createFile(path: Path) {
            Files.createFile(path)
        }

        override fun open(
            path: Path,
            options: Set<OpenOption>,
        ): FileChannel = FileChannel.open(path, options)

        override fun syncDirectory(dir: Path) {
            // Skipped: FileChannel cannot open a directory here (spec §3).
        }

        override val moveRetryMillis: Long = DirectoryStorage.MOVE_RETRY_MILLIS

        override fun processOwner(
            base: Path,
            owner: (Path) -> Any?,
        ): Any? = null

        override fun directoryFault(
            dir: Path,
            ownership: OwnershipCheck,
            mine: Any?,
            owner: (Path) -> Any?,
        ): String? = null

        override fun modeFault(
            dir: Path,
            ownership: OwnershipCheck,
        ): String? = null
    }, ;

    /** Creates directory [dir], rwx------ on POSIX; follows no link at [dir]. */
    abstract fun createDirectory(dir: Path)

    /** Creates [path] new (`CREATE_NEW`, so no link is followed), rw------- on POSIX. */
    abstract fun createFile(path: Path)

    /** Opens [path] with [options], a file it creates being rw------- on POSIX. */
    abstract fun open(
        path: Path,
        options: Set<OpenOption>,
    ): FileChannel

    /** Forces directory [dir]'s entries to the device, where a directory can be opened. */
    abstract fun syncDirectory(dir: Path)

    /** How long a rename over an open target is retried (spec §3: Windows only). */
    abstract val moveRetryMillis: Long

    /**
     * The process's owner, on POSIX the uid of a probe file this call creates under a temp name in [base] and deletes
     * (the JVM has no getuid); null where there is no ownership check.
     */
    abstract fun processOwner(
        base: Path,
        owner: (Path) -> Any?,
    ): Any?

    /** Why [dir]'s mode is not owner-only under [ownership], or null; on POSIX only, and read before any probe is written. */
    abstract fun modeFault(
        dir: Path,
        ownership: OwnershipCheck,
    ): String?

    /** Why directory [dir] is not this process's ([mine]) under [ownership], or null: on POSIX its mode and its owner. */
    abstract fun directoryFault(
        dir: Path,
        ownership: OwnershipCheck,
        mine: Any?,
        owner: (Path) -> Any?,
    ): String?

    companion object {
        private val FILE_MODE = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
        private val DIRECTORY_MODE = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))

        fun of(fileSystem: FileSystem): StoragePlatform =
            if (fileSystem.supportedFileAttributeViews().contains("posix")) POSIX else OTHER

        /**
         * The ownership rule (spec §3): never other-writable; group-writable only under [OwnershipCheck.OWNER_OR_GROUP];
         * the root's owner [theirs] is the process's [mine]. Null when the root passes.
         */
        fun ownershipFault(
            mode: Set<PosixFilePermission>,
            ownership: OwnershipCheck,
            mine: Any?,
            theirs: Any?,
        ): String? = modeFault(mode, ownership) ?: if (mine != theirs) "owned by uid $theirs, not $mine" else null

        /** The mode half of [ownershipFault]: never other-writable; group-writable only under `OWNER_OR_GROUP`. */
        fun modeFault(
            mode: Set<PosixFilePermission>,
            ownership: OwnershipCheck,
        ): String? =
            when {
                PosixFilePermission.OTHERS_WRITE in mode -> {
                    "writable by others: ${PosixFilePermissions.toString(mode)}"
                }

                ownership == OwnershipCheck.STRICT && PosixFilePermission.GROUP_WRITE in mode -> {
                    "group-writable under STRICT: ${PosixFilePermissions.toString(mode)}"
                }

                else -> {
                    null
                }
            }
    }
}
