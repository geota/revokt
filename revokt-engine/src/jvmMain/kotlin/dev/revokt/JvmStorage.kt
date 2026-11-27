// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt

import dev.revokt.engine.store.DirectoryStorage
import java.nio.file.Path

/** The JVM's durable storage (spec §3), as `JvmSeedSource` is for seeds. */
public object JvmStorage {
    /**
     * The durable store in directory [dir], which `start()` creates rwx------ when absent; this call does no I/O. Give
     * each process and channel its own dedicated directory, never a volume's mount point, and never one shared across
     * hosts.
     *
     * On POSIX [dir] and every directory under it must be owned by the process's uid and pass [ownership]'s mode rule.
     * If they do not, or another process holds the store's lock, or the directory is not empty and not a revokt store,
     * `start()` logs a warning (`STORE_UNREADABLE`, `STORE_LOCKED`) and the instance runs in memory for the life of the
     * process, without retrying. A store written by a newer revokt gets [onNewerLayout].
     */
    @JvmStatic
    @JvmOverloads
    public fun directory(
        dir: Path,
        ownership: OwnershipCheck = OwnershipCheck.STRICT,
        onNewerLayout: NewerLayout = NewerLayout.IN_MEMORY,
    ): RevoktStorage = BackedStorage(DirectoryStorage(dir, ownership, onNewerLayout), isInMemory = false)
}
