// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * Which group bits `JvmStorage.directory(…)`'s ownership check tolerates on the store's directories (spec §3);
 * growable. On POSIX the directory must be owned by the process's uid either way; where the file system has no `unix`
 * view (Windows) the check is skipped.
 */
public enum class OwnershipCheck {
    /** Owned by the process's uid and neither group- nor other-writable. */
    STRICT,

    /**
     * As [STRICT], but group-writable is tolerated: the Kubernetes `fsGroup` case. Every member of the group is then
     * inside the store's trust boundary.
     */
    OWNER_OR_GROUP,
}
