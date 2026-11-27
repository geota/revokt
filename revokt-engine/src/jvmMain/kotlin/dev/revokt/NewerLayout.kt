// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/** What a store whose `store.version` is higher than this engine's gets (spec §3, §6.5); growable. */
public enum class NewerLayout {
    /**
     * Left untouched and unlocked: the instance runs in memory for the life of the process (`STORE_NEWER_LAYOUT`). The
     * `JvmStorage.directory(…)` default, for a directory a newer binary may share.
     */
    IN_MEMORY,

    /**
     * Rebuilt as a lower version is: every key deleted, then rebuilt from the seed. For a directory one binary owns, where
     * a higher version can only be a rollback to an older build.
     */
    REBUILD,
}
