// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.source
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path

/** The JVM's file-backed seed sources (spec §4), as `JvmStorage` is for storage. */
public object JvmSeedSource {
    /**
     * The archive at [path], re-opened on every start task and seed re-check, so a replaced file is picked up. A missing
     * file opens null; any other I/O failure is thrown to the loader (an unreadable seed).
     */
    @JvmStatic
    public fun fromPath(path: Path): SeedSource =
        SeedSource {
            try {
                Files.newInputStream(path).source()
            } catch (_: NoSuchFileException) {
                null
            }
        }
}
