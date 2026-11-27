// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.store

import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktStorageContract
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.ExperimentalPathApi
import kotlin.io.path.deleteRecursively
import kotlin.test.AfterTest

/** The `RevoktStorage` contract (spec §3) over `DirectoryStorage` on a real temporary directory. */
class JvmStorageContractTest : RevoktStorageContract() {
    private val dir: Path = Files.createTempDirectory("revokt-contract")
    override val store: StorageBackend = DirectoryStorage(dir.resolve("store"))

    @OptIn(ExperimentalPathApi::class)
    @AfterTest
    fun cleanUp() {
        dir.deleteRecursively()
    }
}
