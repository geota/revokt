// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt

import dev.revokt.engine.store.DirectoryStorage
import dev.revokt.engine.store.InMemoryStorage
import dev.revokt.engine.store.StorageBackend
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * `RevoktStorage.inMemory()` (spec §3, #109): the contract, and what only the in-memory store does; and the public
 * factories, `inMemory()`, `JvmStorage.directory(…)` and the internal `of(…)`, over the sealed type.
 */
class RevoktStorageTest : RevoktStorageContract() {
    override val store: StorageBackend = RevoktStorage.inMemory().backend

    @Test
    fun `identity is the instance, and lock holds nothing`() {
        assertSame(store, store.identity())
        assertNotSame(store.identity(), RevoktStorage.inMemory().backend.identity())
        val first = store.lock()
        val second = store.lock()
        second.close()
        first.close()
        first.close()
        store.lock().use { store.write("k", byteArrayOf(1)) }
        assertTrue("k" in store.names())
    }

    @Test
    fun `each call is a separate store`() {
        store.write("k", byteArrayOf(1))
        assertNull(RevoktStorage.inMemory().backend.read("k"))
    }

    @Test
    fun `inMemory is in memory, and of is only when its backend is`() {
        assertTrue(RevoktStorage.inMemory().isInMemory)
        assertIs<InMemoryStorage>(RevoktStorage.inMemory().backend)
        assertTrue(RevoktStorage.of(InMemoryStorage()).isInMemory)
        val wrapped = object : StorageBackend by InMemoryStorage() {}
        val of = RevoktStorage.of(wrapped)
        assertFalse(of.isInMemory)
        assertSame(wrapped, of.backend)
    }

    @Test
    fun `directory does no I O, is not in memory, and carries its options with spec section 3's defaults`() {
        val dir = Files.createTempDirectory("revokt-storage")
        try {
            val root = dir.resolve("a/store")
            val plain = JvmStorage.directory(root)
            assertFalse(Files.exists(dir.resolve("a")), "no I/O")
            assertFalse(plain.isInMemory)
            val backend = assertIs<DirectoryStorage>(plain.backend)
            assertEquals(NewerLayout.IN_MEMORY, backend.onNewerLayout)
            assertEquals(OwnershipCheck.STRICT, backend.ownership)
            val rebuild = JvmStorage.directory(root, OwnershipCheck.OWNER_OR_GROUP, NewerLayout.REBUILD)
            val rebuildBackend = assertIs<DirectoryStorage>(rebuild.backend)
            assertEquals(NewerLayout.REBUILD, rebuildBackend.onNewerLayout)
            assertEquals(OwnershipCheck.OWNER_OR_GROUP, rebuildBackend.ownership)
            assertEquals(
                OwnershipCheck.OWNER_OR_GROUP,
                assertIs<DirectoryStorage>(JvmStorage.directory(root, OwnershipCheck.OWNER_OR_GROUP).backend).ownership,
            )
            assertFalse(Files.exists(dir.resolve("a")), "no I/O")
        } finally {
            dir.toFile().deleteRecursively()
        }
    }
}
