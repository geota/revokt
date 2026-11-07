// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `RevoktStorage.inMemory()` (spec §3, #109). */
class RevoktStorageTest {
    private val store = RevoktStorage.inMemory()

    @Test
    fun `a written key reads back and is listed, a deleted one is gone`() {
        assertNull(store.read("a/b"))
        store.write("a/b", byteArrayOf(1, 2))
        store.write("c", byteArrayOf(3))
        assertContentEquals(byteArrayOf(1, 2), store.read("a/b"))
        assertEquals(setOf("a/b", "c"), store.names())
        store.write("a/b", byteArrayOf(4))
        assertContentEquals(byteArrayOf(4), store.read("a/b"))
        store.delete("a/b")
        assertNull(store.read("a/b"))
        assertEquals(setOf("c"), store.names())
        store.delete("a/b")
        store.delete("never")
        assertEquals(setOf("c"), store.names())
    }

    @Test
    fun `the store keeps its own copies`() {
        val bytes = byteArrayOf(1, 2, 3)
        store.write("k", bytes)
        bytes[0] = 9
        val read = assertNotNullRead("k")
        assertContentEquals(byteArrayOf(1, 2, 3), read)
        read[1] = 9
        assertContentEquals(byteArrayOf(1, 2, 3), store.read("k"))
        val names = store.names()
        store.write("other", byteArrayOf())
        assertEquals(setOf("k"), names)
    }

    @Test
    fun `an empty file is a file`() {
        store.write("empty", byteArrayOf())
        assertContentEquals(byteArrayOf(), store.read("empty"))
        assertEquals(setOf("empty"), store.names())
    }

    @Test
    fun `deleting the last key under a directory leaves no directory behind`() {
        store.write("d/x", byteArrayOf(1))
        store.delete("d/x")
        assertEquals(emptySet(), store.names())
        store.write("d", byteArrayOf(2))
        assertContentEquals(byteArrayOf(2), store.read("d"))
    }

    @Test
    fun `a key cannot sit under a file, nor a file over a directory`() {
        store.write("a/b", byteArrayOf(1))
        assertFailsWith<IllegalArgumentException> { store.write("a", byteArrayOf(2)) }
        assertFailsWith<IllegalArgumentException> { store.write("a/b/c", byteArrayOf(2)) }
        assertFailsWith<IllegalArgumentException> { store.write("a/b/c/d", byteArrayOf(2)) }
        assertEquals(setOf("a/b"), store.names())
        assertNull(store.read("a"))
        store.write("ab", byteArrayOf(3))
        store.write("a/bc", byteArrayOf(3))
        assertEquals(setOf("a/b", "ab", "a/bc"), store.names())
    }

    @Test
    fun `every method refuses a name that is not a key, the lock included`() {
        val rejected =
            listOf(
                "",
                ".",
                "..",
                "a//b",
                "/x",
                "x/",
                "a/../b",
                "../x",
                "x".repeat(97),
                ".lock",
                "abc\n",
                "a\\b",
                "a\u0000b",
                "é",
                "a b",
            )
        for (name in rejected) {
            assertFailsWith<IllegalArgumentException>(name) { store.read(name) }
            assertFailsWith<IllegalArgumentException>(name) { store.write(name, byteArrayOf(1)) }
            assertFailsWith<IllegalArgumentException>(name) { store.delete(name) }
        }
        assertEquals(emptySet(), store.names())
        store.write("x".repeat(96), byteArrayOf(1))
        assertEquals(setOf("x".repeat(96)), store.names())
    }

    @Test
    fun `identity is null and lock holds nothing`() {
        assertNull(store.identity())
        val first = store.lock()
        val second = store.lock()
        second.close()
        first.close()
        first.close()
        store.lock().use { store.write("k", byteArrayOf(1)) }
        assertTrue("k" in store.names())
    }

    @Test
    fun `StoreLockedException carries its message and cause`() {
        val cause = IllegalStateException("held")
        val e = StoreLockedException("locked", cause)
        assertEquals("locked", e.message)
        assertEquals(cause, e.cause)
        assertNull(StoreLockedException("locked").cause)
    }

    @Test
    fun `each call is a separate store`() {
        store.write("k", byteArrayOf(1))
        assertNull(RevoktStorage.inMemory().read("k"))
    }

    private fun assertNotNullRead(name: String): ByteArray = kotlin.test.assertNotNull(store.read(name))
}
