// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** Spec §5.1 declarations: `LruMap`, bounded and access-ordered. */
class LruMapTest {
    @Test
    fun `lru map evicts the least recently inserted entry when untouched`() {
        val m = LruMap<Int, String>(2)
        m.put(1, "a")
        m.put(2, "b")
        m.put(3, "c")
        assertEquals(2, m.size)
        assertNull(m[1])
        assertEquals("b", m[2])
        assertEquals("c", m[3])
    }

    @Test
    fun `lru map get refreshes an entry`() {
        val m = LruMap<Int, String>(2)
        m.put(1, "a")
        m.put(2, "b")
        assertEquals("a", m[1])
        m.put(3, "c")
        assertEquals("a", m[1])
        assertNull(m[2])
        assertEquals("c", m[3])
    }

    @Test
    fun `lru map put replaces and refreshes an existing key without growing`() {
        val m = LruMap<Int, String>(2)
        m.put(1, "a")
        m.put(2, "b")
        m.put(1, "a2")
        assertEquals(2, m.size)
        m.put(3, "c")
        assertEquals("a2", m[1])
        assertNull(m[2])
    }

    @Test
    fun `lru map a miss changes nothing`() {
        val m = LruMap<Int, String>(1)
        assertNull(m[1])
        assertEquals(0, m.size)
        m.put(1, "a")
        assertNull(m[2])
        m.put(2, "b")
        assertNull(m[1])
        assertEquals("b", m[2])
        assertEquals(1, m.size)
    }

    @Test
    fun `lru map rejects a capacity below one`() {
        assertFailsWith<IllegalArgumentException> { LruMap<Int, Int>(0) }
        assertFailsWith<IllegalArgumentException> { LruMap<Int, Int>(-1) }
    }
}
