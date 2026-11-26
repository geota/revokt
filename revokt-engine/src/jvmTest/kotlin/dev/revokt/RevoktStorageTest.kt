// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `RevoktStorage.inMemory()` (spec §3, #109): the contract, and what only the in-memory store does. */
class RevoktStorageTest : RevoktStorageContract() {
    override val store: RevoktStorage = RevoktStorage.inMemory()

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
    fun `each call is a separate store`() {
        store.write("k", byteArrayOf(1))
        assertNull(RevoktStorage.inMemory().read("k"))
    }
}
