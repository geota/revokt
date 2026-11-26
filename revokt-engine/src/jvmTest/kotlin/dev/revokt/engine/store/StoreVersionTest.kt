// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** `store.version`'s grammar (spec §6.5): ASCII `[1-9][0-9]{0,8}` and nothing else; the writer writes `1`. */
class StoreVersionTest {
    @Test
    fun `the grammar's versions parse and round-trip`() {
        for ((text, version) in listOf("1" to 1, "2" to 2, "9" to 9, "10" to 10, "999999999" to 999_999_999)) {
            assertEquals(version, StoreVersion.parse(text.encodeToByteArray()), text)
            assertContentEquals(text.encodeToByteArray(), StoreVersion.encode(version))
        }
        assertContentEquals("1".encodeToByteArray(), StoreVersion.encode(StoreVersion.CURRENT))
    }

    @Test
    fun `anything else is malformed`() {
        val malformed =
            listOf("", "0", "00", "01", "1\n", "1\r\n", " 1", "1 ", "+1", "-1", "1a", "a", "1000000000", "1.0", "١")
        for (text in malformed) assertNull(StoreVersion.parse(text.encodeToByteArray()), "'$text'")
        // A byte above ASCII, alone and after a digit; a NUL after a digit.
        for (bytes in listOf(
            byteArrayOf(0xB1.toByte()),
            byteArrayOf('1'.code.toByte(), 0x80.toByte()),
            byteArrayOf(0x31, 0),
        )) {
            assertNull(StoreVersion.parse(bytes), bytes.contentToString())
        }
    }

    @Test
    fun `the writer refuses a version the grammar cannot hold`() {
        assertFailsWith<IllegalArgumentException> { StoreVersion.encode(0) }
        assertFailsWith<IllegalArgumentException> { StoreVersion.encode(-1) }
        assertFailsWith<IllegalStateException> { StoreVersion.encode(1_000_000_000) }
    }
}
