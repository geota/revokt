// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.engine.c2sp.C2spIndex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec §6.5's derived names (revision 48) and generation directory names. The expected hashes were computed outside the
 * engine, with `printf %s <name> | shasum -a 256`.
 */
class GenerationNamesTest {
    @Test
    fun `a filename of at most 32 bytes is its own name`() {
        assertEquals("compat-2026-11-06-delta-0123.bin", GenerationNames.derive("compat-2026-11-06-delta-0123.bin"))
        assertEquals("a", GenerationNames.derive("a"))
        assertEquals("x".repeat(32), GenerationNames.derive("x".repeat(32)))
    }

    @Test
    fun `a 33-byte filename becomes its first 15 characters, a dash and 16 hex of its SHA-256`() {
        val name = GenerationNames.derive("compat-2026-11-06-delta-01234.bin")
        assertEquals("compat-2026-11--31041d40a1b14a73", name)
        assertEquals(GenerationNames.DERIVED_LENGTH, name.length)
        assertEquals("aaaaaaaaaaaaaaa-852785c805c77e71", GenerationNames.derive("a".repeat(33)))
    }

    @Test
    fun `a 64-byte filename becomes 32 characters`() {
        val long = "compat-2026-11-06-full-filter-with-a-very-long-name-012345678.ff"
        assertEquals(64, long.length)
        assertEquals("compat-2026-11--decf10cbc971a35f", GenerationNames.derive(long))
        assertEquals("ZZZZZZZZZZZZZZZ-cc7321cce5e4409b", GenerationNames.derive("Z".repeat(64)))
    }

    @Test
    fun `every derived name is a C2SP filename and a key segment`() {
        for (length in 1..64) {
            val name = GenerationNames.derive("n".repeat(length))
            assertTrue(C2spIndex.isFilename(name), name)
            assertTrue(StoreKeys.isKey(name), name)
        }
    }

    @Test
    fun `a name outside the source filename rule is refused`() {
        for (bad in listOf(
            "",
            ".",
            "..",
            "x".repeat(65),
            "a/b",
            "/x",
            "../x",
            "a\\b",
            "abc\n",
            "a\u0000",
            "é",
            "a b",
        )) {
            assertFalse(GenerationNames.isSourceFilename(bad), bad)
            assertFailsWith<IllegalArgumentException>(bad) { GenerationNames.derive(bad) }
        }
        for (good in listOf(
            "...",
            ".a",
            "x".repeat(64),
            "A-Z_a-z.0-9",
        )) {
            assertTrue(GenerationNames.isSourceFilename(good), good)
        }
    }

    @Test
    fun `a directory is gen, the 13-digit timestamp and 16 hex of the SHA-256 of the generation id`() {
        assertEquals(
            "gen-1762430400000-dc148ce178adeca2",
            GenerationNames.directory(1_762_430_400_000, "crlite/compat/2026-11-06T12:00:00Z"),
        )
        assertEquals("gen-0000000000005-711430f6164e9380", GenerationNames.directory(5, "g1"))
        assertEquals("gen-0000000000000-711430f6164e9380", GenerationNames.directory(0, "g1"))
        assertEquals("gen-9999999999999-711430f6164e9380", GenerationNames.directory(9_999_999_999_999, "g1"))
    }

    @Test
    fun `directory names sort chronologically`() {
        val times = listOf(5L, 40L, 999L, 1_000L, 1_762_430_400_000L, 9_999_999_999_999L)
        assertEquals(times, times.shuffled().sortedBy { GenerationNames.directory(it, "g$it") }.toList())
    }

    @Test
    fun `a timestamp outside 13 digits and an empty id are refused`() {
        assertFailsWith<IllegalArgumentException> { GenerationNames.directory(-1, "g1") }
        assertFailsWith<IllegalArgumentException> { GenerationNames.directory(10_000_000_000_000, "g1") }
        assertFailsWith<IllegalArgumentException> { GenerationNames.directory(1, "") }
    }

    @Test
    fun `isDirectory accepts exactly the directory shape`() {
        assertTrue(GenerationNames.isDirectory("gen-1762430400000-dc148ce178adeca2"))
        for (bad in listOf(
            "gen-1762430400000-dc148ce178adeca",
            "gen-1762430400000-dc148ce178adeca22",
            "gen-176243040000-dc148ce178adeca22",
            "gen-1762430400000-DC148CE178ADECA2",
            "gen-1762430400000-dc148ce178adecag",
            "gen-17624304000a0-dc148ce178adeca2",
            "gen-1762430400000_dc148ce178adeca2",
            "gen_1762430400000-dc148ce178adeca2",
            "Gen-1762430400000-dc148ce178adeca2",
            "blobs",
            "",
        )) {
            assertFalse(GenerationNames.isDirectory(bad), bad)
        }
    }

    @Test
    fun `isSha256Hex accepts exactly 64 lowercase hex characters`() {
        assertTrue(GenerationNames.isSha256Hex("0123456789abcdef".repeat(4)))
        for (bad in listOf("0".repeat(63), "0".repeat(65), "A".repeat(64), "g".repeat(64), "")) {
            assertFalse(GenerationNames.isSha256Hex(bad), bad)
        }
    }
}
