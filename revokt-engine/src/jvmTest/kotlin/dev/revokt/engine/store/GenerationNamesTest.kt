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
 * Spec §6.5's derived names (revision 48) and the content-addressed key shape. The expected hashes were computed outside the
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
    fun `isSha256Hex accepts exactly 64 lowercase hex characters`() {
        assertTrue(GenerationNames.isSha256Hex("0123456789abcdef".repeat(4)))
        for (bad in listOf("0".repeat(63), "0".repeat(65), "A".repeat(64), "g".repeat(64), "")) {
            assertFalse(GenerationNames.isSha256Hex(bad), bad)
        }
    }
}
