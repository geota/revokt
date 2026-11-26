// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The `RevoktStorage` key rule (spec §3, #109 and its name-hardening comment). */
class StoreKeysTest {
    @Test
    fun `segments of the key characters joined by a slash are keys`() {
        for (key in listOf(
            "a",
            "current",
            "crlite/compat/updater.json",
            "crlite/compat/gen-1762430400000-dc148ce178adeca2/meta.json",
            "crlite/compat/blobs/" + "0".repeat(64),
            "a-z_.0-9",
            "...",
            ".a",
            "a.",
            "a.lock",
            "store.version",
            "a/store.versions",
            "a/x.store.version",
            "x".repeat(96),
            "x".repeat(96) + "/" + "y".repeat(96),
        )) {
            assertTrue(StoreKeys.isKey(key), key)
        }
    }

    @Test
    fun `dot, empty or long segments, a reserved segment, uppercase and any other character are not keys`() {
        for (key in listOf(
            "",
            ".",
            "..",
            "a/.",
            "a/..",
            "./a",
            "../x",
            "a/../b",
            "a/./b",
            "/x",
            "x/",
            "a//b",
            "/",
            "x".repeat(97),
            "a/" + "x".repeat(97),
            ".lock",
            "a/.lock",
            "a/.lock/b",
            ".lock/b",
            "crlite/store.version",
            "store.version/x",
            ".LOCK",
            ".Lock",
            "A-Z_a-z.0-9",
            "A",
            "crlite/COMPAT/current",
            "abc\n",
            "\nabc",
            "a\nb",
            "a\\b",
            "a\u0000b",
            "a\u0000",
            "é",
            "aé",
            "ａ",
            "a b",
            "a:b",
            "C:x",
            "a\tb",
            "a\rb",
        )) {
            assertFalse(StoreKeys.isKey(key), key.toList().joinToString { it.code.toString(16) })
        }
    }
}
