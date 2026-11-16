// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.RevoktLimits
import dev.revokt.engine.store.GenerationNames
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** A C2SP mirror's `manifest.json` (spec §7.3, upki v1.0.1's `Manifest`) and §7.3's manifest-name rules (revision 52). */
class C2spManifestTest {
    private val hash = "ab".repeat(32)

    private fun parse(json: String): ManifestRead = C2spManifest.parse(json.encodeUtf8(), RevoktLimits.MAX_JSON_BYTES)

    private fun parsed(json: String): C2spManifest = assertIs<ManifestRead.Parsed>(parse(json), json).manifest

    private fun malformed(json: String) {
        assertIs<ManifestRead.Malformed>(parse(json), json)
    }

    private fun entry(
        filename: String,
        size: Long = 1,
        hash: String = this.hash,
    ): ManifestFile = ManifestFile(filename, size, hash)

    private fun check(vararg files: ManifestFile): ManifestCheck = ManifestNames.check(files.toList())

    private fun refused(vararg files: ManifestFile) {
        assertIs<ManifestCheck.Refused>(check(*files), files.joinToString())
    }

    @Test
    fun `upki's manifest shape is read, files or its alias filters, and other members are allowed`() {
        val files = """[{"filename":"a.filter","size":3,"hash":"$hash","extra":1}]"""
        val m = parsed("""{"generated_at":1762400000,"comment":"upki-mirror","files":$files,"other":true}""")
        assertEquals(1_762_400_000uL, m.generatedAt)
        assertEquals("upki-mirror", m.comment)
        assertEquals(listOf("a.filter"), m.files.map { it.filename })
        assertEquals(3, m.files.single().size)
        // fixture (e): a manifest with filters for files installs (revision 56).
        assertEquals(1, parsed("""{"generated_at":0,"comment":"","filters":$files}""").files.size)
        assertEquals(0, parsed("""{"generated_at":0,"comment":"","files":[]}""").files.size)
        // generated_at is a u64; a size beyond Long saturates, so every cap refuses it.
        val u64 = "18446744073709551615"
        val big = parsed("""{"generated_at":0,"comment":"","files":[{"filename":"a","size":$u64,"hash":"$hash"}]}""")
        assertEquals(Long.MAX_VALUE, big.files.single().size)
    }

    @Test
    fun `fixture (e) - a manifest without comment is FAILED, and so is any other shape that is not upki's`() {
        val f = """[{"filename":"a","size":1,"hash":"$hash"}]"""
        for (json in listOf(
            """{"generated_at":0,"files":$f}""",
            """{"generated_at":0,"comment":1,"files":$f}""",
            """{"comment":"","files":$f}""",
            """{"generated_at":-1,"comment":"","files":$f}""",
            """{"generated_at":1.5,"comment":"","files":$f}""",
            """{"generated_at":"0","comment":"","files":$f}""",
            """{"generated_at":0,"comment":""}""",
            """{"generated_at":0,"comment":"","files":{}}""",
            """{"generated_at":0,"comment":"","files":$f,"filters":$f}""",
            """{"generated_at":0,"comment":"","files":[1]}""",
            """{"generated_at":0,"comment":"","files":[{"size":1,"hash":"$hash"}]}""",
            """{"generated_at":0,"comment":"","files":[{"filename":1,"size":1,"hash":"$hash"}]}""",
            """{"generated_at":0,"comment":"","files":[{"filename":"a","hash":"$hash"}]}""",
            """{"generated_at":0,"comment":"","files":[{"filename":"a","size":-1,"hash":"$hash"}]}""",
            """{"generated_at":0,"comment":"","files":[{"filename":"a","size":1}]}""",
            """{"generated_at":0,"comment":"","files":[{"filename":"a","size":1,"hash":7}]}""",
            """{"generated_at":0,"generated_at":0,"comment":"","files":[]}""",
            """[]""",
            """not json""",
        )) {
            malformed(json)
        }
    }

    @Test
    fun `generated_at runs to 9999-12-30T22-00-00Z, the last second upki's jiff Timestamp accepts`() {
        val last = "253402207200"
        assertEquals(253_402_207_200uL, parsed("""{"generated_at":$last,"comment":"","files":[]}""").generatedAt)
        for (past in listOf("253402207201", "253402300799", "9223372036854775807", "18446744073709551615")) {
            malformed("""{"generated_at":$past,"comment":"","files":[]}""")
        }
    }

    @Test
    fun `a manifest over MAX_JSON_BYTES is not read`() {
        val padding = " ".repeat(RevoktLimits.MAX_JSON_BYTES.toInt())
        malformed("""{"generated_at":0,"comment":"","files":[]}$padding""")
    }

    @Test
    fun `fixture (e) - a manifest naming dot, dot-dot, a path, a reserved name or a trailing dot is refused`() {
        for (name in listOf(
            ".",
            "..",
            "../x",
            "/x",
            "a/b",
            "META.JSON",
            "meta.json.",
            "Index.Bin",
            "CURRENT",
            ".LOCK",
            "",
            "a b",
            "é",
            "x".repeat(65),
        )) {
            refused(entry("a.filter"), entry(name))
        }
    }

    @Test
    fun `fixture (e) - two files whose names are equal ignoring ASCII case are refused`() {
        refused(entry("a.filter"), entry("A.FILTER"))
        refused(entry("a.filter"), entry("a.filter"))
        // Over 32 bytes the derived names differ (the hash is of the exact bytes), so the filenames themselves are
        // compared ignoring case.
        val long = "abcdefghijklmnopqrstuvwxyz0123456789"
        refused(entry(long), entry(long.uppercase()))
        refused(entry(long), entry(long))
    }

    @Test
    fun `fixture (e) - a hash of 63 or 65 hex characters or holding a non-hex character is refused`() {
        for (bad in listOf("a".repeat(63), "a".repeat(65), "g" + "a".repeat(63), "", "ab".repeat(31) + "a ")) {
            refused(entry("a.filter", hash = bad))
        }
    }

    @Test
    fun `a hash in either case names the lowercase blob key`() {
        val upper = "AB".repeat(32)
        val file = assertIs<ManifestCheck.Checked>(check(entry("a.filter", hash = upper))).files.single()
        assertEquals(hash.decodeHex(), file.sha256)
        assertEquals(hash, file.sha256.hex())
    }

    @Test
    fun `fixture (e) - a 33-byte name is named by its derived name, and 64 bytes is the longest`() {
        val long = "x".repeat(33)
        val longest = "y".repeat(64)
        val checked = assertIs<ManifestCheck.Checked>(check(entry("a.filter"), entry(long), entry(longest))).files
        assertEquals(listOf("a.filter", long, longest), checked.map { it.filename })
        assertEquals(
            listOf("a.filter", GenerationNames.derive(long), GenerationNames.derive(longest)),
            checked.map { it.name },
        )
        assertEquals(32, checked[1].name.length)
    }

    @Test
    fun `names in the generation are unique ignoring ASCII case, a derived name included`() {
        val long = "Abcdefghijklmnopqrstuvwxyz0123456789"
        val derived = GenerationNames.derive(long)
        // A short name equal to another file's derived name, in another case, would share its index entry.
        refused(entry(long), entry(derived.uppercase()))
        assertTrue(check(entry(long), entry("a.filter")) is ManifestCheck.Checked)
    }

    @Test
    fun `every reserved name is refused in any case`() {
        for (reserved in AttachmentName.RESERVED) {
            refused(entry(reserved))
            refused(entry(reserved.uppercase()))
        }
    }
}
