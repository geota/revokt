// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The configured `c2spMirror` URL (spec §4 R bullets, §7.3 "The base"), read at `build()` by [HopUrl.parse] (the
 * maintainer's decisions on #192: IP literals allowed, a port from 1 to 65535).
 */
class C2spMirrorSourceTest {
    private fun base(url: String): String = C2spMirrorSource.Builder(url).build().baseUrl

    @Test
    fun `a URL without a trailing slash gets one, so every file is the URL, a slash and its name`() {
        val source = C2spMirrorSource.Builder("https://upki.rustls.dev/revocation").build()
        assertEquals("https://upki.rustls.dev/revocation/", source.baseUrl)
        assertEquals("https://upki.rustls.dev/revocation/manifest.json", source.manifestUrl)
        assertEquals("https://upki.rustls.dev/revocation/a.filter", source.fileUrl("a.filter"))
        assertEquals("https://upki.rustls.dev/revocation/", base("https://upki.rustls.dev/revocation/"))
        assertEquals("https://upki.rustls.dev/", base("https://upki.rustls.dev"))
    }

    @Test
    fun `the base is the URL as HopUrl re-serialised it`() {
        assertEquals("https://mirror.example/a/", base("https://MIRROR.Example:443/a/b/../"))
        assertEquals("https://mirror.example:8443/r/", base("https://mirror.example:8443/r"))
    }

    @Test
    fun `IP literals and any port from 1 to 65535 are allowed`() {
        assertEquals("https://10.0.0.1:1/", base("https://10.0.0.1:1"))
        assertEquals("https://[2001:db8::1]:65535/r/", base("https://[2001:DB8::1]:65535/r/"))
        for (port in listOf("0", "65536", "")) {
            assertFailsWith<IllegalArgumentException>(port) { base("https://mirror.example:$port/") }
        }
    }

    @Test
    fun `fixture (e) - a c2spMirror URL with a query or a fragment throws IllegalArgumentException at build`() {
        for (url in listOf(
            "https://m.example/r/?a=1",
            "https://m.example/r/?",
            "https://m.example/r/#x",
            "https://m.example/r/#",
        )) {
            assertFailsWith<IllegalArgumentException>(url) { base(url) }
        }
    }

    @Test
    fun `a URL that is not https, carries userinfo or breaks the grammar throws at build`() {
        for (url in listOf(
            "http://m.example/",
            "HTTPS://m.example/",
            "https://user@m.example/",
            "https://user:pw@m.example/",
            "https://m.example/a b/",
            "https://m.example/%zz/",
            "ftp://m.example/",
            "m.example/r/",
            "",
        )) {
            assertFailsWith<IllegalArgumentException>(url) { base(url) }
        }
    }

    @Test
    fun `the source id defaults to c2spMirror and an empty one throws`() {
        assertEquals("c2spMirror", C2spMirrorSource.Builder("https://m.example/").build().sourceId)
        assertEquals(
            "mine",
            C2spMirrorSource
                .Builder("https://m.example/")
                .sourceId("mine")
                .build()
                .sourceId,
        )
        assertFailsWith<IllegalArgumentException> {
            C2spMirrorSource
                .Builder(
                    "https://m.example/",
                ).sourceId("")
                .build()
        }
    }
}
