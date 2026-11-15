// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** [HopUrl]'s reading and reference resolution (spec §7.3 "Redirects": a relative `Location` resolves, RFC 3986 §5). */
class HopUrlTest {
    private fun parsed(url: String): HopUrl = assertIs<HopUrlRead.Parsed>(HopUrl.parse(url), url).url

    private fun resolved(
        base: String,
        reference: String,
    ): String = assertIs<HopUrlRead.Parsed>(parsed(base).resolve(reference), reference).url.toString()

    private fun refused(
        base: String,
        reference: String,
    ): StrictUrlFailure = assertIs<HopUrlRead.Refused>(parsed(base).resolve(reference), reference).failure

    @Test
    fun `RFC 3986 section 5_4 reference resolution examples, over https`() {
        // RFC 3986 §5.4.1 and §5.4.2 with the base http://a/b/c/d;p?q made https; the scheme-relative "//g" gains the
        // root path, and "g:h" or "http:g" are refused (no `https://`).
        val base = "https://a/b/c/d;p?q"
        val examples =
            mapOf(
                "g" to "https://a/b/c/g",
                "./g" to "https://a/b/c/g",
                "g/" to "https://a/b/c/g/",
                "/g" to "https://a/g",
                "//g" to "https://g/",
                "?y" to "https://a/b/c/d;p?y",
                "g?y" to "https://a/b/c/g?y",
                "#s" to "https://a/b/c/d;p?q",
                "g#s" to "https://a/b/c/g",
                "g?y#s" to "https://a/b/c/g?y",
                ";x" to "https://a/b/c/;x",
                "g;x" to "https://a/b/c/g;x",
                "g;x?y#s" to "https://a/b/c/g;x?y",
                "" to "https://a/b/c/d;p?q",
                "." to "https://a/b/c/",
                "./" to "https://a/b/c/",
                ".." to "https://a/b/",
                "../" to "https://a/b/",
                "../g" to "https://a/b/g",
                "../.." to "https://a/",
                "../../" to "https://a/",
                "../../g" to "https://a/g",
                "../../../g" to "https://a/g",
                "../../../../g" to "https://a/g",
                "/./g" to "https://a/g",
                "/../g" to "https://a/g",
                "g." to "https://a/b/c/g.",
                ".g" to "https://a/b/c/.g",
                "g.." to "https://a/b/c/g..",
                "..g" to "https://a/b/c/..g",
                "./../g" to "https://a/b/g",
                "./g/." to "https://a/b/c/g/",
                "g/./h" to "https://a/b/c/g/h",
                "g/../h" to "https://a/b/c/h",
                "g;x=1/./y" to "https://a/b/c/g;x=1/y",
                "g;x=1/../y" to "https://a/b/c/y",
                "g?y/./x" to "https://a/b/c/g?y/./x",
                "g?y/../x" to "https://a/b/c/g?y/../x",
                "g#s/./x" to "https://a/b/c/g",
                "g#s/../x" to "https://a/b/c/g",
                "https://g/x" to "https://g/x",
            )
        for ((reference, expected) in examples) assertEquals(expected, resolved(base, reference), reference)
        assertEquals(StrictUrlFailure.SYNTAX, refused(base, "g:h"))
        assertEquals(StrictUrlFailure.SYNTAX, refused(base, "http:g"))
        assertEquals(StrictUrlFailure.SCHEME, refused(base, "http://g"))
    }

    @Test
    fun `a URL is re-serialised with its scheme and host lowercased, 443 dropped and the fragment gone`() {
        assertEquals("https://cdn.example/A/b?Q=1", parsed("https://CDN.Example:443/A/b?Q=1#F").toString())
        assertEquals("https://cdn.example:8443/", parsed("https://cdn.example:8443").toString())
        assertEquals("https://cdn.example/a/c", parsed("https://cdn.example/a/b/../c").toString())
        // %2E is not a dot segment here, and escapes are kept as written.
        assertEquals("https://cdn.example/a/%2E%2e/c", parsed("https://cdn.example/a/%2E%2e/c").toString())
    }

    @Test
    fun `origins differ by host or port, never by path or query`() {
        val url = parsed("https://cdn.example/a")
        assertEquals(false, url.isCrossOrigin(parsed("https://CDN.example:443/b?x")))
        assertEquals(true, url.isCrossOrigin(parsed("https://cdn.example:8443/a")))
        assertEquals(true, url.isCrossOrigin(parsed("https://other.example/a")))
        assertEquals(443, url.port)
        assertEquals("cdn.example", url.host)
    }

    @Test
    fun `equality is by the re-serialised URL`() {
        assertEquals(parsed("https://CDN.example:443/a#x"), parsed("https://cdn.example/a"))
        assertEquals(parsed("https://CDN.example:443/a#x").hashCode(), parsed("https://cdn.example/a").hashCode())
        assertEquals(false, parsed("https://cdn.example/a").equals("https://cdn.example/a"))
    }

    @Test
    fun `a reference with no scheme, a bad scheme name or an empty authority is refused`() {
        assertEquals(StrictUrlFailure.SYNTAX, (HopUrl.parse("cdn.example/a") as HopUrlRead.Refused).failure)
        assertEquals(StrictUrlFailure.SYNTAX, (HopUrl.parse("/a") as HopUrlRead.Refused).failure)
        assertEquals(StrictUrlFailure.SCHEME, (HopUrl.parse("HttpS://cdn.example/a") as HopUrlRead.Refused).failure)
        assertEquals(StrictUrlFailure.SCHEME, (HopUrl.parse("1https://cdn.example/a") as HopUrlRead.Refused).failure)
        assertEquals(StrictUrlFailure.HOST, refused("https://cdn.example/", "//"))
        // A first segment holding ':' after a character no scheme allows is a relative path.
        assertEquals("https://cdn.example/a_b:c", resolved("https://cdn.example/", "a_b:c"))
    }
}
