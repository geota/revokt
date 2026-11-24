// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** [StrictUrl], the grammar of the x5u URL (spec §7.1 "The x5u URL grammar"). */
class StrictUrlTest {
    @Test
    fun `an IP literal is never a host, and the port follows the last colon`() {
        for (host in listOf("127.0.0.1", "[::1]", "[2001:db8::a]", "[::1]:8443", "0x7f.1")) {
            val url = "https://$host/x"
            assertEquals(StrictUrlFailure.HOST, assertIs<StrictUrlRead.Refused>(StrictUrl.parse(url), url).failure)
        }
        val parsed = assertIs<StrictUrlRead.Parsed>(StrictUrl.parse("https://a.example:8443/x?y"))
        assertEquals(Triple("a.example", "8443", "/x?y"), Triple(parsed.host, parsed.port, parsed.rest))
        val bare = assertIs<StrictUrlRead.Parsed>(StrictUrl.parse("https://a.example"))
        assertEquals(null, bare.port)
        assertEquals("", bare.rest)
    }

    @Test
    fun `a host is one java net URI reads as a host`() {
        // #322: java.net.URI's hostname grammar (RFC 2396 §3.2.2): a label starts and ends with a letter or digit,
        // and the last label starts with a letter; anything else is a registry-based authority with a null host.
        val refused = listOf("-.a.example", "-a.example", "a-.example", "a.-b", "a.b-", "x.1a", "x.0xg", "a.9")
        val parsed = listOf("a.example", "1a.example", "a--b.example", "x.a1", "A-1.B2", "a")
        for (host in refused + parsed) {
            val url = "https://$host/"
            val read = StrictUrl.parse(url)
            if (host in refused) {
                assertEquals(StrictUrlFailure.HOST, assertIs<StrictUrlRead.Refused>(read, url).failure)
            } else {
                assertEquals(host, assertIs<StrictUrlRead.Parsed>(read, url).host)
            }
            assertEquals(host in parsed, URI(url).host != null, url)
        }
    }

    @Test
    fun `the path and query grammar is RFC 3986 pchars, slashes and question marks`() {
        assertTrue(StrictUrl.isPathAndQuery(""))
        assertTrue(StrictUrl.isPathAndQuery("/a%2Fb/-._~!$&'()*+,;=:@?x=/?y"))
        for (bad in listOf("/a b", "/a#b", "/a%", "/a%2", "/a%zz", "/a[b]", "/ü", "/a\\b")) {
            assertFalse(StrictUrl.isPathAndQuery(bad), bad)
        }
    }
}
