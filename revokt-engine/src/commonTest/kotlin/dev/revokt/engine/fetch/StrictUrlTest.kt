// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

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
    fun `the path and query grammar is RFC 3986 pchars, slashes and question marks`() {
        assertTrue(StrictUrl.isPathAndQuery(""))
        assertTrue(StrictUrl.isPathAndQuery("/a%2Fb/-._~!$&'()*+,;=:@?x=/?y"))
        for (bad in listOf("/a b", "/a#b", "/a%", "/a%2", "/a%zz", "/a[b]", "/ü", "/a\\b")) {
            assertFalse(StrictUrl.isPathAndQuery(bad), bad)
        }
    }
}
