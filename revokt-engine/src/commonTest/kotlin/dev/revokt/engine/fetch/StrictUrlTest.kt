// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** [StrictUrl], the grammar of the x5u URL (spec §7.1 "The x5u URL grammar"), also used by the redirect hops (#192). */
class StrictUrlTest {
    @Test
    fun `IP literals are hosts only when the caller allows them`() {
        for (host in listOf("127.0.0.1", "[::1]", "[2001:db8::a]")) {
            val url = "https://$host/x"
            assertEquals(host, assertIs<StrictUrlRead.Parsed>(StrictUrl.parse(url, ipLiterals = true), url).host)
            assertEquals(
                StrictUrlFailure.HOST,
                assertIs<StrictUrlRead.Refused>(StrictUrl.parse(url, false), url).failure,
            )
        }
    }

    @Test
    fun `a bracketed host's port follows the bracket`() {
        val parsed = assertIs<StrictUrlRead.Parsed>(StrictUrl.parse("https://[::1]:8443/x?y", ipLiterals = true))
        assertEquals(Triple("[::1]", "8443", "/x?y"), Triple(parsed.host, parsed.port, parsed.rest))
        val bare = assertIs<StrictUrlRead.Parsed>(StrictUrl.parse("https://[::1]", ipLiterals = true))
        assertEquals(null, bare.port)
        assertEquals("", bare.rest)
    }

    @Test
    fun `IPv4 is four decimal octets with no leading zero`() {
        for (good in listOf("0.0.0.0", "1.2.3.4", "255.255.255.255", "10.0.0.1", "192.0.2.10")) {
            assertTrue(StrictUrl.isIpv4(good), good)
        }
        for (bad in listOf(
            "1.2.3",
            "1.2.3.4.5",
            "256.1.1.1",
            "01.2.3.4",
            "1.2.3.04",
            "1..3.4",
            "a.b.c.d",
            "1.2.3.4.",
            "0x7f.0.0.1",
            "",
            "1.2.3.1000",
        )) {
            assertFalse(StrictUrl.isIpv4(bad), bad)
        }
    }

    @Test
    fun `IPv6 is eight groups, or fewer around one double colon, bracketed`() {
        for (good in listOf(
            "[::]",
            "[::1]",
            "[1::]",
            "[1:2:3:4:5:6:7:8]",
            "[1::8]",
            "[1:2:3:4:5:6:7::]",
            "[::2:3:4:5:6:7:8]",
            "[ABCD:ef01::1]",
            "[::ffff:192.0.2.1]",
            "[1:2:3:4:5:6:192.0.2.1]",
            "[1::5:6:192.0.2.1]",
        )) {
            assertTrue(StrictUrl.isIpv6Literal(good), good)
        }
        for (bad in listOf(
            "::1",
            "[::1",
            "::1]",
            "[]",
            "[:]",
            "[:::]",
            "[1:2:3:4:5:6:7]",
            "[1:2:3:4:5:6:7:8:9]",
            "[1:2:3:4:5:6:7:8::]",
            "[1::2::3]",
            "[:1::2]",
            "[1::2:]",
            "[12345::1]",
            "[g::1]",
            "[fe80::1%25eth0]",
            "[v1.x]",
            "[::192.0.2.1:1]",
            "[1:2:3:4:5:6:7:192.0.2.1]",
            "[::ffff:192.0.2.256]",
            "[::1.2.3]",
            "[1.2.3.4::]",
            "[1:1.2.3.4::]",
            "[a:b:c:d:e:1.2.3.4::]",
        )) {
            assertFalse(StrictUrl.isIpv6Literal(bad), bad)
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
