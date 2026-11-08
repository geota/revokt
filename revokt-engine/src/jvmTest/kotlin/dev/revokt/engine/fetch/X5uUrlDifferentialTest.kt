// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import java.net.URI
import java.net.URL
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [X5uUrl]'s narrow grammar against the JDK's URL parsers (spec §7.1 "the parsed URI host", #177): every URL it lets
 * through is one `java.net.URI` and `java.net.URL`, which `HttpsURLConnection` connects with, read as https to the
 * allowlisted host on port 443 with no userinfo, so no fetcher can be pointed at another host than the one checked.
 */
class X5uUrlDifferentialTest {
    private val host = "content-signature-2.cdn.mozilla.net"
    private val mirror = "x5u.mirror.example"

    private val pieces =
        listOf(
            "https://",
            "http://",
            "HTTPS://",
            host,
            mirror,
            "evil.example",
            "@",
            ":",
            "443",
            "8443",
            "/",
            "//",
            "?",
            "#",
            "\\",
            "%2e",
            "%40",
            "%2F",
            "%",
            ".",
            "..",
            "a",
            " ",
            "[",
            "]",
            "[::1]",
            "\t",
            "ü",
            "%00",
            ";",
            "&",
            "=",
            "'",
            "user",
            "-",
            "_",
            "~",
            "\r\n",
            "\u0000",
            "*",
            "!",
            "$",
            "(",
            ")",
        )

    private fun assertJdkAgrees(fetched: String) {
        val uri = URI(fetched)
        assertEquals("https", uri.scheme, fetched)
        assertTrue(uri.host == host || uri.host == mirror, "URI host ${uri.host} of $fetched")
        assertTrue(uri.port == -1 || uri.port == 443, "URI port ${uri.port} of $fetched")
        assertNull(uri.rawUserInfo, fetched)
        assertNull(uri.rawFragment, fetched)
        val url = URL(fetched)
        assertEquals(uri.host, url.host, fetched)
        assertEquals(443, if (url.port == -1) url.defaultPort else url.port, fetched)
        assertNull(url.userInfo, fetched)
    }

    @Test
    fun `every URL the x5u rules let through is the allowlisted host on 443 to java_net_URI and java_net_URL`() {
        val random = Random(129)
        var allowed = 0
        repeat(200_000) {
            val prefix =
                when (random.nextInt(3)) {
                    0 -> ""
                    1 -> "https://" + (if (random.nextBoolean()) host else mirror)
                    else -> "https://" + (if (random.nextBoolean()) host else mirror) + "/"
                }
            val url = prefix + List(random.nextInt(1, 8)) { pieces[random.nextInt(pieces.size)] }.joinToString("")
            val rewrites = if (random.nextBoolean()) mapOf(host to mirror) else emptyMap()
            val checked = X5uUrl.check(url, setOf(host, mirror), rewrites)
            val fetched = checked.url ?: return@repeat
            allowed++
            assertJdkAgrees(fetched)
            // The input itself reads the same way wherever the JDK accepts it.
            val original = runCatching { URI(url) }.getOrNull()
            if (original != null) {
                assertEquals(
                    fetched.substringAfter("://").substringBefore('/').substringBefore('?'),
                    rewrites[original.host] ?: original.host,
                    url,
                )
            }
        }
        assertTrue(allowed > 10_000, "the generator reached the accepting grammar: $allowed")
    }

    @Test
    fun `known parser-differential shapes are refused`() {
        for (url in listOf(
            "https://$host\\@evil.example/x",
            "https://evil.example\\@$host/x",
            "https://evil.example#@$host/x",
            "https://evil.example?@$host/x",
            "https://$host%2F@evil.example/x",
            "https://$host:443@evil.example/x",
            "https://evil.example%2F$host/x",
            "https://$host%00.evil.example/x",
            "https://$host./x",
            "https://$host\t/x",
            "https://$host /x",
            "https:/$host/x",
            "https:$host/x",
            "https://[$host]/x",
            "https://0x7f.0.0.1/x",
        )) {
            assertNull(X5uUrl.check(url, setOf(host), emptyMap()).url, url)
        }
    }
}
