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
 * [StrictUrl]'s narrow grammar against the JDK's URL parsers (spec §7.1 "the parsed URI host" and "The x5u URL
 * grammar", #177; the redirect hops of #192): every x5u URL [X5uUrl] lets through is one `java.net.URI` and `java.net.URL`, which
 * `HttpsURLConnection` connects with, read as https to the allowlisted host on port 443 with no userinfo, and every
 * redirect hop [HopUrl] resolves is read by both as https to the host and port [HopUrl] checked, so no fetcher can be
 * pointed at another host than the one checked.
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

    private val hopPieces =
        pieces +
            listOf(
                "mirror.example",
                "MIRROR.Example",
                "127.0.0.1",
                "010.0.0.1",
                "[::1]",
                "[::ffff:192.0.2.1]",
                "[2001:DB8::A]",
                "[1.2.3.4::]",
                "[1:192.0.2.1::]",
                "[fe80::1%25eth0]",
                ":8443",
                ":0",
                "../",
                "./",
                "%2e%2e/",
                "?q=1",
                "#f",
                "//",
                "///",
                "https:",
            )

    private fun assertJdkAgreesHop(hop: HopUrl) {
        val fetched = hop.toString()
        val uri = URI(fetched)
        assertEquals("https", uri.scheme, fetched)
        if (uri.host == null) {
            // A DNS name RFC 2396 does not read as a host (an edge hyphen, `-`; a last label starting with a digit,
            // `a.1b`): URI keeps the authority as a registry name, exactly as written, so a URI-based client connects
            // nowhere rather than to another host.
            assertTrue(StrictUrl.isHostName(hop.host), fetched)
            assertEquals(fetched.substringAfter("://").substringBefore('/'), uri.rawAuthority, fetched)
        } else {
            assertEquals(hop.host, uri.host, fetched)
            assertEquals(hop.port, if (uri.port == -1) 443 else uri.port, fetched)
        }
        assertNull(uri.rawUserInfo, fetched)
        assertNull(uri.rawFragment, fetched)
        val url = URL(fetched)
        assertEquals(hop.host, url.host, fetched)
        assertEquals(hop.port, if (url.port == -1) url.defaultPort else url.port, fetched)
        assertNull(url.userInfo, fetched)
    }

    @Test
    fun `every redirect hop the hop rules let through is its checked host and port to java_net_URI and java_net_URL`() {
        val random = Random(192)
        val bases =
            listOf("https://mirror.example/revocation/manifest.json", "https://[::1]:8443/a/b", "https://10.0.0.1/x?y")
                .map { (HopUrl.parse(it) as HopUrlRead.Parsed).url }
        var absolute = 0
        var relative = 0
        repeat(200_000) {
            val prefix =
                when (random.nextInt(4)) {
                    0 -> ""
                    1 -> "https://"
                    2 -> "//"
                    else -> "/"
                }
            val text =
                prefix + List(random.nextInt(1, 8)) { hopPieces[random.nextInt(hopPieces.size)] }.joinToString("")
            (HopUrl.parse(text) as? HopUrlRead.Parsed)?.let {
                absolute++
                assertJdkAgreesHop(it.url)
            }
            val base = bases[random.nextInt(bases.size)]
            val resolved = (base.resolve(text) as? HopUrlRead.Parsed)?.url ?: return@repeat
            relative++
            assertJdkAgreesHop(resolved)
            // A reference with no authority of its own keeps the base's host and port, whatever its path holds.
            if (!text.startsWith("//") && !text.startsWith("https:")) {
                assertEquals(base.host to base.port, resolved.host to resolved.port, text)
            }
        }
        assertTrue(absolute > 1_000, "the generator reached the accepting grammar: $absolute")
        assertTrue(relative > 20_000, "the generator reached the accepting resolution: $relative")
    }

    @Test
    fun `known parser-differential shapes are refused as redirect hops`() {
        val base = (HopUrl.parse("https://mirror.example/a") as HopUrlRead.Parsed).url
        for (location in listOf(
            "https://mirror.example\\@evil.example/x",
            "https://evil.example\\@mirror.example/x",
            "https:\\\\evil.example/x",
            "/\\evil.example/x",
            "\\\\evil.example/x",
            "https://mirror.example%2F@evil.example/x",
            "https://mirror.example:443@evil.example/x",
            "https://evil.example%2Fmirror.example/x",
            "https://mirror.example%00.evil.example/x",
            "https://mirror.example\t/x",
            "https:/evil.example/x",
            "https:evil.example/x",
            "https://[mirror.example]/x",
            "https://0x7f.0.0.1/x",
            "https://2130706433/x",
            "https://[::1]@evil.example/x",
            "https://[::ffff:7f00:1]%2F@evil.example/x",
        )) {
            assertTrue(base.resolve(location) is HopUrlRead.Refused, location)
        }
        // What follows a '#' is a fragment to every parser, so the host is the one before it, and the fragment is dropped.
        val fragment = (base.resolve("https://evil.example#@mirror.example/x") as HopUrlRead.Parsed).url
        assertEquals("https://evil.example/", fragment.toString())
        assertEquals("evil.example", URI("https://evil.example#@mirror.example/x").host)
    }
}
