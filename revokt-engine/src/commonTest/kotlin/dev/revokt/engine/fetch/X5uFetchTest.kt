// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.SyncStage
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The x5u URL rules and cap (spec §7.1 "x5u chain" and the private-mirror paragraph, §9 `data-path (d)`, the #177
 * review's rewrite contract): every refusal happens before any fetch.
 */
class X5uFetchTest {
    private val host = "content-signature-2.cdn.mozilla.net"
    private val path = "/g/chains/202402/onecrl.content-signature.mozilla.org-2026-11-25-18-04-25.chain"
    private val x5u = "https://$host$path"
    private val pem = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"

    private fun refused(
        url: String,
        failure: X5uUrlFailure,
        source: MozillaRemoteSettings = MozillaRemoteSettings.DEFAULT,
    ) {
        val fetcher = ScriptedFetcher { ok(pem) }
        val failed = client(fetcher, source).fetchX5u(url).assertFailed(SyncStage.X5U, ClientFailure.X5U_URL)
        assertTrue(failed.detail.startsWith("$failure:"), "$url: ${failed.detail}")
        assertEquals(0, fetcher.requests.size, "$url: nothing is fetched")
    }

    private fun fetched(
        url: String,
        source: MozillaRemoteSettings = MozillaRemoteSettings.DEFAULT,
    ): String {
        val fetcher = ScriptedFetcher { ok(pem) }
        assertEquals(pem.encodeToByteArray().toByteString(), client(fetcher, source).fetchX5u(url).assertOk())
        val request = fetcher.requests.single()
        assertEquals(mapOf("User-Agent" to "revokt"), request.headers)
        assertEquals(RevoktLimits.MAX_X5U_BYTES, request.maxBodyBytes)
        return request.url
    }

    private fun mirror(
        target: String,
        vararg hosts: String,
    ): MozillaRemoteSettings =
        MozillaRemoteSettings.DEFAULT
            .newBuilder()
            .x5uHosts(setOf(*hosts))
            .x5uHostRewrite(host, target)
            .build()

    @Test
    fun `Mozilla's x5u URL is fetched as given, with the User-Agent and the 64 KiB cap`() {
        assertEquals(x5u, fetched(x5u))
        // An explicit :443 is the default port, dropped from what is fetched.
        assertEquals(x5u, fetched("https://$host:443$path"))
        assertEquals("https://$host/a/b%20c?x=1&y=2", fetched("https://$host/a/b%20c?x=1&y=2"))
    }

    @Test
    fun `data-path (d) a non-allowlisted host, userinfo or port 8443 is FAILED with no fetch`() {
        refused("https://evil.example$path", X5uUrlFailure.HOST)
        refused("https://user@$host$path", X5uUrlFailure.USERINFO)
        refused("https://user:pass@$host$path", X5uUrlFailure.USERINFO)
        refused("https://$host@evil.example$path", X5uUrlFailure.USERINFO)
        refused("https://$host:8443$path", X5uUrlFailure.PORT)
    }

    @Test
    fun `the scheme is https only and the port 443 only`() {
        refused("http://$host$path", X5uUrlFailure.SCHEME)
        refused("HTTPS://$host$path", X5uUrlFailure.SCHEME)
        refused("ftp://$host$path", X5uUrlFailure.SCHEME)
        refused("//$host$path", X5uUrlFailure.SYNTAX)
        refused("$host$path", X5uUrlFailure.SYNTAX)
        refused("", X5uUrlFailure.SYNTAX)
        for (port in listOf("80", "0443", "4430", "", "-443", "443a", "65979")) {
            refused("https://$host:$port$path", X5uUrlFailure.PORT)
        }
    }

    @Test
    fun `hosts are compared exactly and must be plain ASCII DNS names`() {
        refused("https://Content-Signature-2.cdn.mozilla.net$path", X5uUrlFailure.HOST)
        refused("https://$host.$path", X5uUrlFailure.SYNTAX)
        refused("https://content-signature-2.cdn.mozilla.net.evil.example$path", X5uUrlFailure.HOST)
        for (bad in listOf(
            "content-signatüre-2.cdn.mozilla.net",
            "content-signature-2%2Ecdn.mozilla.net",
            "content-signature-2.cdn.mozilla.net\\.evil.example",
            "content-signature-2..cdn.mozilla.net",
            ".content-signature-2.cdn.mozilla.net",
            "[::1]",
            "",
            "a b",
            "a" + "b".repeat(63) + ".net",
            List(130) { "a" }.joinToString(".") + ".net",
        )) {
            refused("https://$bad$path", X5uUrlFailure.SYNTAX)
        }
        refused("https://:443$path", X5uUrlFailure.SYNTAX)
        // A last label that reads as a number is an IPv4 address to WHATWG parsers, not a DNS name.
        for (numeric in listOf("1.2.3.4", "127.1", "2130706433", "0x7f.0.0.1", "a.0x7F", "a.0x", "cdn.mozilla.443")) {
            refused("https://$numeric$path", X5uUrlFailure.SYNTAX)
        }
        val numericLabels =
            MozillaRemoteSettings.DEFAULT
                .newBuilder()
                .x5uHosts(setOf("1a.2b.3c", "x.0xg"))
                .build()
        assertEquals("https://1a.2b.3c$path", fetched("https://1a.2b.3c$path", numericLabels))
        assertEquals("https://x.0xg$path", fetched("https://x.0xg$path", numericLabels))
    }

    @Test
    fun `the path is a plain RFC 3986 path, with no fragment`() {
        refused("https://$host", X5uUrlFailure.SYNTAX)
        refused("https://$host?x", X5uUrlFailure.SYNTAX)
        refused("https://$host#x", X5uUrlFailure.SYNTAX)
        for (bad in listOf(
            "$path#frag",
            "/a b",
            "/a\\b",
            "/a%2",
            "/a%zz",
            "/ü",
            "/a\"b",
            "/a<b>",
            "/a\r\nb",
            "/a{b}",
            "/a|b",
            "/a^b",
        )) {
            refused("https://$host$bad", X5uUrlFailure.SYNTAX)
        }
        assertEquals("https://$host/a%2Fb/-._~!$&'()*+,;=:@", fetched("https://$host/a%2Fb/-._~!$&'()*+,;=:@"))
    }

    @Test
    fun `data-path (d) the rewrite is applied before the allowlist check`() {
        // The original host is not in x5uHosts: only the rewritten one is checked.
        val source = mirror("x5u.mirror.example", "x5u.mirror.example")
        assertEquals("https://x5u.mirror.example$path", fetched(x5u, source))
        assertEquals("https://x5u.mirror.example$path", fetched("https://$host:443$path", source))
        // A host that is not rewritten is checked as is.
        refused("https://other.example$path", X5uUrlFailure.HOST, source)
        // The rewrite key is matched exactly, ASCII case included.
        refused("https://CONTENT-SIGNATURE-2.cdn.mozilla.net$path", X5uUrlFailure.HOST, source)
    }

    @Test
    fun `data-path (d) the rewritten URI is re-parsed and re-checked whole, the port rule included`() {
        // Targets the builder lets through but the x5u grammar does not read as a DNS host name.
        refused(x5u, X5uUrlFailure.SYNTAX, mirror("1.2.3.4", "1.2.3.4"))
        refused(x5u, X5uUrlFailure.SYNTAX, mirror("x5u mirror.example", "x5u mirror.example"))
        refused(x5u, X5uUrlFailure.SYNTAX, mirror("x5u..mirror.example", "x5u..mirror.example"))

        // MozillaRemoteSettings.Builder.build() now refuses these targets (spec §4, revision 56); the re-check still
        // holds for the rewrite map on its own.
        fun rechecked(target: String): X5uUrlFailure? = X5uUrl.check(x5u, setOf(target), mapOf(host to target)).failure
        assertEquals(X5uUrlFailure.PORT, rechecked("x5u.mirror.example:8443"))
        assertEquals(X5uUrlFailure.USERINFO, rechecked("user@x5u.mirror.example"))
        assertEquals(X5uUrlFailure.REWRITE, rechecked("x5u.mirror.example/prefix"))
        assertEquals(X5uUrlFailure.SYNTAX, rechecked("x5u.mirror.example?x"))
        assertEquals(X5uUrlFailure.SYNTAX, rechecked("x5u.mirrör.example"))
        assertEquals(X5uUrlFailure.SYNTAX, rechecked(""))
        // A target of host:443 parses as the host, not the target exactly.
        assertEquals(X5uUrlFailure.REWRITE, rechecked("x5u.mirror.example:443"))
    }

    @Test
    fun `data-path (d) an x5u body over 64 KiB is FAILED, and one of 64 KiB is returned`() {
        val over = ByteArray((RevoktLimits.MAX_X5U_BYTES + 1).toInt())
        client(
            ScriptedFetcher { response(200, over) },
        ).fetchX5u(x5u).assertFailed(SyncStage.X5U, ClientFailure.BODY_TOO_LARGE)
        val atCap = ByteArray(RevoktLimits.MAX_X5U_BYTES.toInt())
        assertEquals(atCap.size, client(ScriptedFetcher { response(200, atCap) }).fetchX5u(x5u).assertOk().size)
    }

    @Test
    fun `the x5u fetch carries stage X5U on every failure`() {
        client(ScriptedFetcher { response(302) }).fetchX5u(x5u).assertFailed(SyncStage.X5U, ClientFailure.HTTP_STATUS)
        client(ScriptedFetcher { response(407) }).fetchX5u(x5u).assertFailed(SyncStage.X5U, ClientFailure.HTTP_STATUS)
        client(ScriptedFetcher { response(304) }).fetchX5u(x5u).assertFailed(SyncStage.X5U, ClientFailure.HTTP_STATUS)
        client(ScriptedFetcher { error("down") }).fetchX5u(x5u).assertFailed(SyncStage.X5U, ClientFailure.FETCHER_THREW)
    }
}
