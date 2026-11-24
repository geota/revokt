// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt

import dev.revokt.engine.fetch.X5uUrl
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

/** `MozillaRemoteSettings` as spec §4 and §7.1 declare it (#111): the §7.1 defaults and the two build-time checks. */
class MozillaRemoteSettingsTest {
    private val mozillaX5u = "content-signature-2.cdn.mozilla.net"
    private val mozillaCdn = "cdn.mozilla.net"

    @Test
    fun `DEFAULT carries the section 7_1 values and pins root-ca-production-amo`() {
        val d = MozillaRemoteSettings.DEFAULT
        assertEquals("https://firefox.settings.services.mozilla.com/v1", d.baseUrl)
        assertEquals("security-state", d.bucket)
        assertEquals("cert-revocations", d.collection(Dataset.CRLITE))
        // The attachment base is read from the server (spec §7.1), under Mozilla's CDN domain.
        assertEquals(null, d.attachmentBaseUrl)
        assertEquals(setOf(mozillaCdn), d.allowedDomains)
        assertEquals(emptyMap(), d.x5uHostRewrites)
        assertEquals("mozilla-remote-settings", d.sourceId)
        assertEquals("revokt", d.userAgent)
        // Spec §7.1 and Appendix A (revision 49), the hex written out here rather than shared with the main code.
        val amo = "3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7".decodeHex()
        assertEquals(listOf(amo), d.pinnedRootSpkiSha256s.map { it.toByteString() })
        assertEquals(setOf(amo), d.pinnedRootSpkis)
        // The builder starts from DEFAULT, so a mirror configuration keeps the pin.
        assertEquals(d, MozillaRemoteSettings.Builder().build())
    }

    @Test
    fun `a rewrite target outside allowedDomains throws from build`() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                MozillaRemoteSettings.Builder().x5uHostRewrite(mozillaX5u, "mirror.example").build()
            }
        assertTrue("mirror.example" in e.message.orEmpty(), e.message)
        // The rule is exact, so a target that differs only in case is outside it, and a suffix must be a whole label.
        for (target in listOf("Mirror.example", "evilmirror.example", "mirror.example.org")) {
            assertFailsWith<IllegalArgumentException>(target) {
                MozillaRemoteSettings
                    .Builder()
                    .allowedDomains(setOf("mirror.example"))
                    .x5uHostRewrite(mozillaX5u, target)
                    .build()
            }
        }
        // The check runs at build(), over the final set: replacing allowedDomains after the rewrite drops the target.
        assertFailsWith<IllegalArgumentException> {
            MozillaRemoteSettings
                .Builder()
                .allowedDomains(setOf("mirror.example"))
                .x5uHostRewrite(mozillaX5u, "mirror.example")
                .allowedDomains(setOf(mozillaCdn))
                .build()
        }
        // A target under an allowed domain, at any depth, builds.
        MozillaRemoteSettings.Builder().x5uHostRewrite(mozillaX5u, "a.b.cdn.mozilla.net").build()
    }

    @Test
    fun `an allowedDomains entry or a rewrite side that is not a DNS host name throws from build`() {
        val label63 = "a".repeat(63)
        val name253 = listOf(label63, label63, label63, "a".repeat(61)).joinToString(".")
        // Spec §4 and §9's API rows (revision 56), then the rest of the x5u URL grammar's host rule (spec §7.1).
        val notHostNames =
            listOf(
                "mirror.example:443",
                "user@mirror.example",
                "mirror.example/x",
                "mirror.example?x",
                "mirror.example#x",
                "[::1]",
                "mirrör.example",
                "mirror\u0080.example",
                "",
                "mirror.example.",
                "mirror..example",
                ".mirror.example",
                "mirror example",
                "mirror\t.example",
                "mirror\u0000.example",
                "mirror\u007F.example",
                "mirror\\.example",
                "mirror%2Eexample",
                "mirror_x.example",
                "*.mirror.example",
                "a".repeat(64) + ".example",
                name253.dropLast(1) + "ab",
                "1.2.3.4",
                "0x7f.1",
                "mirror.0x",
                "mirror.443",
                // #322: labels start and end with a letter or digit, and the last starts with a letter, as
                // java.net.URI reads a host.
                "-.mirror.example",
                "-mirror.example",
                "mirror-.example",
                "mirror.-example",
                "mirror.example-",
                "x.0xg",
                "1a.2b.3c",
            )
        // Each builder against the reason build() reports first: the allowedDomains entries are checked before the
        // rewrites.
        val cases =
            listOf<Pair<String, (String) -> MozillaRemoteSettings.Builder>>(
                "allowedDomains entry" to
                    { bad -> MozillaRemoteSettings.Builder().allowedDomains(setOf(mozillaCdn, bad)) },
                "allowedDomains entry" to { bad ->
                    MozillaRemoteSettings
                        .Builder()
                        .allowedDomains(setOf(mozillaCdn, bad))
                        .x5uHostRewrite(mozillaX5u, bad)
                },
                "x5uHostRewrite to" to { bad -> MozillaRemoteSettings.Builder().x5uHostRewrite(mozillaX5u, bad) },
                "x5uHostRewrite from" to { bad -> MozillaRemoteSettings.Builder().x5uHostRewrite(bad, mozillaX5u) },
            )
        for (bad in notHostNames) {
            for ((reason, builder) in cases) {
                val e = assertFailsWith<IllegalArgumentException>("$reason \"$bad\"") { builder(bad).build() }
                assertTrue(e.message.orEmpty().startsWith("$reason \"$bad\" is not a DNS host name"), e.message)
            }
        }
        // DEFAULT's host is one, and DEFAULT builds.
        assertEquals(MozillaRemoteSettings.DEFAULT, MozillaRemoteSettings.DEFAULT.newBuilder().build())
        assertEquals(MozillaRemoteSettings.DEFAULT, MozillaRemoteSettings.Builder().build())
        // At the edges of the grammar: upper case (hosts are compared exactly), a 63-character label, a 253-character
        // name, numeric labels that are not last, a last label with digits after its first letter, and hyphens inside
        // a label. A single label is a host name too, but not a domain to allow.
        val domains = setOf("Mirror.Example", "$label63.example", name253, "1a.2b.c3", "1.2.3.a-b", "a--b.x0g")
        val built =
            MozillaRemoteSettings
                .Builder()
                .allowedDomains(domains)
                .apply { for (h in domains) x5uHostRewrite(h, h) }
                .x5uHostRewrite("mirror", "Mirror.Example")
                .build()
        assertEquals(domains, built.allowedDomains)
        // build() and the fetch-time check accept exactly the same host names.
        val hostNames = domains + "mirror"
        for (h in notHostNames + hostNames) {
            assertEquals(h in hostNames, X5uUrl.check("https://$h/x", setOf(h), emptyMap()).url != null, h)
        }
    }

    @Test
    fun `a single-label allowedDomains entry throws from build, since it would allow a whole TLD`() {
        for (label in listOf("net", "org", "mirror", "Example")) {
            val e =
                assertFailsWith<IllegalArgumentException>(label) {
                    MozillaRemoteSettings.Builder().allowedDomains(setOf(mozillaCdn, label)).build()
                }
            assertEquals(
                "allowedDomains entry \"$label\" is a single label, which would allow a whole top-level domain " +
                    "(spec §4, §7.1)",
                e.message,
            )
        }
        // Two labels build, a public suffix included: the rule is the operator's, and only the single label is refused.
        MozillaRemoteSettings.Builder().allowedDomains(setOf("mozilla.net", "co.uk")).build()
    }

    @Test
    fun `a rewrite target under allowedDomains builds, and a later rewrite of the same host replaces the first`() {
        val mirror =
            MozillaRemoteSettings
                .Builder()
                .baseUrl("https://mirror.example/v1")
                .attachmentBaseUrl("https://mirror.example/attachments/")
                .allowedDomains(setOf("mirror.example", "other.example"))
                .x5uHostRewrite(mozillaX5u, "other.example")
                .x5uHostRewrite(mozillaX5u, "mirror.example")
                .build()
        assertEquals(mapOf(mozillaX5u to "mirror.example"), mirror.x5uHostRewrites)
        assertEquals(MozillaRemoteSettings.DEFAULT.pinnedRootSpkis, mirror.pinnedRootSpkis)
        assertEquals("mozilla-remote-settings", mirror.sourceId)
    }

    @Test
    fun `URLs are not checked here - http, userinfo and a non-443 port all build`() {
        // Spec §4: the https and no-userinfo rule is Revokt.Builder.build()'s (#139); the port-443 rule is the fetch-time
        // x5u rule (#129), and nothing rejects a base URL's port.
        for (url in listOf(
            "http://mirror.example/v1",
            "https://user:pw@mirror.example/v1",
            "https://mirror.example:8443/v1",
        )) {
            val s =
                MozillaRemoteSettings
                    .Builder()
                    .baseUrl(url)
                    .attachmentBaseUrl(url)
                    .build()
            assertEquals(url, s.baseUrl)
            assertEquals(url, s.attachmentBaseUrl)
        }
        // An empty domain set and an empty pin set build too: every x5u fetch and server base, or every chain, then
        // fails closed.
        assertEquals(
            emptySet(),
            MozillaRemoteSettings
                .Builder()
                .allowedDomains(emptySet())
                .build()
                .allowedDomains,
        )
        // A pinned base is cleared back to the server's with null.
        assertEquals(
            MozillaRemoteSettings.DEFAULT,
            MozillaRemoteSettings
                .Builder()
                .attachmentBaseUrl("https://mirror.example/a/")
                .attachmentBaseUrl(null)
                .build(),
        )
        assertEquals(
            emptyList(),
            MozillaRemoteSettings
                .Builder()
                .pinnedRootSpkiSha256s(emptyList())
                .build()
                .pinnedRootSpkiSha256s,
        )
    }

    @Test
    fun `pinnedRootSpkiSha256s copies its input and compares by content`() {
        val a = ByteArray(32) { 1 }
        val b = ByteArray(32) { 2 }
        val builder = MozillaRemoteSettings.Builder().pinnedRootSpkiSha256s(listOf(a, b, a.copyOf()))
        a[0] = 9
        val s = builder.build()
        assertEquals(
            listOf(
                ByteArray(32) {
                    1
                }.toByteString(),
                b.toByteString(),
            ),
            s.pinnedRootSpkiSha256s.map { it.toByteString() },
        )
        // A getter returns fresh copies.
        s.pinnedRootSpkiSha256s[0][0] = 7
        assertContentEquals(ByteArray(32) { 1 }, s.pinnedRootSpkiSha256s[0])
        assertNotSame(s.pinnedRootSpkiSha256s[0], s.pinnedRootSpkiSha256s[0])
        // Equal content in other arrays is an equal configuration.
        assertEquals(
            s,
            MozillaRemoteSettings.Builder().pinnedRootSpkiSha256s(listOf(ByteArray(32) { 1 }, b.copyOf())).build(),
        )
    }

    @Test
    fun `the builder copies the domain set`() {
        val domains = mutableSetOf("mirror.example")
        val builder = MozillaRemoteSettings.Builder().allowedDomains(domains)
        domains += "other.example"
        assertEquals(setOf("mirror.example"), builder.build().allowedDomains)
    }

    @Test
    fun `equal inputs are equal, newBuilder round-trips, and every field takes part`() {
        val full =
            MozillaRemoteSettings
                .Builder()
                .baseUrl("https://mirror.example/v2")
                .bucket("b")
                .collection(Dataset.CRLITE, "c")
                .attachmentBaseUrl("https://mirror.example/a/")
                .allowedDomains(setOf("mirror.example"))
                .x5uHostRewrite(mozillaX5u, "mirror.example")
                .pinnedRootSpkiSha256s(listOf(ByteArray(32) { 3 }))
                .userAgent("ua")
                .sourceId("mirror")
                .build()
        val again = full.newBuilder().build()
        assertEquals(full, again)
        assertEquals(full.hashCode(), again.hashCode())
        assertEquals(full.toString(), again.toString())
        assertEquals(MozillaRemoteSettings.DEFAULT, MozillaRemoteSettings.DEFAULT.newBuilder().build())
        val d = MozillaRemoteSettings.DEFAULT
        val variants =
            listOf<MozillaRemoteSettings.Builder.() -> Unit>(
                { baseUrl("https://firefox.settings.services.mozilla.com/v2") },
                { bucket("main") },
                { collection(Dataset.CRLITE, "intermediates") },
                { attachmentBaseUrl("https://firefox-settings-attachments.cdn.mozilla.net") },
                { allowedDomains(setOf(mozillaCdn, "mirror.example")) },
                { x5uHostRewrite("mirror.example", mozillaX5u) },
                { pinnedRootSpkiSha256s(listOf(ByteArray(32))) },
                { userAgent("other") },
                { sourceId("other") },
            )
        for (change in variants) assertNotEquals(d, d.newBuilder().apply(change).build())
        assertNotEquals<Any>(d, "settings")
    }

    @Test
    fun `toString names every field, a pin as hex`() {
        val s = MozillaRemoteSettings.DEFAULT.toString()
        for (part in listOf(
            "baseUrl=https://firefox.settings.services.mozilla.com/v1",
            "bucket=security-state",
            "CRLITE=cert-revocations",
            "attachmentBaseUrl=null",
            "allowedDomains=[$mozillaCdn]",
            "x5uHostRewrites={}",
            "pinnedRootSpkiSha256s=[3317fa45154ac7da55694d3782316056471fc147c04aed3e03ffe99565b1e2e7]",
            "userAgent=revokt",
            "sourceId=mozilla-remote-settings",
        )) {
            assertTrue(part in s, s)
        }
    }
}
