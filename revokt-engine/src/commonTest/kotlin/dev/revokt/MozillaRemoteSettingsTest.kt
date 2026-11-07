// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

/** `MozillaRemoteSettings` as spec §4 and §7.1 declare it (#111): the §7.1 defaults and the one build-time check. */
class MozillaRemoteSettingsTest {
    private val mozillaX5u = "content-signature-2.cdn.mozilla.net"

    @Test
    fun `DEFAULT carries the section 7_1 values and pins root-ca-production-amo`() {
        val d = MozillaRemoteSettings.DEFAULT
        assertEquals("https://firefox.settings.services.mozilla.com/v1", d.baseUrl)
        assertEquals("security-state", d.bucket)
        assertEquals("cert-revocations", d.collection(Dataset.CRLITE))
        assertEquals("https://firefox-settings-attachments.cdn.mozilla.net/", d.attachmentBaseUrl)
        assertEquals(setOf(mozillaX5u), d.x5uHosts)
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
    fun `a rewrite target outside x5uHosts throws from build`() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                MozillaRemoteSettings.Builder().x5uHostRewrite(mozillaX5u, "mirror.example").build()
            }
        assertTrue("mirror.example" in e.message.orEmpty(), e.message)
        // Membership is exact, so a target that differs only in case is outside the set.
        assertFailsWith<IllegalArgumentException> {
            MozillaRemoteSettings
                .Builder()
                .x5uHosts(setOf("mirror.example"))
                .x5uHostRewrite(mozillaX5u, "Mirror.example")
                .build()
        }
        // The check runs at build(), over the final set: replacing x5uHosts after the rewrite drops the target.
        assertFailsWith<IllegalArgumentException> {
            MozillaRemoteSettings
                .Builder()
                .x5uHosts(setOf("mirror.example"))
                .x5uHostRewrite(mozillaX5u, "mirror.example")
                .x5uHosts(setOf(mozillaX5u))
                .build()
        }
    }

    @Test
    fun `a rewrite target in x5uHosts builds, and a later rewrite of the same host replaces the first`() {
        val mirror =
            MozillaRemoteSettings
                .Builder()
                .baseUrl("https://mirror.example/v1")
                .attachmentBaseUrl("https://mirror.example/attachments/")
                .x5uHosts(setOf("mirror.example", "other.example"))
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
        val hosts = setOf("user@mirror.example", "mirror.example:8443")
        assertEquals(
            hosts,
            MozillaRemoteSettings
                .Builder()
                .x5uHosts(hosts)
                .build()
                .x5uHosts,
        )
        // An empty allowlist and an empty pin set build too: every x5u fetch, or every chain, then fails closed.
        assertEquals(
            emptySet(),
            MozillaRemoteSettings
                .Builder()
                .x5uHosts(emptySet())
                .build()
                .x5uHosts,
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
    fun `the builder copies the host set`() {
        val hosts = mutableSetOf("mirror.example")
        val builder = MozillaRemoteSettings.Builder().x5uHosts(hosts)
        hosts += "other.example"
        assertEquals(setOf("mirror.example"), builder.build().x5uHosts)
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
                .x5uHosts(setOf("mirror.example"))
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
                { x5uHosts(setOf(mozillaX5u, "mirror.example")) },
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
            "attachmentBaseUrl=https://firefox-settings-attachments.cdn.mozilla.net/",
            "x5uHosts=[$mozillaX5u]",
            "x5uHostRewrites={}",
            "pinnedRootSpkiSha256s=[3317fa45154ac7da55694d3782316056471fc147c04aed3e03ffe99565b1e2e7]",
            "userAgent=revokt",
            "sourceId=mozilla-remote-settings",
        )) {
            assertTrue(part in s, s)
        }
    }
}
