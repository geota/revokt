// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.SyncStage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The attachment base of spec §7.1: [MozillaRemoteSettings.attachmentBaseUrl] when pinned, else the server root's
 * `capabilities.attachments.base_url` under `allowedDomains`, with no fallback.
 */
class AttachmentBaseTest {
    private val root = "https://firefox.settings.services.mozilla.com/v1/"
    private val cdn = "https://firefox-settings-attachments.cdn.mozilla.net/"

    private fun served(baseUrl: String): String = """{"capabilities":{"attachments":{"base_url":"$baseUrl"}}}"""

    private fun read(
        body: String,
        source: MozillaRemoteSettings = MozillaRemoteSettings.DEFAULT,
    ): Pair<ClientResult<String>, ScriptedFetcher> {
        val fetcher = ScriptedFetcher { ok(body) }
        return client(fetcher, source).attachmentBase() to fetcher
    }

    private fun refused(
        body: String,
        source: MozillaRemoteSettings = MozillaRemoteSettings.DEFAULT,
    ) {
        val failed = read(body, source).first.assertFailed(SyncStage.ATTACHMENT, ClientFailure.ATTACHMENT_BASE)
        assertEquals(200, failed.httpStatus, body)
    }

    @Test
    fun `the server's base_url under cdn_mozilla_net is read from the server root`() {
        val (result, fetcher) = read(served(cdn))
        assertEquals(cdn, result.assertOk())
        val request = fetcher.requests.single()
        assertEquals(root, request.url)
        assertEquals(mapOf("User-Agent" to "revokt"), request.headers)
        assertEquals(RevoktLimits.MAX_JSON_BYTES, request.maxBodyBytes)
        // Any host under the domain, the domain itself, an explicit :443 (dropped) and a deeper path.
        for ((given, used) in listOf(
            "https://other.cdn.mozilla.net/a/b/" to "https://other.cdn.mozilla.net/a/b/",
            "https://cdn.mozilla.net/" to "https://cdn.mozilla.net/",
            "https://firefox-settings-attachments.cdn.mozilla.net:443/" to cdn,
            "https://firefox-settings-attachments.cdn.mozilla.net" to
                "https://firefox-settings-attachments.cdn.mozilla.net",
        )) {
            assertEquals(used, read(served(given)).first.assertOk(), given)
        }
    }

    @Test
    fun `a base_url that fails the URL rules or the domain rule is FAILED at ATTACHMENT, with no fallback`() {
        for (bad in listOf(
            "http://firefox-settings-attachments.cdn.mozilla.net/",
            "HTTPS://firefox-settings-attachments.cdn.mozilla.net/",
            "https://user@firefox-settings-attachments.cdn.mozilla.net/",
            "https://firefox-settings-attachments.cdn.mozilla.net:8443/",
            "https://firefox-settings-attachments.cdn.mozilla.net/?x=1",
            "https://firefox-settings-attachments.cdn.mozilla.net/#x",
            "https://firefox-settings-attachments.cdn.mozilla.net/a b/",
            "https://evil.example/",
            "https://evilcdn.mozilla.net/",
            "https://mozilla.net/",
            "https://cdn.mozilla.net.evil.example/",
            "https://firefox-settings-attachments.CDN.mozilla.net/",
            "https://1.2.3.4/",
            "https://[::1]/",
            "//firefox-settings-attachments.cdn.mozilla.net/",
            "",
        )) {
            refused(served(bad))
        }
    }

    @Test
    fun `a server root that is not the capabilities shape is FAILED at ATTACHMENT`() {
        for (body in listOf(
            "not json",
            "[]",
            "{}",
            """{"capabilities":{}}""",
            """{"capabilities":{"attachments":{}}}""",
            """{"capabilities":{"attachments":{"base_url":null}}}""",
            """{"capabilities":{"attachments":{"base_url":["$cdn"]}}}""",
            """{"capabilities":{"attachments":"$cdn"}}""",
        )) {
            refused(body)
        }
        // A failed fetch keeps the client's own failure, at stage ATTACHMENT.
        client(ScriptedFetcher { response(503, headers = arrayOf("Retry-After" to "7")) })
            .attachmentBase()
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.HTTP_STATUS)
            .also { assertEquals(503 to 7_000L, it.httpStatus to it.backoffMillis) }
    }

    @Test
    fun `allowedDomains governs the server's base_url, and a pinned base is used with no fetch`() {
        val mirror =
            MozillaRemoteSettings.DEFAULT
                .newBuilder()
                .baseUrl("https://mirror.example/v1")
                .allowedDomains(setOf("mirror.example"))
                .build()
        val (result, fetcher) = read(served("https://a.mirror.example/attachments/"), mirror)
        assertEquals("https://a.mirror.example/attachments/", result.assertOk())
        assertEquals("https://mirror.example/v1/", fetcher.requests.single().url)
        refused(served(cdn), mirror)
        // A pinned base is operator configuration: not fetched, not checked against allowedDomains.
        val pinned = mirror.newBuilder().attachmentBaseUrl("https://elsewhere.example/a/").build()
        val (base, none) = read(served(cdn), pinned)
        assertEquals("https://elsewhere.example/a/", base.assertOk())
        assertTrue(none.requests.isEmpty())
    }
}
