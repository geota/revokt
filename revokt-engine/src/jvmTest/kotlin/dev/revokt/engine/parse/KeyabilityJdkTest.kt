// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.KeyabilityClause
import kotlin.test.Test
import kotlin.test.assertEquals

/** The profile over the committed real certificates (spec §9.2, revision 34). */
class KeyabilityJdkTest {
    @Test
    fun `the committed real certificates pass K1 to K4`() {
        val names =
            listOf("github.com", "letsencrypt.org", "www.google.com", "www.mozilla.org").flatMap { site ->
                (1..3).map { "$site-$it" }
            } +
                listOf(
                    "letsencrypt.org-4",
                    "mozilla-content-signing-c0",
                    "mozilla-content-signing-c1",
                    "mozilla-content-signing-c2",
                )
        for (name in names) {
            val der =
                checkNotNull(
                    javaClass.getResourceAsStream("certs/$name.der"),
                ) { "missing $name" }.use { it.readBytes() }
            val p = (CertificateParser.parse(der) as CertificateParse.Parsed).certificate
            // Until #25 no certificate passes K5, so NAME means it passed K1 to K4.
            assertEquals(KeyabilityClause.NAME, Keyability.firstFailing(p), name)
        }
    }
}
