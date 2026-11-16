// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.verify.JcaSignatureVerifier
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * #225's CA check on real chains: the committed corpus chains walk to `Found` under the JDK verifier with their last
 * certificate as the anchor, so no honest chain is cut by it, and [Cert.isCa] agrees with the JDK's reading of
 * basicConstraints on every corpus certificate.
 */
@OptIn(RevoktInternalApi::class)
class HonestCorpusWalkTest {
    private val chains: Map<String, Int> =
        mapOf(
            "github.com" to 3,
            "letsencrypt.org" to 4,
            "www.google.com" to 3,
            "www.mozilla.org" to 3,
            "mozilla-content-signing" to 3,
        )

    private fun der(
        host: String,
        n: Int,
    ): ByteArray {
        val name = if (host == "mozilla-content-signing") "$host-c${n - 1}" else "$host-$n"
        val path = "/dev/revokt/engine/parse/certs/$name.der"
        return checkNotNull(javaClass.getResourceAsStream(path)) { "missing fixture $path" }.use { it.readBytes() }
    }

    private fun chain(host: String): List<ByteArray> = (1..chains.getValue(host)).map { der(host, it) }

    @Test
    fun `walker the corpus chains are Found with the CA check`() {
        for (host in chains.keys) {
            val ders = chain(host)
            val index = CandidateIndex(listOf(ders.last()))
            val presented = ders.dropLast(1).map { index.cert(WalkerCerts.parse(it)) }
            val verifier = JcaSignatureVerifier()
            val walk =
                reconstruct(
                    presented,
                    index,
                    verifier,
                    verifier.unsupportedOids(),
                    LruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
                )
            assertIs<Walk.Found>(walk, host)
            assertEquals(
                ders.size,
                walk.paths
                    .first()
                    .certs.size,
                "$host: the whole chain",
            )
            assertTrue(presented.drop(1).all { it.isCa }, "$host: every intermediate is a CA")
            assertTrue(!presented[0].isCa, "$host: the leaf is not")
        }
    }

    @Test
    fun `walker isCa agrees with the JDK's basicConstraints on the corpus`() {
        val factory = CertificateFactory.getInstance("X.509")
        for (host in chains.keys) {
            for (der in chain(host)) {
                val p = (CertificateParser.parse(der) as CertificateParse.Parsed).certificate
                val jdk = (factory.generateCertificate(der.inputStream()) as X509Certificate).basicConstraints >= 0
                assertEquals(jdk, Cert.of(p, ::canonicalSubject).isCa, host)
            }
        }
    }
}
