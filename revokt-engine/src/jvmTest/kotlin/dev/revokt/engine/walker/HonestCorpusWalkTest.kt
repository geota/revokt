// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.VerifyResult
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.verify.JcaSignatureVerifier
import okio.ByteString
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

    /** [host]'s chain walked for [eku], its last certificate the anchor, with the JDK verifier. */
    private fun walk(
        host: String,
        eku: RequiredEku = RequiredEku.SERVER_AUTH,
    ): Pair<List<Cert>, Walk> {
        val ders = chain(host)
        val index = CandidateIndex(listOf(ders.last()))
        val presented = ders.dropLast(1).map { index.cert(WalkerCerts.parse(it)) }
        val verifier = JcaSignatureVerifier()
        val memo = LruMap<Pair<ByteString, ByteString>, VerifyResult>(RevoktLimits.CROSS_CALL_MEMO_ENTRIES)
        return presented to reconstruct(presented, index, verifier, verifier.unsupportedOids(), memo, eku)
    }

    @Test
    fun `walker the TLS corpus chains are Found with the issuer rules for serverAuth and clientAuth`() {
        for (host in chains.keys - CONTENT_SIGNING) {
            val ders = chain(host)
            val (presented, walk) = walk(host)
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
            // For clientAuth the chain is Found exactly when every intermediate, read by the JDK, has no extKeyUsage
            // or lists clientAuth (Let's Encrypt's current intermediates list serverAuth only).
            val factory = CertificateFactory.getInstance("X.509")
            val clientOk =
                ders.drop(1).dropLast(1).all {
                    val eku = (factory.generateCertificate(it.inputStream()) as X509Certificate).extendedKeyUsage
                    eku == null || CLIENT_AUTH in eku
                }
            assertEquals(clientOk, walk(host, RequiredEku.CLIENT_AUTH).second is Walk.Found, "$host for clientAuth")
        }
    }

    @Test
    fun `walker the content-signing chain is NotFound for serverAuth, its intermediate listing codeSigning only`() {
        val factory = CertificateFactory.getInstance("X.509")
        val intermediate = factory.generateCertificate(chain(CONTENT_SIGNING)[1].inputStream()) as X509Certificate
        assertEquals(listOf("1.3.6.1.5.5.7.3.3"), intermediate.extendedKeyUsage)
        val (presented, walk) = walk(CONTENT_SIGNING)
        assertIs<Walk.NotFound>(walk)
        assertTrue(presented[1].isCa, "a CA, so the extKeyUsage decides")
    }

    private companion object {
        const val CONTENT_SIGNING = "mozilla-content-signing"
        const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
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
