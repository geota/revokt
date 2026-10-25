// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.producer.ProducerCorpus
import org.conscrypt.Conscrypt
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Oracle 2 of spec §9.2: Conscrypt's `CertificateFactory` (BoringSSL) from `conscrypt-openjdk-uber`, the stand-in for
 * the platform Conscrypt on Android. Its `getEncoded()` is `i2d_X509` of the parsed object; it parses strict DER, so it
 * needs no read fallback.
 */
internal object Oracle2 : PlatformOracle {
    private val provider = Conscrypt.newProvider()

    private val factory = CertificateFactory.getInstance("X.509", provider)

    override val id = "2"

    override val version: String = Conscrypt.version().let { "${it.major()}.${it.minor()}.${it.patch()}" }

    override val tbsDivergence = "CONSCRYPT_TBS"

    @Suppress("TooGenericExceptionCaught") // §9.2: every exception other than CertificateException is a Crash
    override fun run(b: ByteArray): PlatformOracle.Outcome =
        try {
            PlatformOracle.Outcome.Accept(factory.generateCertificate(ByteArrayInputStream(b)) as X509Certificate)
        } catch (_: CertificateException) {
            PlatformOracle.Outcome.Reject
        } catch (e: Exception) {
            PlatformOracle.Outcome.Crash(e)
        }

    override fun read(
        name: String,
        certificate: X509Certificate,
    ): ProducerCorpus.Input = ProducerCorpus.Input("$name (conscrypt encoded)", certificate.encoded)
}
