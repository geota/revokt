// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.ParseReason
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.producer.ProducerCorpus
import java.io.ByteArrayInputStream
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Oracle 1 of spec §9.2: the JDK's `SUN` `CertificateFactory`, run live on the test JDK (`-Prevokt.testJdk`), with the
 * §9.2 Java field normalisation and the read fallback of revision 39. A platform getter that throws on an accepted
 * certificate marks its field `unavailable`.
 */
internal object Oracle1 : PlatformOracle {
    override val ocspNoCheckEmpty = true

    /** A definite TLV header: its length in octets and its content length. */
    class Header(
        val size: Int,
        val length: Long,
    ) {
        fun end(p: Int): Long = p + size + length
    }

    /** The suffix naming a platform-canon read. */
    const val PLATFORM_CANON = "(platform canon)"

    private val factory = CertificateFactory.getInstance("X.509", "SUN")

    override val id = "1"

    override val version: String = Runtime.version().feature().toString()

    override val label: String = "oracle 1 (JDK ${System.getProperty("java.runtime.version")})"

    @Suppress("TooGenericExceptionCaught") // §9.2: every exception other than CertificateException is a Crash
    override fun run(b: ByteArray): PlatformOracle.Outcome =
        try {
            PlatformOracle.Outcome.Accept(factory.generateCertificate(ByteArrayInputStream(b)) as X509Certificate)
        } catch (_: CertificateException) {
            PlatformOracle.Outcome.Reject
        } catch (e: Exception) {
            PlatformOracle.Outcome.Crash(e)
        }

    /**
     * The bytes revokt reads for an accepted certificate (spec §9.2 revision 39) as a replay input: `getEncoded()`, or
     * the platform canon where revokt's parse of that is `ParseFailed(STRUCTURE)`; null when no platform canon can be
     * built. A getter that throws is `unavailable`, which the committed corpus must not contain, so it propagates.
     */
    override fun read(
        name: String,
        certificate: X509Certificate,
    ): ProducerCorpus.Input? {
        val encoded = certificate.encoded
        val parse = CertificateParser.parse(encoded)
        if (parse !is CertificateParse.Failed || parse.reason != ParseReason.STRUCTURE) {
            return ProducerCorpus.Input("$name (encoded)", encoded)
        }
        val parts = platformCanon(certificate.tbsCertificate, certificate.signature) ?: return null
        return ProducerCorpus.Input("$name $PLATFORM_CANON", parts.canon(), parts = parts)
    }

    /**
     * The parts of `SEQUENCE { tbs, the signature AlgorithmIdentifier TLV located in it, BIT STRING { 00, signature } }`;
     * null when the locator finds no AlgorithmIdentifier.
     */
    fun platformCanon(
        tbs: ByteArray,
        signature: ByteArray,
    ): Oracle3b.Parts? =
        algorithm(tbs)?.let {
            Oracle3b.Parts(Oracle3a.hex(tbs), Oracle3a.hex(it), Oracle3a.hex(signature))
        }

    /**
     * The locator of §9.2: one-octet identifiers and definite lengths of at most four octets; after the TBS header, skip a
     * first element `A0`, then one element, and take the next if its identifier is `30`.
     */
    private fun algorithm(tbs: ByteArray): ByteArray? {
        var p = header(tbs, 0)?.size ?: return null
        val skip = if (p < tbs.size && tbs[p] == 0xa0.toByte()) 2 else 1
        repeat(skip) { p = header(tbs, p)?.end(p)?.toInt() ?: return null }
        val end = header(tbs, p)?.end(p)?.toInt() ?: return null
        return if (tbs[p] == 0x30.toByte()) tbs.copyOfRange(p, end) else null
    }

    /** The definite header at [p] whose content fits in [b], or null (indefinite, five or more length octets, overrun). */
    fun header(
        b: ByteArray,
        p: Int,
    ): Header? {
        if (p + 1 >= b.size) return null
        val first = b[p + 1].toInt() and 0xff
        val count = if (first < 0x80) 0 else first and 0x7f
        if (first == 0x80 || count > 4 || p + 2 + count > b.size) return null
        val length =
            if (count == 0) {
                first.toLong()
            } else {
                (0 until count).fold(0L) { n, i -> (n shl 8) or (b[p + 2 + i].toLong() and 0xff) }
            }
        return Header(2 + count, length).takeIf { it.end(p) <= b.size }
    }
}
