// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.ParseReason
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * Oracle 1 of spec §9.2: the JDK's `SUN` `CertificateFactory`, run live on the test JDK (`-Prevokt.testJdk`), with the
 * §9.2 Java field normalisation. A getter that throws on an accepted certificate marks its field `unavailable`.
 */
internal object Oracle1 {
    sealed class Outcome {
        class Accept(
            val certificate: X509Certificate,
        ) : Outcome()

        object Reject : Outcome()

        class Crash(
            val error: Throwable,
        ) : Outcome()
    }

    private val factory = CertificateFactory.getInstance("X.509", "SUN")

    val version: String = System.getProperty("java.runtime.version")

    fun run(b: ByteArray): Outcome =
        try {
            Outcome.Accept(factory.generateCertificate(ByteArrayInputStream(b)) as X509Certificate)
        } catch (_: CertificateException) {
            Outcome.Reject
        } catch (e: RuntimeException) {
            Outcome.Crash(e)
        }

    /**
     * The bytes revokt reads for an accepted certificate (spec §9.2 revision 39) as a replay input: `getEncoded()`, or
     * the platform canon where revokt's parse of that is `ParseFailed(STRUCTURE)`; null when no platform canon can be
     * built.
     */
    fun read(
        name: String,
        jdk: X509Certificate,
    ): ProducerCorpus.Input? {
        val encoded = jdk.encoded
        val parse = CertificateParser.parse(encoded)
        if (parse !is CertificateParse.Failed || parse.reason != ParseReason.STRUCTURE) {
            return ProducerCorpus.Input("$name (encoded)", encoded)
        }
        val parts = platformCanon(jdk) ?: return null
        return ProducerCorpus.Input("$name (platform canon)", parts.canon(), parts = parts)
    }

    /**
     * The parts of `SEQUENCE { getTBSCertificate(), the signature AlgorithmIdentifier TLV located in it, BIT STRING { 00,
     * getSignature() } }`, the bytes the JDK verifies over; null when a getter throws or the AlgorithmIdentifier cannot be
     * located (the TBS's third element, or its second without `[0]`).
     */
    fun platformCanon(jdk: X509Certificate): Oracle3b.Parts? =
        try {
            val tbs = jdk.tbsCertificate
            algorithm(tbs)?.let { Oracle3b.Parts(Oracle3a.hex(tbs), Oracle3a.hex(it), Oracle3a.hex(jdk.signature)) }
        } catch (_: RuntimeException) {
            null
        } catch (_: CertificateException) {
            null
        }

    /** The TBS's signature AlgorithmIdentifier TLV, read with definite lengths only. */
    private fun algorithm(tbs: ByteArray): ByteArray? {
        var p = element(tbs, 0)?.first ?: return null
        val end = tbs.size
        val skip = if (p < end && tbs[p] == 0xa0.toByte()) 2 else 1
        repeat(skip) { p = element(tbs, p)?.second ?: return null }
        val (_, next) = element(tbs, p) ?: return null
        return if (next <= end && tbs[p] == 0x30.toByte()) tbs.copyOfRange(p, next) else null
    }

    /** The TLV at [p]: the offset of its content and of its end, or null for an indefinite or overrunning one. */
    private fun element(
        b: ByteArray,
        p: Int,
    ): Pair<Int, Int>? {
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
        val content = p + 2 + count
        return if (length <= b.size - content) content to (content + length.toInt()) else null
    }

    /** One normalised field comparison: [mismatch] is null when the field agrees, [unavailable] when its getter threw. */
    class Field(
        val name: String,
        val mismatch: String?,
        val unavailable: Boolean = false,
    )

    /**
     * The §9.2 normalised fields of [jdk] against revokt's [c]: the serial by value, the SPKI by SHA-256, the names in
     * `CANONICAL` form, every extension value unwrapped, the critical OIDs and the validity in epoch milliseconds.
     */
    fun compare(
        jdk: X509Certificate,
        c: ParsedCertificate,
    ): List<Field> =
        listOf(
            field("serial") { expect(jdk.serialNumber, c.rawSerial().takeIf { it.isNotEmpty() }?.let(::BigInteger)) },
            field("spki") { expect(sha(jdk.publicKey.encoded), sha(c.rawSpki())) },
            field("issuer") { expect(canonical(jdk.issuerX500Principal), canonical(X500Principal(c.rawIssuer()))) },
            field("subject") { expect(canonical(jdk.subjectX500Principal), canonical(X500Principal(c.rawSubject()))) },
            field("extensions") { extensions(jdk, c) },
            field("critical") {
                expect(
                    jdk.criticalExtensionOIDs.orEmpty(),
                    c.tbs.extensions
                        .filter { it.critical }
                        .oids(),
                )
            },
            field("notBefore") { expect(jdk.notBefore.time, c.tbs.validity.notBeforeMillis) },
            field("notAfter") { expect(jdk.notAfter.time, c.tbs.validity.notAfterMillis) },
        )

    private fun field(
        name: String,
        check: () -> String?,
    ): Field =
        try {
            Field(name, check())
        } catch (e: RuntimeException) {
            Field(name, "getter threw $e", unavailable = true)
        }

    private fun expect(
        jdk: Any?,
        revokt: Any?,
    ): String? = if (jdk == revokt) null else "JDK $jdk, revokt $revokt"

    private fun extensions(
        jdk: X509Certificate,
        c: ParsedCertificate,
    ): String? {
        val oids = jdk.criticalExtensionOIDs.orEmpty() + jdk.nonCriticalExtensionOIDs.orEmpty()
        expect(oids, c.tbs.extensions.oids())?.let { return "OIDs: $it" }
        if (c.tbs.extensions.any { it.oidDotted == null }) return "an OID revokt cannot name"
        for (e in c.tbs.extensions) {
            val unwrapped = unwrap(jdk.getExtensionValue(e.oidDotted))
            val value =
                e.value
                    .bytes(c.tbsBytes)
                    .toByteString()
                    .hex()
            expect(unwrapped, value)?.let { return "${e.oidDotted}: $it" }
        }
        return null
    }

    private fun List<dev.revokt.engine.parse.Extension>.oids(): Set<String?> = map { it.oidDotted }.toSet()

    /** `getExtensionValue`'s DER OCTET STRING, unwrapped to its content (hex). */
    private fun unwrap(wrapped: ByteArray?): String? {
        if (wrapped == null || wrapped.size < 2 || wrapped[0] != 0x04.toByte()) return null
        val first = wrapped[1].toInt() and 0xff
        val header = if (first < 0x80) 2 else 2 + (first and 0x7f)
        return wrapped.copyOfRange(header, wrapped.size).toByteString().hex()
    }

    private fun canonical(p: X500Principal): String = p.getName(X500Principal.CANONICAL)

    private fun sha(b: ByteArray): String = b.toByteString().sha256().hex()
}
