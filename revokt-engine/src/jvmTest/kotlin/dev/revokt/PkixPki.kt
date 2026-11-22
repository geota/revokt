// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.oid
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import java.io.ByteArrayInputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Really signed P-256 certificates for the PKIX fallback and anchor-snapshot tests: the JDK's `CertPathBuilder` verifies
 * every link, so these are real chains. Each issued certificate takes a fresh serial.
 */
internal object PkixPki {
    /** `ecdsa-with-SHA256`. */
    private val ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))

    /** 2026-10-22 to 2050-01-01. */
    val LONG_VALIDITY: ByteArray = validity("261022134530Z", "20500101000000Z")

    /** Inside [LONG_VALIDITY]: 2027-01-01T00:00:00Z. */
    const val NOW: Long = 1_798_761_600_000

    private var serial = 0x1000

    class Issued(
        val der: ByteArray,
        val keys: KeyPair,
        val name: ByteArray,
    ) {
        val x509: X509Certificate get() = x509(der)
    }

    fun keys(): KeyPair =
        KeyPairGenerator
            .getInstance("EC")
            .apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()

    /** A Name with one CN as a UTF8String, or as a PrintableString with [printable] (another raw encoding, the same name). */
    fun name(
        cn: String,
        printable: Boolean = false,
    ): ByteArray = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(if (printable) 0x13 else 0x0c, ascii(cn)))))

    fun validity(
        notBefore: String,
        notAfter: String,
    ): ByteArray =
        seq(
            tlv(if (notBefore.length == 13) 0x17 else 0x18, ascii(notBefore)),
            tlv(if (notAfter.length == 13) 0x17 else 0x18, ascii(notAfter)),
        )

    /** A self-signed CA. */
    fun root(cn: String): Issued {
        val keys = keys()
        val name = name(cn)
        return Issued(sign(name, name, keys, keys, ca = true, LONG_VALIDITY), keys, name)
    }

    /**
     * A certificate for [subject] signed by [issuer]; [issuerName] is the issuer field as written (by default the
     * issuer's subject bytes), [ca] writes basicConstraints `cA = TRUE`.
     */
    fun issue(
        subject: String,
        issuer: Issued,
        ca: Boolean,
        validity: ByteArray = LONG_VALIDITY,
        issuerName: ByteArray = issuer.name,
        extensions: List<ByteArray> = emptyList(),
    ): Issued {
        val keys = keys()
        val name = name(subject)
        return Issued(sign(name, issuerName, keys, issuer.keys, ca, validity, extensions), keys, name)
    }

    fun x509(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private fun sign(
        subject: ByteArray,
        issuer: ByteArray,
        keys: KeyPair,
        issuerKeys: KeyPair,
        ca: Boolean,
        validity: ByteArray,
        extensions: List<ByteArray> = emptyList(),
    ): ByteArray {
        val s = serial++

        fun cert(signature: ByteArray) =
            TestCert(
                serial = tlv(0x02, TestDer.bytes(s shr 8, s and 0xff)),
                tbsSignature = ECDSA_SHA256,
                issuer = issuer,
                validity = validity,
                subject = subject,
                spki = keys.public.encoded,
                extensions = listOf(TestDer.basicConstraints(ca)) + extensions,
                outerAlgorithm = ECDSA_SHA256,
                signature = signature,
            )
        val tbs = cert(tlv(0x03, TestDer.bytes(0))).tbs
        val sig =
            Signature.getInstance("SHA256withECDSA").run {
                initSign(issuerKeys.private)
                update(tbs)
                sign()
            }
        return cert(tlv(0x03, TestDer.bytes(0), sig)).der
    }
}
