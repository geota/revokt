// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.testing.SymKey
import dev.revokt.testing.SymName

/** Certificates for the walker package's tests: names, keys and key identifiers chosen per test. */
internal object WalkerCerts {
    const val SHA256_RSA: String = "1.2.840.113549.1.1.11"
    const val ECDSA_SHA256: String = "1.2.840.10045.4.3.2"
    const val RSA_KEY: String = "1.2.840.113549.1.1.1"
    const val EC_KEY: String = "1.2.840.10045.2.1"
    const val P256: String = "1.2.840.10045.3.1.7"

    private var serials = 0
    private var keys = 0

    fun parse(der: ByteArray): ParsedCertificate =
        when (val r = CertificateParser.parse(der)) {
            is CertificateParse.Parsed -> r.certificate
            is CertificateParse.Failed -> error("unparseable test certificate: ${r.reason} ${r.detail}")
        }

    fun cert(
        der: ByteArray,
        canonicaliser: (ByteArray) -> String? = ::canonicalSubject,
    ): Cert = Cert.of(parse(der), canonicaliser)

    fun rsaKey(): SymKey = SymKey(7, keys++, RSA_KEY)

    fun ecKey(): SymKey = SymKey(7, keys++, EC_KEY, P256)

    /** An AKI extension value with only the issuer-and-serial form: `[1] GeneralNames`, `[2] serial`. */
    fun akiIssuerAndSerial(issuer: SymName): ByteArray =
        TestDer.seq(TestDer.tlv(0xa1, TestDer.tlv(0xa4, issuer.der())), TestDer.tlv(0x82, TestDer.bytes(1)))

    fun akiKeyId(keyId: ByteArray): ByteArray = TestDer.seq(TestDer.tlv(0x80, keyId))

    /**
     * A certificate's DER. [ski] writes an SKI extension; [aki] an AKI extension with that value. Each call takes a
     * fresh serial, so two calls never give the same bytes.
     */
    fun der(
        subject: SymName,
        issuer: SymName,
        key: SymKey = rsaKey(),
        sigOid: String = SHA256_RSA,
        ski: ByteArray? = null,
        aki: ByteArray? = null,
    ): ByteArray =
        TestCert(
            serial = TestDer.tlv(0x02, TestDer.bytes(0x01, ++serials and 0xff, serials shr 8 and 0x7f)),
            tbsSignature = TestDer.seq(TestDer.oid(sigOid)),
            issuer = issuer.der(),
            subject = subject.der(),
            spki = key.spki,
            extensions =
                listOfNotNull(
                    ski?.let { TestDer.extension(Oid.SUBJECT_KEY_IDENTIFIER, TestDer.tlv(0x04, it)) },
                    aki?.let { TestDer.extension(Oid.AUTHORITY_KEY_IDENTIFIER, it) },
                ),
            outerAlgorithm = TestDer.seq(TestDer.oid(sigOid)),
        ).der
}
