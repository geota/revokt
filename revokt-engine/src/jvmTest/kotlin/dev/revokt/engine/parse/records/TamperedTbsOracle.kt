// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

import dev.revokt.engine.parse.oracle.Oracle1
import dev.revokt.engine.parse.oracle.PlatformOracle
import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

/**
 * A test double of a platform oracle: oracle 1, except that every accepted certificate's `getTBSCertificate()` carries
 * one octet more than `Cert.tbs`, so the divergence path of spec §9.2 D2 (`CONSCRYPT_TBS` on Conscrypt) is exercised
 * although no committed input reaches it.
 */
internal object TamperedTbsOracle : PlatformOracle by Oracle1 {
    override val id = "tampered"

    override val tbsDivergence = "CONSCRYPT_TBS"

    override val label = "a tampered-TBS oracle"

    override fun run(b: ByteArray): PlatformOracle.Outcome =
        when (val o = Oracle1.run(b)) {
            is PlatformOracle.Outcome.Accept -> PlatformOracle.Outcome.Accept(Tampered(o.certificate))
            else -> o
        }

    /** Oracle 1's read of the untampered certificate, so the bytes read have goldens. */
    override fun read(
        name: String,
        certificate: X509Certificate,
    ) = Oracle1.read(name, (certificate as? Tampered)?.delegate ?: certificate)

    /** [delegate] in every respect but its TBS, which gains a trailing octet. */
    private class Tampered(
        val delegate: X509Certificate,
    ) : X509Certificate() {
        override fun getTBSCertificate(): ByteArray = delegate.tbsCertificate + 0

        override fun checkValidity() = delegate.checkValidity()

        override fun checkValidity(date: Date) = delegate.checkValidity(date)

        override fun getVersion(): Int = delegate.version

        override fun getSerialNumber(): BigInteger = delegate.serialNumber

        @Deprecated("as X509Certificate", ReplaceWith("issuerX500Principal"))
        override fun getIssuerDN(): Principal = delegate.issuerX500Principal

        @Deprecated("as X509Certificate", ReplaceWith("subjectX500Principal"))
        override fun getSubjectDN(): Principal = delegate.subjectX500Principal

        override fun getIssuerX500Principal(): X500Principal = delegate.issuerX500Principal

        override fun getSubjectX500Principal(): X500Principal = delegate.subjectX500Principal

        override fun getNotBefore(): Date = delegate.notBefore

        override fun getNotAfter(): Date = delegate.notAfter

        override fun getSignature(): ByteArray = delegate.signature

        override fun getSigAlgName(): String = delegate.sigAlgName

        override fun getSigAlgOID(): String = delegate.sigAlgOID

        override fun getSigAlgParams(): ByteArray? = delegate.sigAlgParams

        override fun getIssuerUniqueID(): BooleanArray? = delegate.issuerUniqueID

        override fun getSubjectUniqueID(): BooleanArray? = delegate.subjectUniqueID

        override fun getKeyUsage(): BooleanArray? = delegate.keyUsage

        override fun getBasicConstraints(): Int = delegate.basicConstraints

        override fun getEncoded(): ByteArray = delegate.encoded

        override fun verify(key: PublicKey) = delegate.verify(key)

        override fun verify(
            key: PublicKey,
            sigProvider: String,
        ) = delegate.verify(key, sigProvider)

        override fun toString(): String = "tampered $delegate"

        override fun getPublicKey(): PublicKey = delegate.publicKey

        override fun hasUnsupportedCriticalExtension(): Boolean = delegate.hasUnsupportedCriticalExtension()

        override fun getCriticalExtensionOIDs(): Set<String>? = delegate.criticalExtensionOIDs

        override fun getNonCriticalExtensionOIDs(): Set<String>? = delegate.nonCriticalExtensionOIDs

        override fun getExtensionValue(oid: String): ByteArray? = delegate.getExtensionValue(oid)
    }
}
