// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.math.BigInteger
import java.security.Principal
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date

/** An [X509Certificate] whose getters are lambdas; every other member throws. */
@Suppress("TooManyFunctions")
internal class FakeX509Certificate(
    private val encoded: () -> ByteArray?,
    private val tbs: () -> ByteArray? = { error("tbs") },
    private val sig: () -> ByteArray? = { error("signature") },
) : X509Certificate() {
    override fun getEncoded(): ByteArray? = encoded()

    override fun getTBSCertificate(): ByteArray? = tbs()

    override fun getSignature(): ByteArray? = sig()

    override fun toString(): String = "FakeX509Certificate"

    override fun verify(key: PublicKey?): Unit = error("unused")

    override fun verify(
        key: PublicKey?,
        sigProvider: String?,
    ): Unit = error("unused")

    override fun getPublicKey(): PublicKey = error("unused")

    override fun hasUnsupportedCriticalExtension(): Boolean = error("unused")

    override fun getCriticalExtensionOIDs(): MutableSet<String> = error("unused")

    override fun getNonCriticalExtensionOIDs(): MutableSet<String> = error("unused")

    override fun getExtensionValue(oid: String?): ByteArray = error("unused")

    override fun checkValidity(): Unit = error("unused")

    override fun checkValidity(date: Date?): Unit = error("unused")

    override fun getVersion(): Int = error("unused")

    override fun getSerialNumber(): BigInteger = error("unused")

    @Deprecated("unused")
    override fun getIssuerDN(): Principal = error("unused")

    @Deprecated("unused")
    override fun getSubjectDN(): Principal = error("unused")

    override fun getNotBefore(): Date = error("unused")

    override fun getNotAfter(): Date = error("unused")

    override fun getSigAlgName(): String = error("unused")

    override fun getSigAlgOID(): String = error("unused")

    override fun getSigAlgParams(): ByteArray = error("unused")

    override fun getIssuerUniqueID(): BooleanArray = error("unused")

    override fun getSubjectUniqueID(): BooleanArray = error("unused")

    override fun getKeyUsage(): BooleanArray = error("unused")

    override fun getBasicConstraints(): Int = error("unused")
}
