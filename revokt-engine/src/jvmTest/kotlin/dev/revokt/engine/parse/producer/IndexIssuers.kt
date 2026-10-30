// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import okio.ByteString.Companion.toByteString
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal

/**
 * The issuer corpus's certificates whose SPKI hashes to an index key of the fixture generation (spec §9.2, revision 45),
 * as the test JDK reads them: what tells a leaf of an index issuer, which CRLite can mark revoked, from any other. Needs
 * the large corpus (`-Prevokt.corpus`).
 */
internal object IndexIssuers {
    private val factory = CertificateFactory.getInstance("X.509")

    /** Each index-key certificate the test JDK reads: the index key (hex), its subject and its public key. */
    val certificates: List<Triple<String, X500Principal, PublicKey>> by lazy {
        ExternalCorpus.issuer.inputs.mapNotNull { input ->
            val parsed = CertificateParser.parse(input.der) as? CertificateParse.Parsed ?: return@mapNotNull null
            val key =
                parsed.certificate
                    .rawSpki()
                    .toByteString()
                    .sha256()
                    .hex()
            if (key !in FixtureIndex.keys) return@mapNotNull null
            jdk(input.der)?.let { Triple(key, it.subjectX500Principal, it.publicKey) }
        }
    }

    private val bySubject by lazy { certificates.groupBy({ it.second }, { it.first to it.third }) }

    /** [der] as the test JDK reads it; null where it does not. */
    fun jdk(der: ByteArray): X509Certificate? =
        runCatching { factory.generateCertificate(der.inputStream()) as X509Certificate }.getOrNull()

    fun signedBy(
        leaf: X509Certificate,
        key: PublicKey,
    ): Boolean = runCatching { leaf.verify(key) }.isSuccess

    /** The index key of a certificate whose subject is [leaf]'s issuer and whose key verifies [leaf]; null if none. */
    fun keyOf(leaf: X509Certificate): String? =
        bySubject[leaf.issuerX500Principal].orEmpty().firstOrNull { signedBy(leaf, it.second) }?.first
}
