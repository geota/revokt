// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.parse.producer.ProducerCorpus
import java.math.BigInteger
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `PresentedChain` (spec §4, #120) against the JDK's `X509Certificate` on the committed corpus chains: `dnsNames` equals
 * the `dNSName` entries of `getSubjectAlternativeNames()`, and the other fields the JDK's encodings of the same parts.
 */
@OptIn(RevoktTestingApi::class)
class PresentedChainJdkTest {
    /** The committed real-world chains, leaf first (`certs/<host>-<n>.der`). */
    private val chains =
        mapOf(
            "github.com" to 3,
            "letsencrypt.org" to 4,
            "www.google.com" to 3,
            "www.mozilla.org" to 3,
        ).map { (host, n) -> host to (1..n).map { "certs/$host-$it.der" } } +
            ("mozilla-content-signing" to (0..2).map { "certs/mozilla-content-signing-c$it.der" })

    private fun x509(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate

    private fun jdkDnsNames(x: X509Certificate): List<String> =
        x.subjectAlternativeNames
            .orEmpty()
            .filter { it[0] == 2 }
            .map { it[1] as String }

    @Test
    fun `dnsNames and the other fields equal the JDK's on the committed corpus chains`() {
        var names = 0
        for ((name, paths) in chains) {
            val ders = paths.map(ProducerCorpus::resource)
            val chain =
                PresentedChain
                    .Builder()
                    .certificates(ders)
                    .build()
            assertEquals(ders.size, chain.size, name)
            for ((i, der) in ders.withIndex()) {
                val x = x509(der)
                val at = "$name[$i]"
                assertTrue(chain.parsed(i), at)
                assertEquals(jdkDnsNames(x), chain.dnsNames(i), at)
                assertContentEquals(der, chain.der(i), at)
                assertContentEquals(x.subjectX500Principal.encoded, chain.subject(i), at)
                assertContentEquals(x.issuerX500Principal.encoded, chain.issuer(i), at)
                assertContentEquals(
                    MessageDigest.getInstance("SHA-256").digest(x.publicKey.encoded),
                    chain.spkiSha256(i),
                    at,
                )
                assertEquals(x.serialNumber, BigInteger(chain.serial(i)), at)
                names += chain.dnsNames(i).size
            }
        }
        // The leaves carry names; a vacuous comparison would pass on empty lists alone.
        assertTrue(names >= chains.size, "only $names dNSName entries over the corpus")
    }
}
