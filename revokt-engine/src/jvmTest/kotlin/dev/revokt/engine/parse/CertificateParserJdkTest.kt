// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.ParseReason
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Cross-check against the JDK's `SUN` X.509 parser over real certificates (four public web PKI chains with SCTs and
 * Mozilla's content-signing chain). Not the §9.2 oracle-1 replay (#12): a smoke check that the fields revokt slices
 * are the ones the platform reads.
 */
class CertificateParserJdkTest {
    private val fixtures: List<Pair<String, ByteArray>> =
        listOf(
            "github.com-1",
            "github.com-2",
            "github.com-3",
            "letsencrypt.org-1",
            "letsencrypt.org-2",
            "letsencrypt.org-3",
            "letsencrypt.org-4",
            "www.google.com-1",
            "www.google.com-2",
            "www.google.com-3",
            "www.mozilla.org-1",
            "www.mozilla.org-2",
            "www.mozilla.org-3",
            "mozilla-content-signing-c0",
            "mozilla-content-signing-c1",
            "mozilla-content-signing-c2",
        ).map { name ->
            val stream = checkNotNull(javaClass.getResourceAsStream("certs/$name.der")) { "missing fixture $name" }
            name to stream.use { it.readBytes() }
        }

    @Test
    fun `parser agrees with the JDK on every field of real certificates`() {
        val factory = CertificateFactory.getInstance("X.509")
        for ((name, der) in fixtures) {
            val jdk = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            val p =
                when (val r = CertificateParser.parse(der)) {
                    is CertificateParse.Parsed -> r.certificate
                    is CertificateParse.Failed -> fail("$name: ${r.reason} ${r.detail}")
                }
            assertContentEquals(jdk.tbsCertificate, p.tbs.tlv.bytes(der), "$name tbs")
            assertEquals(jdk.serialNumber, BigInteger(p.rawSerial()), "$name serial")
            assertContentEquals(jdk.issuerX500Principal.encoded, p.rawIssuer(), "$name issuer")
            assertContentEquals(jdk.subjectX500Principal.encoded, p.rawSubject(), "$name subject")
            assertContentEquals(jdk.publicKey.encoded, p.rawSpki(), "$name spki")
            assertEquals(jdk.notBefore.time, p.tbs.validity.notBeforeMillis, "$name notBefore")
            assertEquals(jdk.notAfter.time, p.tbs.validity.notAfterMillis, "$name notAfter")
            assertEquals(jdk.version, (p.tbs.version?.let { p.der[it.start].toInt() } ?: 0) + 1, "$name version")
            assertContentEquals(
                jdk.signature,
                p.signatureValue.bytes(der).copyOfRange(1, p.signatureValue.length),
                "$name signature",
            )
            val oids = jdk.criticalExtensionOIDs.orEmpty() + jdk.nonCriticalExtensionOIDs.orEmpty()
            assertEquals(
                oids,
                p.tbs.extensions
                    .map { it.oidDotted }
                    .toSet(),
                "$name extension OIDs",
            )
            assertEquals(
                jdk.criticalExtensionOIDs.orEmpty(),
                p.tbs.extensions
                    .filter {
                        it.critical
                    }.mapNotNull { it.oidDotted }
                    .toSet(),
                "$name critical",
            )
            for (e in p.tbs.extensions) {
                val wrapped = jdk.getExtensionValue(e.oidDotted)
                assertContentEquals(
                    wrapped.copyOfRange(wrapped.size - e.value.length, wrapped.size),
                    e.value.bytes(der),
                    "$name ${e.oidDotted}",
                )
            }
            assertEquals(emptyList(), p.nonMinimalHeaders.map { it.site }, "$name non-minimal headers")
        }
    }

    @Test
    fun `parser reads SCT extensions from the four leaf certificates`() {
        val leaves = fixtures.filter { it.first.endsWith("-1") && !it.first.startsWith("mozilla") }
        assertEquals(4, leaves.size)
        for ((name, der) in leaves) {
            val p = (CertificateParser.parse(der) as CertificateParse.Parsed).certificate
            assertEquals(1, p.extensions(Oid.SCT_LIST).size, name)
            assertTrue(
                p
                    .extensions(Oid.SCT_LIST)
                    .single()
                    .value.length > 100,
                "$name SCT list is present and non-trivial",
            )
        }
    }

    /**
     * Spec §9.2 revision 33: the parse tolerates trailing elements exactly where the JDK does. Every structural variant
     * of `letsencrypt.org-2` the JDK accepts must parse with the JDK's extension set; the ones it rejects at a place
     * §9.2 keeps strict must be `STRUCTURE`. Regenerate the variants with `certs/variants/generate.py`.
     */
    @Test
    fun `parser accepts every structural variant the JDK accepts and rejects the strict ones`() {
        val factory = CertificateFactory.getInstance("X.509")
        val strict =
            setOf(
                "cert-null-after-signature",
                "validity-null-after-times",
                "extensions-seq-with-null-element",
                "extension-null-between-oid-and-value",
                "tbs-junk-before-extensions",
            )
        val names =
            listOf(
                "cert-null-after-signature",
                "ext3-null-after-sequence",
                "ext3-primitive-83",
                "extension-null-after-extnvalue",
                "extension-null-between-oid-and-value",
                "extensions-seq-with-null-element",
                "spki-then-null-then-uid",
                "tbs-junk-after-extensions",
                "tbs-junk-before-extensions",
                "tbs-null-after-extensions",
                "tbs-null-before-extensions",
                "tbs-two-ext3",
                "uid-81-twice",
                "uid-82-then-81",
                "uid-a2-constructed",
                "uid-constructed-a1",
                "validity-null-after-times",
                "version-wrapper-trailing",
            )
        val tolerantWithoutIgnored = setOf("uid-a2-constructed", "uid-constructed-a1")
        for (name in names) {
            val stream =
                checkNotNull(javaClass.getResourceAsStream("certs/variants/$name.der")) { "missing variant $name" }
            val der = stream.use { it.readBytes() }
            val jdk =
                runCatching {
                    factory.generateCertificate(
                        ByteArrayInputStream(der),
                    ) as X509Certificate
                }.getOrNull()
            val parse = CertificateParser.parse(der)
            if (name in strict) {
                assertNull(jdk, "$name: the JDK rejects it")
                assertEquals(
                    ParseReason.STRUCTURE,
                    (parse as? CertificateParse.Failed)?.reason,
                    "$name: §9.2 keeps it strict",
                )
                continue
            }
            checkNotNull(jdk) { "$name: the JDK accepts it" }
            val p =
                (parse as? CertificateParse.Parsed)?.certificate
                    ?: fail("$name: ${(parse as CertificateParse.Failed).detail}")
            val oids = jdk.criticalExtensionOIDs.orEmpty() + jdk.nonCriticalExtensionOIDs.orEmpty()
            assertEquals(
                oids,
                p.tbs.extensions
                    .mapNotNull { it.oidDotted }
                    .toSet(),
                "$name extensions",
            )
            assertEquals(
                name !in tolerantWithoutIgnored,
                p.ignoredElements.isNotEmpty(),
                "$name records what it ignored",
            )
        }
    }
}
