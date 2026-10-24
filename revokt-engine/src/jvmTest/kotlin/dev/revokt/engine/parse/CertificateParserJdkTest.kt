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

    private enum class Expected {
        /** The JDK accepts it; revokt parses it with the JDK's extension set and records what it ignored. */
        TOLERATED,

        /** As [TOLERATED], with nothing ignored (a constructed unique id is read, not skipped). */
        TOLERATED_NOTHING_IGNORED,

        /** The JDK accepts it, but §9.2 keeps it `STRUCTURE`: the producer flattens `[0]` and keys other bytes. */
        JDK_ACCEPTS_KEPT_STRICT,

        /** The JDK rejects it, and §9.2 keeps it `STRUCTURE`. */
        STRICT,
    }

    private val variants: Map<String, Expected> =
        mapOf(
            "cert-null-after-signature" to Expected.STRICT,
            "ext3-null-after-sequence" to Expected.TOLERATED,
            "ext3-primitive-83" to Expected.TOLERATED,
            "extension-null-after-extnvalue" to Expected.TOLERATED,
            "extension-null-between-oid-and-value" to Expected.STRICT,
            "extensions-seq-with-null-element" to Expected.STRICT,
            "spki-then-null-then-uid" to Expected.TOLERATED,
            "tbs-junk-after-extensions" to Expected.TOLERATED,
            "tbs-junk-before-extensions" to Expected.STRICT,
            "tbs-null-after-extensions" to Expected.TOLERATED,
            "tbs-null-before-extensions" to Expected.TOLERATED,
            "tbs-two-ext3" to Expected.TOLERATED,
            "uid-81-twice" to Expected.TOLERATED,
            "uid-82-then-81" to Expected.TOLERATED,
            "uid-a2-constructed" to Expected.TOLERATED_NOTHING_IGNORED,
            "uid-constructed-a1" to Expected.TOLERATED_NOTHING_IGNORED,
            "validity-null-after-times" to Expected.STRICT,
            "version-wrapper-trailing" to Expected.JDK_ACCEPTS_KEPT_STRICT,
        )

    /**
     * Spec §9.2 revision 33: the parse tolerates trailing elements at least where the JDK does, except inside `[0]`.
     * Regenerate the variants with `certs/variants/generate.py`.
     */
    @Test
    fun `parser reads every structural variant as the spec assigns it against the JDK`() {
        val factory = CertificateFactory.getInstance("X.509")
        for ((name, expected) in variants) {
            val stream =
                checkNotNull(javaClass.getResourceAsStream("certs/variants/$name.der")) { "missing variant $name" }
            val der = stream.use { it.readBytes() }
            val jdk =
                runCatching {
                    factory.generateCertificate(
                        ByteArrayInputStream(der),
                    ) as X509Certificate
                }.getOrNull()
            checkVariant(name, expected, jdk, CertificateParser.parse(der))
        }
    }

    private fun checkVariant(
        name: String,
        expected: Expected,
        jdk: X509Certificate?,
        parse: CertificateParse,
    ) {
        assertEquals(expected == Expected.STRICT, jdk == null, "$name: JDK acceptance")
        when (expected) {
            Expected.STRICT, Expected.JDK_ACCEPTS_KEPT_STRICT -> {
                assertEquals(ParseReason.STRUCTURE, (parse as? CertificateParse.Failed)?.reason, "$name: kept strict")
            }

            Expected.TOLERATED, Expected.TOLERATED_NOTHING_IGNORED -> {
                val p =
                    (parse as? CertificateParse.Parsed)?.certificate
                        ?: fail("$name: ${(parse as CertificateParse.Failed).detail}")
                val oids = jdk!!.criticalExtensionOIDs.orEmpty() + jdk.nonCriticalExtensionOIDs.orEmpty()
                assertEquals(
                    oids,
                    p.tbs.extensions
                        .mapNotNull { it.oidDotted }
                        .toSet(),
                    "$name extensions",
                )
                assertEquals(
                    expected == Expected.TOLERATED,
                    p.ignoredElements.isNotEmpty(),
                    "$name records what it ignored",
                )
            }
        }
    }
}
