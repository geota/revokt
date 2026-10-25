// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.ParseReason
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
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
 * Mozilla's content-signing chain). Not the §9.2 oracle-1 replay (`oracle/ParserReplayTest`): a smoke check that the
 * fields revokt slices are the ones the platform reads.
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
            assertContentEquals(jdk.tbsCertificate, p.tbsBytes, "$name tbs")
            assertEquals(jdk.serialNumber, BigInteger(p.rawSerial()), "$name serial")
            assertContentEquals(jdk.issuerX500Principal.encoded, p.rawIssuer(), "$name issuer")
            assertContentEquals(jdk.subjectX500Principal.encoded, p.rawSubject(), "$name subject")
            assertContentEquals(jdk.publicKey.encoded, p.rawSpki(), "$name spki")
            assertEquals(jdk.notBefore.time, p.tbs.validity.notBeforeMillis, "$name notBefore")
            assertEquals(jdk.notAfter.time, p.tbs.validity.notAfterMillis, "$name notAfter")
            assertEquals(jdk.version, (p.tbs.version?.let { p.tbsBytes[it.start].toInt() } ?: 0) + 1, "$name version")
            assertContentEquals(jdk.signature, p.envelope.signature, "$name Cert.sig")
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
                    e.value.bytes(p.tbsBytes),
                    "$name ${e.oidDotted}",
                )
            }
            assertEquals(emptyList(), p.nonMinimalHeaders.map { it.site }, "$name non-minimal headers")
        }
    }

    /** OpenSSL's reading of each leaf's SCTs (`openssl x509 -text`), log id and timestamp in epoch milliseconds. */
    private val leafScts: Map<String, Set<Sct>> =
        listOf(
            "github.com" to
                Sct("d76d7d10d1a7f577c2c7e95fd700bff982c9335a65e1d0b3017317c0c8c56977".decodeHex(), 1788221432017L),
            "github.com" to
                Sct("c8a3c47fc7b3adb9356b013f6a7a126de33a4e43a5c646f997ad3975991dcf9a".decodeHex(), 1788221431981L),
            "www.google.com" to
                Sct("d809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14".decodeHex(), 1790624482689L),
            "www.google.com" to
                Sct("74db9d58f7d47e9dfd787a162a991c18cf698da7c729918c9a18b0450dba44bc".decodeHex(), 1790624482729L),
            "letsencrypt.org" to
                Sct("d809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14".decodeHex(), 1788535982377L),
            "letsencrypt.org" to
                Sct("46af863d3b3ee59fa577dea8245d36b0d9ed22a223f4617741229452ee95505f".decodeHex(), 1788535982552L),
            "www.mozilla.org" to
                Sct("001a5d1a1c2d9375b6485578f82f71a1ae6eef397d297c8ae3157bcadee1a01e".decodeHex(), 1792551111641L),
            "www.mozilla.org" to
                Sct("1a8b9d6b8dd791d1cd0549edb60355d606b64fad30db71fe788f0fc7c8fbc4b1".decodeHex(), 1792551112740L),
        ).groupBy({ it.first }, { it.second }).mapValues { it.value.toSet() }

    @Test
    fun `parser extracts the SCTs OpenSSL reads from the four leaves`() {
        for ((host, expected) in leafScts) {
            val der = fixtures.first { it.first == "$host-1" }.second
            val p = (CertificateParser.parse(der) as CertificateParse.Parsed).certificate
            assertEquals(expected, p.fields.scts, host)
        }
    }

    @Test
    fun `parser extracts the SKI and AKI key identifiers OpenSSL reads`() {
        val expected =
            mapOf(
                "github.com-1" to
                    ("6698ec4c1135f74b50848ba81c3665d01756d4e0" to "1799a804c16fe42d70a80a103d03d3e91ab82663"),
                "www.google.com-1" to
                    ("dd9ed8bda33cb2cad1c07a7a5ec975197b09f94e" to "75bec477ae89f644377dcfb1681f1d1aebdc3459"),
                "letsencrypt.org-2" to
                    ("b959f28ecf22f086d33748ff761418ba82d85587" to "a3c8265a8ea14cd03563fc9b23c83aae56f34f56"),
            )
        for ((name, ids) in expected) {
            val der = fixtures.first { it.first == name }.second
            val p = (CertificateParser.parse(der) as CertificateParse.Parsed).certificate
            assertEquals(
                ids.first,
                p.fields.ski!!
                    .bytes(p.tbsBytes)
                    .toByteString()
                    .hex(),
                "$name SKI",
            )
            assertEquals(
                ids.second,
                p.fields.akiKeyId!!
                    .bytes(p.tbsBytes)
                    .toByteString()
                    .hex(),
                "$name AKI",
            )
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
