// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.oid
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import dev.revokt.engine.parse.oracle.Oracle1
import dev.revokt.engine.parse.oracle.PlatformOracle
import dev.revokt.engine.parse.producer.ExternalCorpus
import dev.revokt.engine.parse.producer.ProducerCorpus
import java.security.KeyPairGenerator
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The x5u extension readers (spec §7.1, #106) against the JDK's `getBasicConstraints()`, `getKeyUsage()`,
 * `getExtendedKeyUsage()` and `getSubjectAlternativeNames()`: on x5u-shaped certificates built here and on every
 * input of the committed replay corpus (spec §9.2) both the JDK and revokt parse.
 */
class ExtensionValuesJdkTest {
    private val codeSigning = "1.3.6.1.5.5.7.3.3"

    private companion object {
        val LABELS = listOf("basicConstraints", "keyUsage", "extKeyUsage", "subjectAltName")
    }

    /** The one committed input whose value the JDK reads and K8 rejects: keyUsage padding bits set. */
    private val paddingInput = "boundary/reject-key-usage-03-01-05"
    private val boolTrue = tlv(0x01, bytes(0xff))

    private val spki: ByteArray =
        KeyPairGenerator
            .getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
            .public.encoded

    /**
     * What each reader read, as the JDK getter would report it; a failure or an absence reports the getter's null.
     * With [strict] false, the one extension with each OID is read as K8 reads it, without the length-form check.
     */
    private fun revokt(
        c: ParsedCertificate,
        strict: Boolean = true,
    ): List<Any?> {
        fun <T> read(
            certificate: ExtensionRead<T>,
            dotted: String,
            reader: (ByteArray, Span, Boolean) -> ExtensionRead<T>,
        ): T? {
            val r =
                if (strict) {
                    certificate
                } else {
                    c
                        .extensions(
                            dotted,
                        ).singleOrNull()
                        ?.let { reader(c.tbsBytes, it.value, false) }
                }
            return (r as? ExtensionRead.Value)?.value
        }
        val bc =
            read(
                ExtensionValues.basicConstraints(c),
                ExtensionValues.BASIC_CONSTRAINTS,
                ExtensionValues::basicConstraints,
            )
        val ku = read(ExtensionValues.keyUsage(c), ExtensionValues.KEY_USAGE, ExtensionValues::keyUsage)
        val eku =
            read(ExtensionValues.extendedKeyUsage(c), ExtensionValues.EXT_KEY_USAGE, ExtensionValues::extendedKeyUsage)
        val san =
            read(ExtensionValues.subjectAltName(c), ExtensionValues.SUBJECT_ALT_NAME, ExtensionValues::subjectAltName)
        return listOf(
            bc?.let { if (it.ca) it.pathLen ?: Int.MAX_VALUE else -1 } ?: -1,
            ku?.let { List(maxOf(9, it.bits.size)) { bit -> it[bit] } },
            eku?.purposes?.map { Oid.dotted(it.toByteArray(), Span(0, it.size)) },
            san?.dnsNames,
        )
    }

    private fun jdk(x: X509Certificate): List<Any?> =
        listOf(
            x.basicConstraints,
            x.keyUsage?.toList(),
            x.extendedKeyUsage,
            try {
                x.subjectAlternativeNames?.filter { it[0] == 2 }?.map { it[1] as String }
            } catch (_: CertificateParsingException) {
                null
            },
        )

    private fun parsed(der: ByteArray): ParsedCertificate =
        when (val r = CertificateParser.parse(der)) {
            is CertificateParse.Parsed -> r.certificate
            is CertificateParse.Failed -> fail("${r.reason} ${r.detail}")
        }

    private fun x509(der: ByteArray): X509Certificate =
        when (val o = Oracle1.run(der)) {
            is PlatformOracle.Outcome.Accept -> o.certificate
            else -> fail("the JDK rejects the certificate: $o")
        }

    private fun built(vararg extensions: ByteArray): ByteArray =
        TestCert(spki = spki, extensions = extensions.toList()).der

    @Test
    fun `the readers agree with the JDK on the x5u-shaped certificates`() {
        val bc = ExtensionValues.BASIC_CONSTRAINTS
        val ku = ExtensionValues.KEY_USAGE
        val caKeyUsage = TestDer.extension(ku, tlv(0x03, bytes(0x01, 0x06)), critical = true)
        val certificates =
            mapOf(
                "CA, pathLen 0" to
                    built(TestDer.extension(bc, seq(boolTrue, tlv(0x02, bytes(0))), critical = true), caKeyUsage),
                "CA, pathLen 300" to
                    built(
                        TestDer.extension(bc, seq(boolTrue, tlv(0x02, bytes(0x01, 0x2c))), critical = true),
                        caKeyUsage,
                    ),
                "CA, no pathLen" to built(TestDer.extension(bc, seq(boolTrue), critical = true), caKeyUsage),
                "CA, no keyUsage" to built(TestDer.extension(bc, seq(boolTrue))),
                "cA FALSE encoded" to built(TestDer.extension(bc, seq(tlv(0x01, bytes(0))))),
                "cA omitted" to built(TestDer.extension(bc, seq())),
                "leaf" to
                    built(
                        TestDer.extension(ku, tlv(0x03, bytes(0x07, 0x80)), critical = true),
                        TestDer.extension(ExtensionValues.EXT_KEY_USAGE, seq(oid(codeSigning))),
                        TestDer.extension(
                            ExtensionValues.SUBJECT_ALT_NAME,
                            seq(tlv(0x82, ascii("onecrl.content-signature.mozilla.org"))),
                        ),
                    ),
                "leaf, two names and a URI" to
                    built(
                        TestDer.extension(
                            ExtensionValues.SUBJECT_ALT_NAME,
                            seq(
                                tlv(0x82, ascii("a.example")),
                                tlv(0x86, ascii("https://a.example/")),
                                tlv(0x82, ascii("b.example")),
                            ),
                        ),
                    ),
                "keyUsage, 9 bits" to built(TestDer.extension(ku, tlv(0x03, bytes(0x07, 0x04, 0x80)))),
                "keyUsage, 16 bits" to built(TestDer.extension(ku, tlv(0x03, bytes(0x00, 0xff, 0xff)))),
                "keyUsage, 6 bits" to built(TestDer.extension(ku, tlv(0x03, bytes(0x02, 0x04)))),
                "keyUsage, 5 bits" to built(TestDer.extension(ku, tlv(0x03, bytes(0x03, 0xf8)))),
            )
        for ((name, der) in certificates) assertEquals(jdk(x509(der)), revokt(parsed(der)), name)
        // The JDK rejects an empty SAN; revokt reads it as malformed.
        val empty = parsed(built(TestDer.extension(ExtensionValues.SUBJECT_ALT_NAME, seq())))
        assertTrue(ExtensionValues.subjectAltName(empty) is ExtensionRead.Failed)
    }

    @Test
    fun `the readers read Mozilla's content-signing chain as section 7_1 expects`() {
        val (leaf, intermediate, root) =
            (0..2).map {
                parsed(ProducerCorpus.resource("certs/mozilla-content-signing-c$it.der"))
            }
        assertEquals(ExtensionRead.Absent, ExtensionValues.basicConstraints(leaf))
        assertEquals(
            listOf("onecrl.content-signature.mozilla.org"),
            (ExtensionValues.subjectAltName(leaf) as ExtensionRead.Value).value.dnsNames,
        )
        assertTrue(
            (
                ExtensionValues.extendedKeyUsage(
                    leaf,
                ) as ExtensionRead.Value
            ).value.contains(TestDer.oidContent(codeSigning)),
        )
        assertEquals(false, (ExtensionValues.keyUsage(leaf) as ExtensionRead.Value).value.keyCertSign)
        for (ca in listOf(intermediate, root)) {
            val bc = (ExtensionValues.basicConstraints(ca) as ExtensionRead.Value).value
            assertEquals(true to null, bc.ca to bc.pathLen)
            assertTrue((ExtensionValues.keyUsage(ca) as ExtensionRead.Value).value.keyCertSign)
        }
    }

    /**
     * Over the committed replay corpus: wherever the JDK reports a value and revokt reads one, they are equal; revokt
     * reads no value the JDK does not, and the JDK reads one revokt does not on one known input only.
     */
    @Test
    fun `the readers agree with the JDK over the committed corpus`() {
        val both =
            ProducerCorpus.inputs.mapNotNull { input ->
                val x = (Oracle1.run(input.der) as? PlatformOracle.Outcome.Accept)?.certificate
                val c = (CertificateParser.parse(input.der) as? CertificateParse.Parsed)?.certificate
                if (x == null || c == null) null else Compared(input.name, revokt(c), revokt(c, strict = false), jdk(x))
            }
        val findings = both.flatMap { it.findings() }
        val by = findings.groupBy { it.agreement }
        val agreed =
            LABELS.associateWith { label ->
                by[Agreement.SAME_VALUE].orEmpty().count { it.extension == label }
            }
        val onlyJdk = by[Agreement.JDK_ONLY].orEmpty()
        val onlyRevokt = by[Agreement.REVOKT_ONLY].orEmpty()
        println(
            "extension readers vs the JDK: ${both.size} inputs, values agreed $agreed; " +
                "JDK only: ${onlyJdk.map { it.label }}; revokt only: ${onlyRevokt.map { it.label }}",
        )
        assertTrue(both.size > 100, "only ${both.size} inputs compared")
        assertTrue(agreed.values.all { it > 10 }, "too few values compared: $agreed")
        assertEquals(emptyList(), by[Agreement.DIFFER].orEmpty().map { it.label })
        // Pinned over the committed corpus; the large corpus (docs/dev/corpus.md) holds DNS names the JDK's syntax
        // check rejects, and is only reported.
        assertEquals(emptyList(), onlyRevokt.filter { it.committed }.map { it.label }, "values only revokt reads")
        // K8 rejects non-zero keyUsage padding bits, which the JDK ignores. Strict readers reject a non-minimal length,
        // which the JDK accepts (mozilla::pkix does not): every other such value comes from a length mutant whose read
        // without that check is the JDK's value.
        val known = onlyJdk.filter { it.committed && !it.lengthForm }
        assertEquals(listOf("$paddingInput keyUsage"), known.map { it.label }, "values only the JDK reads")
        assertTrue(onlyJdk.any { it.lengthForm }, "no length mutant inside an extension value was compared")
    }

    private data class Finding(
        val label: String,
        val extension: String,
        val agreement: Agreement,
        val committed: Boolean,
        val lengthForm: Boolean,
    )

    private data class Compared(
        val name: String,
        val revokt: List<Any?>,
        val lenient: List<Any?>,
        val jdk: List<Any?>,
    )

    private enum class Agreement { SAME_VALUE, SAME_ABSENT, JDK_ONLY, REVOKT_ONLY, DIFFER }

    /** One [Finding] per extension of this input. */
    private fun Compared.findings(): List<Finding> =
        LABELS.indices.map { i ->
            val agreement = compare(revokt[i], jdk[i], if (i == 0) -1 else null)
            val lengthForm = agreement == Agreement.JDK_ONLY && name.startsWith("mutant/") && lenient[i] == jdk[i]
            val label = "$name ${LABELS[i]}"
            Finding(label, LABELS[i], agreement, !ExternalCorpus.owns(name), lengthForm)
        }

    /** How revokt's [ours] and the JDK's [theirs] compare, [absent] being what a getter reports for no value. */
    private fun compare(
        ours: Any?,
        theirs: Any?,
        absent: Any?,
    ): Agreement =
        when {
            ours == theirs -> if (ours == absent) Agreement.SAME_ABSENT else Agreement.SAME_VALUE
            ours == absent -> Agreement.JDK_ONLY
            theirs == absent -> Agreement.REVOKT_ONLY
            else -> Agreement.DIFFER
        }
}
