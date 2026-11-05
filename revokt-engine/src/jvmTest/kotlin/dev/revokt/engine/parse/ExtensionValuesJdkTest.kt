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
    private val boolTrue = tlv(0x01, bytes(0xff))

    private val spki: ByteArray =
        KeyPairGenerator
            .getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
            .public.encoded

    /** What one reader read, as the JDK getter would report it; a failure or an absence reports the getter's null. */
    private fun revokt(c: ParsedCertificate): List<Any?> =
        listOf(
            when (val r = ExtensionValues.basicConstraints(c)) {
                is ExtensionRead.Value -> if (r.value.ca) r.value.pathLen ?: Int.MAX_VALUE else -1
                else -> -1
            },
            (ExtensionValues.keyUsage(c) as? ExtensionRead.Value)?.value?.let { ku ->
                List(maxOf(9, ku.bits.size)) { ku[it] }
            },
            (ExtensionValues.extendedKeyUsage(c) as? ExtensionRead.Value)?.value?.purposes?.map {
                Oid.dotted(it.toByteArray(), Span(0, it.size))
            },
            (ExtensionValues.subjectAltName(c) as? ExtensionRead.Value)?.value?.dnsNames,
        )

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
     * Over the committed replay corpus: wherever the JDK reports a value and revokt reads one, they are equal; where
     * either reports none, the input is counted, and an input where revokt reads a value the JDK cannot is listed.
     */
    @Test
    fun `the readers agree with the JDK over the committed corpus`() {
        val labels = listOf("basicConstraints", "keyUsage", "extKeyUsage", "subjectAltName")
        var compared = 0
        val differ = ArrayList<String>()
        val onlyRevokt = ArrayList<String>()
        val onlyJdk = ArrayList<String>()
        val agreed = labels.associateWithTo(LinkedHashMap()) { 0 }
        for (input in ProducerCorpus.inputs) {
            val x = (Oracle1.run(input.der) as? PlatformOracle.Outcome.Accept)?.certificate ?: continue
            val c = (CertificateParser.parse(input.der) as? CertificateParse.Parsed)?.certificate ?: continue
            compared++
            val ours = revokt(c)
            val theirs = jdk(x)
            for (i in labels.indices) {
                val absent = if (i == 0) -1 else null
                when {
                    ours[i] == theirs[i] -> if (ours[i] != absent) agreed.merge(labels[i], 1, Int::plus)
                    ours[i] == absent -> onlyJdk += "${input.name} ${labels[i]}"
                    theirs[i] == absent -> onlyRevokt += "${input.name} ${labels[i]}"
                    else -> differ += "${input.name} ${labels[i]}: JDK ${theirs[i]}, revokt ${ours[i]}"
                }
            }
        }
        println(
            "extension readers vs the JDK: $compared inputs, values agreed $agreed; JDK only: $onlyJdk; revokt only: $onlyRevokt",
        )
        assertTrue(compared > 100, "only $compared inputs compared")
        assertTrue(agreed.values.all { it > 10 }, "too few values compared: $agreed")
        assertEquals(emptyList(), differ)
    }
}
