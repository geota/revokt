// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.producer.Canon
import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Oracle 3b's `canon` (spec §9.2) on the replay corpus: it exists for every input revokt parses, with `Cert.tbs` and the
 * TBS signature; it agrees with 3a's parts wherever 3a accepts; it equals the test-side [Canon], written independently
 * again, on every input, existence included; and wherever the JDK parses, its TBS is `getTBSCertificate()`, so the
 * re-encoding is checked against the platform and not only against code written to the same reading.
 */
class Oracle3bTest {
    private class Row(
        val name: String,
        val der: ByteArray,
        val reply: String,
        val parts: Oracle3b.Parts?,
    )

    private val rows: List<Row> by lazy {
        ProducerCorpus.inputs.map { input ->
            val sha =
                input.der
                    .toByteString()
                    .sha256()
                    .hex()
            val reply =
                Oracle3b.reply(sha) ?: fail("${input.name}: no 3b golden; run native/revokt-oracle/record-goldens.sh")
            Row(input.name, input.der, reply, Oracle3b.parts(reply))
        }
    }

    @Test
    fun `3b builds canon for every input revokt parses, with Cert tbs and the TBS signature`() {
        assertEquals(emptyList(), rows.filter { it.reply.startsWith("PANIC") }.map { it.name }, "3b panics")
        var compared = 0
        for (row in rows) {
            val c = (CertificateParser.parse(row.der) as? CertificateParse.Parsed)?.certificate ?: continue
            val b = assertNotNull(row.parts, "${row.name}: revokt parses, 3b has no canon")
            assertEquals(b.tbs, Oracle3a.hex(c.tbsBytes), "${row.name} Cert.tbs")
            assertEquals(b.tbsSignature, Oracle3a.hex(c.tbs.signature.bytes(c.tbsBytes)), "${row.name} TBS signature")
            compared++
        }
        assertTrue(compared > 1000, "only $compared inputs compared")
    }

    @Test
    fun `3b's canon parts agree with 3a's wherever both have them`() {
        val goldens = Oracle3a.goldens()
        val acceptedByThreeA =
            rows.mapNotNull { row ->
                val sha =
                    row.der
                        .toByteString()
                        .sha256()
                        .hex()
                goldens[sha]?.let { Oracle3a.accepted(it) }?.let { row to it.canon }
            }
        val (both, notLocated) = acceptedByThreeA.partition { (row, _) -> row.parts != null }
        for ((row, a) in both) {
            val b = row.parts!!
            assertEquals(a.tbs, b.tbs, "${row.name} tbs")
            assertEquals(a.tbsSignature, b.tbsSignature, "${row.name} TBS signature")
            assertEquals(a.signature, b.signature, "${row.name} signature octets")
        }
        // 3a also accepts bytes after signatureValue and after Certificate, which 3b's envelope rule does not locate;
        // canon takes 3a's parts there (the reference view, ProducerCorpus.Input.canon).
        val names = notLocated.map { (row, _) -> row.name }.toSet()
        assertEquals(THREE_B_NOT_LOCATED, names, "inputs 3a accepts and 3b does not locate")
        assertTrue(both.size > 1000, "only ${both.size} inputs compared")
    }

    @Test
    fun `3b's canon equals the test-side Canon on every input`() {
        for (row in rows) {
            val expected = Canon.of(row.der)
            val actual = row.parts?.canon()
            if (expected == null || actual == null) {
                assertEquals(expected == null, actual == null, "${row.name}: canon exists for one implementation only")
            } else {
                assertContentEquals(expected, actual, "${row.name} canon")
            }
        }
    }

    @Test
    fun `3b's TBS and signature are the JDK's wherever the JDK parses`() {
        val factory = CertificateFactory.getInstance("X.509")
        val compared =
            rows.mapNotNull { row ->
                val b = row.parts
                val jdk =
                    runCatching { factory.generateCertificate(ByteArrayInputStream(row.der)) as X509Certificate }
                        .getOrNull()
                if (b != null && jdk != null) {
                    assertEquals(b.tbs, Oracle3a.hex(jdk.tbsCertificate), "${row.name}: getTBSCertificate()")
                    assertSameUpToPadding(row.name, Oracle3a.bytes(b.signature), jdk.signature)
                    row.name
                } else {
                    null
                }
            }
        println("3b against the JDK: ${compared.size} inputs")
        assertTrue(compared.size > 1000, "only ${compared.size} inputs compared")
        assertEquals(emptyList(), NESTED_INDEFINITE.filter { it !in compared }, "nested chains the JDK parses")
    }

    /** The JDK clears the last octet's padding bits; 3b keeps them. */
    private fun assertSameUpToPadding(
        name: String,
        signature: ByteArray,
        jdkSignature: ByteArray,
    ) {
        assertEquals(signature.size, jdkSignature.size, "$name: getSignature() length")
        if (signature.isEmpty()) return
        assertContentEquals(signature.copyOf(signature.size - 1), jdkSignature.copyOf(jdkSignature.size - 1), name)
        val jdkLast = jdkSignature.last().toInt() and 0xff
        assertEquals(jdkLast, signature.last().toInt() and jdkLast, "$name: getSignature() differs beyond padding")
    }

    private companion object {
        val THREE_B_NOT_LOCATED: Set<String> = setOf("variants/cert-null-after-signature", "fuzz/trailing-byte")

        /** Nested indefinite chains the JDK parses (and verifies, `CertificateParserEnvelopeJdkTest`). */
        val NESTED_INDEFINITE: List<String> =
            listOf(
                "envelope/letsencrypt.org-1/tbs-indefinite-validity",
                "envelope/letsencrypt.org-1/tbs-indefinite-subject-chain",
                "envelope/letsencrypt.org-1/tbs-indefinite-extension-chain",
                "envelope/www.mozilla.org-1/alg-indefinite-null-indefinite",
            )
    }
}
