// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.producer.Canon
import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Oracle 3b's `canon` (spec §9.2) on the replay corpus: it exists for every input revokt parses, with `Cert.tbs` and the
 * TBS signature; it agrees with 3a's parts wherever 3a accepts; and it equals the test-side [Canon], written
 * independently again, on every input, existence included. The D8 replay takes `canon` from 3b.
 */
class Oracle3bTest {
    private class Row(
        val name: String,
        val der: ByteArray,
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
            Row(input.name, input.der, Oracle3b.parts(reply))
        }
    }

    @Test
    fun `3b builds canon for every input revokt parses, with Cert tbs and the TBS signature`() {
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
        // 3a also accepts elements after signatureValue, which 3b, revokt and the JDK reject: compare where both have parts.
        val pairs =
            rows.mapNotNull { row ->
                val a =
                    goldens[
                        row.der
                            .toByteString()
                            .sha256()
                            .hex(),
                    ]?.let { Oracle3a.accepted(it) }
                if (a != null && row.parts != null) Triple(row.name, a, row.parts) else null
            }
        for ((name, a, b) in pairs) {
            assertEquals(a.tbs, b.tbs, "$name tbs")
            assertEquals(a.tbsSignature, b.tbsSignature, "$name TBS signature")
            assertEquals(a.signature, b.signature, "$name signature octets")
        }
        assertTrue(pairs.size > 1000, "only ${pairs.size} inputs compared")
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
}
