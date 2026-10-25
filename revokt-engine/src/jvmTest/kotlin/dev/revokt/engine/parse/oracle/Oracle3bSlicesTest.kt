// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.producer.ProducerCorpus
import dev.revokt.engine.parse.records.CorpusRecord
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Oracle 3b's TBS walk and field slices (spec §9.2) on the replay corpus: 3b locates every input revokt parses, with
 * revokt's serial, SPKI, subject, issuer, extension table, SCT pair set and `Cert.sig`; and its slices equal 3a's
 * wherever 3a accepts, outside 3a's recorded divergence classes (`3A_HEADER_LAX`, `3A_TBS_LAX`), which 3b decides.
 */
class Oracle3bSlicesTest {
    private class Row(
        val name: String,
        val der: ByteArray,
        val reply: String,
    )

    private val rows: List<Row> by lazy {
        ProducerCorpus.inputs.map { input ->
            val reply =
                Oracle3b.reply(sha(input.der))
                    ?: fail("${input.name}: no 3b golden; run native/revokt-oracle/record-goldens.sh")
            Row(input.name, input.der, reply)
        }
    }

    private fun sha(der: ByteArray) = der.toByteString().sha256().hex()

    @Test
    fun `3b locates every input revokt parses, with revokt's fields`() {
        val parsed =
            rows.mapNotNull { row ->
                (CertificateParser.parse(row.der) as? CertificateParse.Parsed)?.certificate?.let { row to it }
            }
        for ((row, c) in parsed) {
            val b = Oracle3b.located(row.reply) ?: fail("${row.name}: revokt parses, 3b answers ${row.reply.take(160)}")
            assertRevoktFields(row.name, c, b)
        }
        assertTrue(parsed.size > 1000, "only ${parsed.size} inputs compared")
        // The other direction: 3b locates only what revokt parses, but for a Certificate header of five or more
        // length octets, which 3b's envelope reads (the reference view) and revokt and the JDK reject.
        val parsedNames = parsed.map { it.first.name }.toSet()
        val locatedOnly = rows.filter { Oracle3b.located(it.reply) != null && it.name !in parsedNames }.map { it.name }
        assertEquals(LOCATED_NOT_PARSED, locatedOnly.toSet(), "inputs 3b locates and revokt rejects")
    }

    private fun assertRevoktFields(
        name: String,
        c: ParsedCertificate,
        b: Oracle3b.Located,
    ) {
        assertEquals(b.serial, Oracle3a.hex(c.rawSerial()), "$name serial")
        assertEquals(b.spki, Oracle3a.hex(c.rawSpki()), "$name spki")
        assertEquals(b.subject, Oracle3a.hex(c.rawSubject()), "$name subject")
        assertEquals(b.issuer, Oracle3a.hex(c.rawIssuer()), "$name issuer")
        assertEquals(b.parts.tbs, Oracle3a.hex(c.tbsBytes), "$name Cert.tbs")
        val signature = Oracle3a.cleared(b.parts.signature, b.unusedBits ?: 0)
        assertEquals(signature, Oracle3a.hex(c.envelope.signature), "$name Cert.sig")
        val revoktTable =
            c.tbs.extensions.map {
                "${Oracle3a.hex(it.oid.bytes(c.tbsBytes))},${it.critical},${Oracle3a.hex(it.value.bytes(c.tbsBytes))}"
            }
        assertEquals(b.extensions.map(::table), revoktTable, "$name extension table")
        val union = b.extensions.flatMap { it.sct.orEmpty() }.toSet()
        val revoktScts =
            c.fields.scts
                .map { Oracle3a.hex(it.logId.toByteArray()) to it.timestamp }
                .toSet()
        assertEquals(union, revoktScts, "$name SCT pairs")
    }

    @Test
    fun `3b's slices equal 3a's wherever 3a accepts, outside 3a's divergence classes`() {
        val goldens = Oracle3a.goldens()
        val accepted =
            rows.mapNotNull { row ->
                goldens[sha(row.der)]?.let { Oracle3a.accepted(it) }?.let { row to it }
            }
        val located = accepted.mapNotNull { (row, a) -> Oracle3b.located(row.reply)?.let { Triple(row.name, a, it) } }
        val divergences = HashMap<String, MutableList<String>>()
        for ((name, a, b) in located) compareSlices(name, a, b, divergences)
        val walkFailed = accepted.filter { (row, _) -> Oracle3b.located(row.reply) == null }.map { it.first.name }
        assertEquals(WALK_FAILS_WHERE_3A_ACCEPTS, walkFailed.toSet(), "inputs 3a accepts and 3b's walk does not")
        // The divergence classes are the committed D3_DIVERGENCE records (spec §9.2 D3, RecordsTest); 3b decides two.
        val recorded = CorpusRecord.divergences().filterKeys { it in setOf("3A_HEADER_LAX", "3A_TBS_LAX") }
        assertEquals(setOf("3A_HEADER_LAX", "3A_TBS_LAX"), recorded.keys, "both 3b-decided classes are recorded")
        assertEquals(recorded, divergences.mapValues { it.value.toSet() }, "divergence classes")
        assertTrue(located.size > 1000, "only ${located.size} inputs compared")
    }

    private fun compareSlices(
        name: String,
        a: Oracle3a.Accepted,
        b: Oracle3b.Located,
        divergences: MutableMap<String, MutableList<String>>,
    ) {
        assertEquals(listOf(a.serial, a.spki, a.subject, a.issuer), listOf(b.serial, b.spki, b.subject, b.issuer), name)
        if (b.tagThreeIgnored) {
            // 3A_TBS_LAX: the §9.2 read has no extensions.
            assertEquals(emptyList(), b.extensions.map(::table), "$name: 3b reads extensions after an ignored element")
            divergences.getOrPut("3A_TBS_LAX") { ArrayList() } += name
            return
        }
        assertEquals(a.extensions.map(::table), b.extensions.map(::table), "$name extension table")
        for ((ea, eb) in a.extensions.zip(b.extensions)) {
            if (eb.value.startsWith("04") || ea.sct.isNullOrEmpty()) {
                assertEquals(sct(ea), sct(eb), "$name SCT field")
            } else {
                // 3A_HEADER_LAX: 3a yields pairs under an inner identifier other than 0x04; §9.2 fails the list.
                assertTrue(eb.sctError, "$name: 3b keeps pairs under inner identifier ${eb.value.take(4)}")
                divergences.getOrPut("3A_HEADER_LAX") { ArrayList() } += name
            }
        }
    }

    private fun table(e: Oracle3a.Extension) = "${e.oid},${e.critical},${e.value}"

    private fun sct(e: Oracle3a.Extension) = if (e.sctError) "E" else e.sct?.joinToString("+") ?: "-"

    private companion object {
        /** 3b locates and revokt rejects: a Certificate header of five or more length octets (the JDK rejects it too). */
        val LOCATED_NOT_PARSED: Set<String> =
            setOf("envelope/letsencrypt.org-1/certificate-long5", "envelope/letsencrypt.org-1/certificate-long8")

        /** Where §9.2 is stricter than x509-parser; revokt rejects each of these too. */
        val WALK_FAILS_WHERE_3A_ACCEPTS: Set<String> =
            setOf(
                // Bytes after signatureValue and after Certificate: 3b's envelope does not locate them.
                "variants/cert-null-after-signature",
                "fuzz/trailing-byte",
                // Validity and [0] hold exactly their elements.
                "variants/validity-null-after-times",
                "variants/version-wrapper-trailing",
                "d7/version-trailing-null",
                // A multi-octet identifier where the tail read meets it.
                "d3/tag3-9f03",
                "d3/tag3-bf03",
                "d7/stop-9f01",
                "d7/stop-bf02",
                // A length of five octets inside the TBS.
                "envelope/letsencrypt.org-1/version-long5",
                "envelope/letsencrypt.org-1/tbs-signature-long5",
            )
    }
}
