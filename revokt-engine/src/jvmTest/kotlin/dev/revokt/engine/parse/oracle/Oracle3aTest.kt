// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.IgnoredSite
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Spec §9.2 D2 against oracle 3a on the replay corpus: wherever revokt parses and 3a accepts, the raw serial, SPKI,
 * subject, issuer, extension table, SCT pair set, `Cert.tbs` and `Cert.sig` agree. The SCT pairs follow the per-extension
 * expectation (∅ when the value's first octet is not `0x04`, recorded as `3A_HEADER_LAX` when 3a yields pairs), and a
 * primitive `[3]` that 3a reads as extensions while revokt ignores it is recorded as `3A_TBS_LAX` with the §9.2 read.
 */
class Oracle3aTest {
    private val goldens by lazy { Oracle3a.goldens() }

    private enum class Divergence { HEADER_LAX, TBS_LAX }

    @Test
    fun `revokt extracts what 3a extracts wherever both accept`() {
        var compared = 0
        val divergences = HashMap<Divergence, MutableList<String>>()
        for (input in ProducerCorpus.inputs) {
            val sha =
                input.der
                    .toByteString()
                    .sha256()
                    .hex()
            val reply =
                goldens[sha] ?: fail("${input.name}: no 3a golden; run native/revokt-oracle/record-goldens.sh")
            val c = (CertificateParser.parse(input.der) as? CertificateParse.Parsed)?.certificate
            val a = Oracle3a.accepted(reply)
            if (c != null && a != null) {
                compared++
                compare(input.name, c, a, divergences)
            }
        }
        println("D2 against 3a: $compared inputs; divergences ${divergences.mapValues { it.value.size }}")
        assertEquals<List<String>?>(listOf("d3/sct-inner-44"), divergences[Divergence.HEADER_LAX], "3A_HEADER_LAX")
        assertEquals<List<String>?>(listOf("d3/primitive-3"), divergences[Divergence.TBS_LAX], "3A_TBS_LAX")
        assertTrue(compared > 1000, "only $compared inputs compared")
    }

    private fun compare(
        name: String,
        c: ParsedCertificate,
        a: Oracle3a.Accepted,
        divergences: MutableMap<Divergence, MutableList<String>>,
    ) {
        assertEquals(a.serial, Oracle3a.hex(c.rawSerial()), "$name serial")
        assertEquals(a.spki, Oracle3a.hex(c.rawSpki()), "$name spki")
        assertEquals(a.subject, Oracle3a.hex(c.rawSubject()), "$name subject")
        assertEquals(a.issuer, Oracle3a.hex(c.rawIssuer()), "$name issuer")
        assertEquals(a.tbs, Oracle3a.hex(c.tbsBytes), "$name Cert.tbs")
        assertEquals(a.tbsSignature, Oracle3a.hex(c.tbs.signature.bytes(c.tbsBytes)), "$name TBS signature")
        val presented = c.envelope.signatureValue
        val unused = if (presented.length > 0) c.der[presented.start].toInt() and 0xff else 0
        assertEquals(cleared(a.signature, unused), Oracle3a.hex(c.envelope.signature), "$name Cert.sig")
        val revoktExtensions =
            c.tbs.extensions.map {
                "${Oracle3a.hex(it.oid.bytes(c.tbsBytes))},${it.critical},${Oracle3a.hex(it.value.bytes(c.tbsBytes))}"
            }
        val oracleExtensions = a.extensions.map { "${it.oid},${it.critical},${it.value}" }
        if (revoktExtensions != oracleExtensions) {
            // 3A_TBS_LAX: 3a takes a primitive [3] as extensions; revokt, like the JDK, ignores it (spec §9.2, D3).
            val primitive3 =
                c.ignoredElements.any {
                    it.site == IgnoredSite.TBS_AFTER_STOP &&
                        c.tbsBytes[it.span.start].toInt() and 0xff == 0x83
                }
            assertTrue(
                primitive3 && revoktExtensions.isEmpty(),
                "$name extensions: revokt $revoktExtensions, 3a $oracleExtensions",
            )
            divergences.getOrPut(Divergence.TBS_LAX) { ArrayList() }.add(name)
            assertEquals(emptySet(), c.fields.scts, "$name: the §9.2 read of a primitive [3] has no SCTs")
            return
        }
        val expected = HashSet<Pair<String, Long>>()
        for ((index, e) in a.extensions.withIndex()) {
            if (e.sct == null) continue
            val pairs = e.sct
            val value = c.tbs.extensions[index].value
            val innerIsOctetString = value.length > 0 && c.tbsBytes[value.start].toInt() and 0xff == 0x04
            if (innerIsOctetString) {
                expected += pairs
            } else if (pairs.isNotEmpty()) {
                divergences.getOrPut(Divergence.HEADER_LAX) { ArrayList() }.add(name)
            }
        }
        val actual =
            c.fields.scts
                .map { Oracle3a.hex(it.logId.toByteArray()) to it.timestamp }
                .toSet()
        assertEquals(expected, actual, "$name SCT pairs")
    }

    private fun cleared(
        hex: String,
        unused: Int,
    ): String {
        if (hex.isEmpty()) return hex
        val b = Oracle3a.bytes(hex)
        b[b.lastIndex] = (b[b.lastIndex].toInt() and (0xff shl minOf(unused, 8))).toByte()
        return Oracle3a.hex(b)
    }

    @Test
    fun `the 3a recording hook writes the corpus on request`() {
        Oracle3a.writeInputsIfRequested()
    }
}
