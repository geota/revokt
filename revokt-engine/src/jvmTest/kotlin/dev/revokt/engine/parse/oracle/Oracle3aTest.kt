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
 * Spec §9.2 D2 against oracle 3a on the replay corpus: wherever revokt parses and 3a accepts, the raw serial, SPKI,
 * subject, issuer, extension table, SCT pair set, `Cert.tbs` and `Cert.sig` agree. The SCT pairs follow the per-extension
 * expectation (∅ when the value's first octet, as 3b locates it, is not `0x04`, recorded as `3A_HEADER_LAX` when 3a
 * yields pairs), and an element with tag number 3 other than a constructed context `[3]` that 3a reads as extensions
 * while 3b's walk and revokt ignore it is recorded as `3A_TBS_LAX` with the §9.2 read (revision 37).
 */
class Oracle3aTest {
    private val goldens by lazy { Oracle3a.goldens() }

    private enum class Divergence { HEADER_LAX, TBS_LAX, DUPLICATE }

    @Test
    fun `revokt extracts what 3a extracts wherever both accept`() {
        var compared = 0
        val divergences = HashMap<Divergence, MutableList<String>>()
        val rejectedByThreeA = ArrayList<String>()
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
                val b =
                    Oracle3b.reply(sha)?.let { Oracle3b.located(it) }
                        ?: fail("${input.name}: revokt parses, 3b does not locate it")
                compare(input.name, c, a, b, divergences)
            } else if (c != null) {
                rejectedByThreeA += input.name
            }
        }
        println("D2 against 3a: $compared inputs; divergences ${divergences.mapValues { it.value.size }}")
        // The divergence classes are the committed D3_DIVERGENCE records (spec §9.2 D3, RecordsTest).
        val recorded = CorpusRecord.divergences()
        for ((d, name) in listOf(
            Divergence.HEADER_LAX to "3A_HEADER_LAX",
            Divergence.DUPLICATE to "DUPLICATE_EXTENSION",
        )) {
            assertEquals(recorded[name], divergences[d]?.toSet(), name)
        }
        // Inputs revokt parses and 3a rejects (x509-parser refuses indefinite and some JDK-tolerated forms): pinned, so
        // a wrapper regression cannot shrink D2 unnoticed. They are D2-referenced by 3b (#38).
        assertEquals(THREE_A_REJECTS, rejectedByThreeA.toSet(), "inputs revokt parses that 3a rejects")
        assertEquals(recorded["3A_TBS_LAX"], divergences[Divergence.TBS_LAX]?.toSet(), "3A_TBS_LAX")
        assertTrue(compared > 1000, "only $compared inputs compared")
    }

    private fun compare(
        name: String,
        c: ParsedCertificate,
        a: Oracle3a.Accepted,
        b: Oracle3b.Located,
        divergences: MutableMap<Divergence, MutableList<String>>,
    ) {
        assertEquals(a.serial, Oracle3a.hex(c.rawSerial()), "$name serial")
        assertEquals(a.spki, Oracle3a.hex(c.rawSpki()), "$name spki")
        assertEquals(a.subject, Oracle3a.hex(c.rawSubject()), "$name subject")
        assertEquals(a.issuer, Oracle3a.hex(c.rawIssuer()), "$name issuer")
        assertEquals(a.canon.tbs, Oracle3a.hex(c.tbsBytes), "$name Cert.tbs")
        assertEquals(a.canon.tbsSignature, Oracle3a.hex(c.tbs.signature.bytes(c.tbsBytes)), "$name TBS signature")
        assertEquals(
            Oracle3a.cleared(a.canon.signature, a.canon.unusedBits),
            Oracle3a.hex(c.envelope.signature),
            "$name Cert.sig",
        )
        val revoktExtensions =
            c.tbs.extensions.map {
                "${Oracle3a.hex(it.oid.bytes(c.tbsBytes))},${it.critical},${Oracle3a.hex(it.value.bytes(c.tbsBytes))}"
            }
        val oracleExtensions = a.extensions.map { "${it.oid},${it.critical},${it.value}" }
        if (revoktExtensions != oracleExtensions) {
            // 3A_TBS_LAX: 3a takes an element with tag number 3 that is not a constructed context [3] as extensions;
            // revokt, like the JDK, ignores it. 3b's TBS walk decides the class (spec §9.2 D2, revision 37).
            assertTrue(
                b.tagThreeIgnored && revoktExtensions.isEmpty(),
                "$name extensions: revokt $revoktExtensions, 3a $oracleExtensions, 3b stop ${b.stop}",
            )
            divergences.getOrPut(Divergence.TBS_LAX) { ArrayList() }.add(name)
            assertEquals(emptySet(), c.fields.scts, "$name: the §9.2 read of an ignored tag-3 element has no SCTs")
            return
        }
        assertEquals(oracleExtensions, b.extensions.map { "${it.oid},${it.critical},${it.value}" }, "$name 3b table")
        val expected = HashSet<Pair<String, Long>>()
        for ((index, e) in a.extensions.withIndex()) {
            if (e.sct == null) continue
            val pairs = e.sct
            // The inner identifier octet is read by 3b's locator, never by revokt (spec §9.2 D2).
            val innerIsOctetString = b.extensions[index].value.startsWith("04")
            if (innerIsOctetString) {
                expected += pairs
            } else if (pairs.isNotEmpty()) {
                divergences.getOrPut(Divergence.HEADER_LAX) { ArrayList() }.add(name)
            }
        }
        if (a.duplicateSct) divergences.getOrPut(Divergence.DUPLICATE) { ArrayList() }.add(name)
        val actual =
            c.fields.scts
                .map { Oracle3a.hex(it.logId.toByteArray()) to it.timestamp }
                .toSet()
        assertEquals(expected, actual, "$name SCT pairs")
    }

    @Test
    fun `the 3a recording hook writes the corpus on request`() {
        Oracle3a.writeInputsIfRequested()
    }

    private companion object {
        val THREE_A_REJECTS: Set<String> =
            setOf(
                // JDK-tolerated trailing elements and unique-id forms x509-parser refuses.
                "variants/ext3-null-after-sequence",
                "variants/ext3-primitive-83",
                "variants/spki-then-null-then-uid",
                "variants/tbs-junk-after-extensions",
                "variants/tbs-null-after-extensions",
                "variants/tbs-null-before-extensions",
                "variants/tbs-two-ext3",
                "variants/uid-81-twice",
                "variants/uid-82-then-81",
                // Indefinite lengths, which x509-parser rejects everywhere.
                "unsigned/letsencrypt.org-1/tbs-indefinite",
                "unsigned/www.google.com-1/tbs-indefinite",
                "unsigned/www.mozilla.org-1/tbs-indefinite",
                "envelope/www.mozilla.org-1/alg-indefinite-null-indefinite",
                "envelope/letsencrypt.org-1/tbs-indefinite-serial-eoc-content",
                // Signature padding bits set, which x509-parser's DER BIT STRING refuses.
                "boundary/signature-padding-bits",
                "envelope/www.mozilla.org-1/sig-unused-bits-1-padding-set",
            ) +
                ProducerCorpus.envelopeLeaves.flatMap { (leaf, _) ->
                    listOf(
                        "tbs-indefinite-version",
                        "tbs-indefinite-validity",
                        "tbs-indefinite-subject-chain",
                        "tbs-indefinite-extension-chain",
                        "tbs-indefinite-definite-subject-indefinite-rdn",
                        "alg-indefinite",
                    ).map { "envelope/$leaf/$it" }
                }
    }
}
