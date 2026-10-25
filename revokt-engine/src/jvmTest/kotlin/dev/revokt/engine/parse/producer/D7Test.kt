// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.Keyability
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** The D7 leniency corpus of spec §9.2 ([D7Corpus]): every case has inputs in the replay, and the required outcomes hold. */
class D7Test {
    private val byName = ProducerCorpus.inputs.associateBy { it.name }

    @Test
    fun `every D7 case's inputs are replay inputs and every built input carries a case`() {
        val missing = D7Corpus.byInput.keys.filter { it !in byName }
        assertEquals(emptyList(), missing, "D7 inputs the replay does not hold (renamed, or bytes another input has)")
        val unused = D7Corpus.inputs().map { it.first }.filter { it !in D7Corpus.byInput }
        assertEquals(emptyList(), unused, "built D7 inputs no case names")
        assertTrue(D7Corpus.cases.all { it.inputs.isNotEmpty() })
    }

    @Test
    fun `revokt's outcome on each D7 input is the one the spec requires`() {
        val wrong = ArrayList<String>()
        for (case in D7Corpus.cases) {
            val required = case.required ?: continue
            for (name in case.inputs) wrong += check(name, required)
        }
        assertEquals(emptyList(), wrong)
    }

    private fun check(
        name: String,
        required: D7Corpus.Required,
    ): List<String> {
        val parse = CertificateParser.parse(byName.getValue(name).der)
        val out = ArrayList<String>()
        if (required.reason != null) {
            val reason = (parse as? CertificateParse.Failed)?.reason?.name ?: "Parsed"
            if (reason != required.reason) out += "$name: $reason, required ${required.reason}"
            return out
        }
        val c = (parse as? CertificateParse.Parsed)?.certificate ?: return listOf("$name: $parse, required Parsed")
        required.scts?.let { n -> if (c.fields.scts.size != n) out += "$name: ${c.fields.scts.size} SCTs, required $n" }
        required.keyable?.let { k ->
            if ((Keyability.firstFailing(c) == null) != k) out += "$name: producerKeyable ${!k}, required $k"
        }
        if (required.sameAsBase) {
            val leaf = name.split('/')[1]
            val base =
                (CertificateParser.parse(ProducerCorpus.resource("certs/$leaf.der")) as? CertificateParse.Parsed)
                    ?.certificate ?: fail("$leaf does not parse")
            assertContentEquals(base.rawSerial(), c.rawSerial(), "$name: serial")
            assertContentEquals(base.rawSpki(), c.rawSpki(), "$name: SPKI")
            if (Keyability.firstFailing(base) !=
                Keyability.firstFailing(c)
            ) {
                out += "$name: keyability differs from $leaf"
            }
        }
        return out
    }
}
