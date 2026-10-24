// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.KeyabilityClause
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The D8 replay of spec §9.2 (revision 35) on recorded oracle-4 goldens; the PR tier needs no Go. Regenerate the goldens
 * with `native/producer-oracle/record-goldens.sh` when the corpus changes.
 */
class ProducerD8Test {
    private val goldens = ProducerCorpus.goldens()

    private class Outcome(
        val input: ProducerCorpus.Input,
        val certificate: ParsedCertificate,
        val clause: KeyabilityClause?,
        val golden: String,
    )

    private val outcomes: List<Outcome> by lazy {
        ProducerCorpus.inputs.mapNotNull { input ->
            val parse = CertificateParser.parse(input.der) as? CertificateParse.Parsed ?: return@mapNotNull null
            val canon = assertNotNull(input.canon, "${input.name}: Parsed but canon cannot be located")
            // D2's first element: Cert.tbs is canon's TBS (canon is built without revokt's parser).
            assertContentEquals(
                canon.copyOfRange(
                    headerLength(canon),
                    headerLength(canon) + parse.certificate.tbsBytes.size,
                ),
                parse.certificate.tbsBytes,
                input.name,
            )
            val golden =
                goldens[input.canonSha256]
                    ?: fail("${input.name}: no oracle-4 golden; run native/producer-oracle/record-goldens.sh")
            Outcome(input, parse.certificate, Keyability.firstFailing(parse.certificate), golden)
        }
    }

    private fun headerLength(tlv: ByteArray): Int =
        if (tlv[1].toInt() and 0x80 ==
            0
        ) {
            2
        } else {
            2 + (tlv[1].toInt() and 0x7f)
        }

    @Test
    fun `D8 - every input inside the profile is keyed by the producer's strict parse with revokt's bytes`() {
        val keyable = outcomes.filter { it.clause == null }
        for (o in keyable) {
            val serial =
                o.certificate
                    .rawSerial()
                    .toByteString()
                    .hex()
            val spki =
                o.certificate
                    .rawSpki()
                    .toByteString()
                    .sha256()
                    .hex()
            assertEquals("OK $serial $spki ct", o.golden, "D8: ${o.input.name}")
        }
        assertTrue(keyable.size >= 30, "D8 exercised on only ${keyable.size} inputs")
    }

    @Test
    fun `the boundary corpus's accept side is inside the profile and its reject side outside`() {
        for (o in outcomes.filter { it.input.name.startsWith("boundary/") }) {
            val reject =
                o.input.name
                    .substringAfter("boundary/")
                    .startsWith("reject-")
            assertEquals(reject, o.clause != null, "${o.input.name}: clause ${o.clause}, producer ${o.golden}")
            if (reject) {
                assertTrue(
                    o.golden.startsWith("REJECT"),
                    "${o.input.name}: the producer rejects it (${o.golden})",
                )
            }
        }
    }

    /**
     * The mutation set (#11): one non-minimal length per header. A header in the signed TBS outside the opaque values
     * puts the leaf outside the profile at an earlier clause than its base's; one in the envelope or inside an opaque
     * extension value leaves the clause unchanged.
     */
    @Test
    fun `a non-minimal length moves the leaf out of the profile exactly where the producer reads it`() {
        val bases = outcomes.filter { it.input.base == null }.associateBy { it.input.name.substringAfterLast('/') }
        val byBase = outcomes.filter { it.input.base != null }.groupBy { it.input.base!! }
        var signed = 0
        var unsigned = 0
        for ((baseName, mutants) in byBase) {
            val base = bases[baseName.substringAfterLast('/')] ?: fail("no base outcome for $baseName")
            for (m in mutants) {
                val label = "${m.input.name}: clause ${m.clause}, base ${base.clause}"
                if (signedPosition(m.input.path!!, base.certificate)) {
                    signed++
                    assertTrue(m.clause != null && (base.clause == null || m.clause < base.clause), label)
                } else {
                    unsigned++
                    assertEquals(base.clause, m.clause, label)
                }
            }
        }
        assertTrue(signed > 1000 && unsigned > 100, "mutation set too small: $signed signed, $unsigned unsigned")
    }

    /** True for a header inside the TBS content and outside the content of every opaque extension value. */
    private fun signedPosition(
        path: String,
        base: ParsedCertificate,
    ): Boolean {
        if (!path.startsWith("/0:30/0:30/")) return false
        val opaque = Regex("^/0:30/0:30/\\d+:a3/0:30/(\\d+):30/\\d+:04~/").find(path) ?: return true
        val extension = base.tbs.extensions[opaque.groupValues[1].toInt()]
        return K8_LISTED.any { Oid.matches(base.tbsBytes, extension.oid, it) }
    }

    @Test
    fun `every gap input carries the producer's path and its first failing clause`() {
        val gap = outcomes.filter { it.clause != null && it.golden.startsWith("OK ") }
        for (o in gap) assertTrue(o.golden.substringAfterLast(' ') in setOf("ct", "lax", "zc"), o.input.name)
        val byClass = gap.groupBy { "${it.clause}/${it.golden.substringAfterLast(' ')}" }.toSortedMap()
        println("D8 gap over the replay corpus (clause/path → inputs): ${byClass.mapValues { it.value.size }}")
        for ((key, members) in byClass) println("  $key, e.g. ${members.take(4).joinToString { it.input.name }}")
    }

    private companion object {
        /** K8's list as spec §9.2 names it, written independently of `Keyability` (canonical OID content). */
        val K8_LISTED: List<ByteArray> =
            listOf(
                "551d0f",
                "551d13",
                "551d11",
                "551d1f",
                "551d23",
                "551d25",
                "551d0e",
                "551d20",
                "2b06010505070101",
                "551d1e",
                "2b0601050507010b",
            ).map { hex -> ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() } }
    }
}
