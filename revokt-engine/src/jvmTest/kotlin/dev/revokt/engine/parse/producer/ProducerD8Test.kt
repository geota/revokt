// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import dev.revokt.KeyabilityClause
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString.Companion.toByteString
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The D8 replay of spec §9.2 (revision 35) on recorded oracle-4 goldens; the PR tier needs no Go. Regenerate the goldens
 * and the gap baseline with `native/producer-oracle/record-goldens.sh` when the corpus changes.
 */
class ProducerD8Test {
    private val goldens = ProducerCorpus.goldens()

    private val zlint = ProducerCorpus.zlint()

    /** One input's outcome; [certificate], [clause] and [golden] are null when the input does not parse. */
    private class Outcome(
        val input: ProducerCorpus.Input,
        val certificate: ParsedCertificate?,
        val clause: KeyabilityClause?,
        val golden: String?,
    )

    private val outcomes: List<Outcome> by lazy { ProducerCorpus.inputs.map { outcome(it) } }

    private val parsed: List<Outcome> by lazy { outcomes.filter { it.certificate != null } }

    private fun outcome(input: ProducerCorpus.Input): Outcome {
        val c =
            (CertificateParser.parse(input.der) as? CertificateParse.Parsed)?.certificate
                ?: return Outcome(input, null, null, null)
        val canon = assertNotNull(input.canon, "${input.name}: Parsed but canon cannot be located")
        val (tbs, octets) = canonParts(canon)
        // D2 against canon, which is built without revokt's parser: Cert.tbs is its first element, and Cert.sig its
        // signature octets with the presented unused-bits octet's low bits cleared.
        assertContentEquals(tbs, c.tbsBytes, "${input.name}: Cert.tbs")
        val presented = c.envelope.signatureValue
        val unused = if (presented.length > 0) input.der[presented.start].toInt() and 0xff else 0
        assertContentEquals(cleared(octets, unused), c.envelope.signature, "${input.name}: Cert.sig")
        val golden =
            goldens[input.canonSha256]
                ?: fail("${input.name}: no oracle-4 golden; run native/producer-oracle/record-goldens.sh")
        return Outcome(input, c, Keyability.firstFailing(c), golden)
    }

    /** canon's TBS TLV and its BIT STRING's octets after the (zero) unused-bits octet. */
    private fun canonParts(canon: ByteArray): Pair<ByteArray, ByteArray> {
        var p = header(canon, 0).first
        val tbsEnd = p + header(canon, p).let { it.first + it.second }
        val tbs = canon.copyOfRange(p, tbsEnd)
        p = tbsEnd + header(canon, tbsEnd).let { it.first + it.second }
        val (h, length) = header(canon, p)
        return tbs to canon.copyOfRange(p + h + 1, p + h + length)
    }

    /** A minimal header at [p]: its length in octets and the content length. */
    private fun header(
        b: ByteArray,
        p: Int,
    ): Pair<Int, Int> {
        val first = b[p + 1].toInt() and 0xff
        if (first < 0x80) return 2 to first
        val count = first and 0x7f
        return (2 + count) to (0 until count).fold(0) { acc, i -> (acc shl 8) or (b[p + 2 + i].toInt() and 0xff) }
    }

    private fun cleared(
        octets: ByteArray,
        unused: Int,
    ): ByteArray {
        if (octets.isEmpty()) return octets
        return octets.copyOf().also {
            it[it.lastIndex] =
                (it[it.lastIndex].toInt() and (0xff shl minOf(unused, 8))).toByte()
        }
    }

    @Test
    fun `every replay input parses except the strict variants, the malformed fuzz seeds and the envelope rejects`() {
        val failing = outcomes.filter { it.certificate == null }.map { it.input.name }.toSet()
        val expected =
            STRICT_VARIANTS.map { "variants/$it" }.toSet() + MALFORMED_FUZZ_SEEDS.map { "fuzz/$it" } +
                ProducerCorpus.envelopeRejects() + BoundaryCorpus.DIVERGENCE_REJECTS.map { "d3/$it" }
        assertEquals(expected, failing)
    }

    @Test
    fun `D8 - every input inside the profile is keyed by the producer's strict parse with revokt's bytes`() {
        val keyable = parsed.filter { it.clause == null }
        for (o in keyable) {
            val c = o.certificate!!
            val serial = c.rawSerial().toByteString().hex()
            val spki =
                c
                    .rawSpki()
                    .toByteString()
                    .sha256()
                    .hex()
            assertEquals("OK $serial $spki ct", o.golden, "D8: ${o.input.name}")
        }
        val distinct = keyable.mapNotNull { it.input.canonSha256 }.toSet().size
        assertTrue(distinct >= 25, "D8 exercised on only $distinct distinct canons")
    }

    @Test
    fun `the D8 gap is zero on the committed real end-entity certificates`() {
        val leaves =
            listOf(
                "github.com-1",
                "letsencrypt.org-1",
                "www.google.com-1",
                "www.mozilla.org-1",
                "mozilla-content-signing-c0",
            )
        for (leaf in leaves) {
            val o = outcomes.single { it.input.name == "certs/$leaf" }
            assertEquals(null, o.clause, "$leaf is inside the profile (producer: ${o.golden})")
            assertTrue(o.golden!!.endsWith(" ct"), "$leaf is keyed through ct")
        }
    }

    @Test
    fun `the boundary corpus's accept side is inside the profile and its reject side outside`() {
        for (o in outcomes.filter { it.input.name.startsWith("boundary/") }) {
            val reject =
                o.input.name
                    .substringAfter("boundary/")
                    .startsWith("reject-")
            assertTrue(o.certificate != null, "${o.input.name} parses")
            assertEquals(reject, o.clause != null, "${o.input.name}: clause ${o.clause}, producer ${o.golden}")
            // Reject side: the producer's exact outcome is pinned (zcrypto-only, lax-only, or a rejection).
            if (reject) {
                val name = o.input.name
                val expected =
                    when {
                        "key-usage" in name -> " zc"
                        "serial-non-minimal" in name || "printable-at" in name -> " lax"
                        else -> "REJECT"
                    }
                val golden = o.golden!!
                assertTrue(
                    if (expected ==
                        "REJECT"
                    ) {
                        golden.startsWith(expected)
                    } else {
                        golden.endsWith(expected)
                    },
                    "$name: expected $expected, producer $golden",
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
        val bases = outcomes.filter { it.input.base == null }.associateBy { it.input.name }
        var signed = 0
        var unsigned = 0
        for (m in outcomes.filter { it.input.base != null }) {
            val base = bases[m.input.base] ?: fail("no base outcome for ${m.input.base}")
            val label = "${m.input.name}: clause ${m.clause}, base ${base.clause}"
            if (signedPosition(m.input.path!!, base.certificate!!)) {
                signed++
                assertTrue(m.clause != null && (base.clause == null || m.clause < base.clause), label)
            } else {
                unsigned++
                assertEquals(base.clause, m.clause, label)
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
        val oid =
            base.tbs.extensions[opaque.groupValues[1].toInt()]
                .oid
                .bytes(base.tbsBytes)
        return K8_LISTED.any { it.contentEquals(oid) }
    }

    /**
     * The D8 gap (spec §9.2): end-entity inputs only (a CA certificate is never counted, since `producerKeyable` is a leaf
     * predicate), each carrying the producer's path, its first failing clause and the pinned zlint result (its error
     * lints, or `unparseable`/`panic` where zlint could not run). The replay fails on any entry, or any change of clause,
     * path or zlint result, not in the committed baseline (`producer/gap-baseline.tsv`). An entry with no zlint error,
     * read conservatively to include one zlint could not lint, is a profile defect that blocks the release until the
     * profile is widened or the entry justified: those entries are pinned.
     */
    @Test
    fun `the D8 gap equals the recorded baseline`() {
        val gap = parsed.filter { it.clause != null && it.golden!!.startsWith("OK ") && !isCa(it.certificate!!) }
        val lines =
            gap
                .map {
                    "${it.input.name}\t${it.clause}\t${it.golden!!.substringAfterLast(' ')}\t${zlintErrors(it)}"
                }.sorted()
        System.getProperty("revokt.writeGapBaseline")?.let { path ->
            File(path).writeText(BASELINE_HEADER + lines.joinToString("\n", postfix = "\n"))
            return
        }
        val baseline =
            String(ProducerCorpus.resource("producer/gap-baseline.tsv")).lines().filter {
                it.isNotBlank() &&
                    !it.startsWith("#")
            }
        assertEquals(
            emptySet(),
            (baseline - lines.toSet()).toSet(),
            "entries gone from the gap: re-record the baseline",
        )
        assertEquals(
            emptySet(),
            (lines - baseline.toSet()).toSet(),
            "new or changed gap entries: justify them and re-record",
        )
        val lintClean = gap.filter { zlintErrors(it) in setOf("-", "unparseable", "panic") }.map { it.input.name }
        assertEquals(LINT_CLEAN, lintClean.toSet(), "D8-gap entries with no zlint error (release blockers, spec §9.2)")
        val caFixtures =
            ProducerCorpus.fixtures.filter {
                isCa(
                    outcomes
                        .single { o ->
                            o.input.name == "certs/$it"
                        }.certificate!!,
                )
            }
        assertEquals(CA_FIXTURES, caFixtures.toSet(), "the CA fixtures are read as CAs")
        println(
            "D8 gap over the replay corpus (clause/path → inputs): ${gap.groupingBy {
                "${it.clause}/${it.golden!!.substringAfterLast(
                    ' ',
                )}"
            }.eachCount().toSortedMap()}",
        )
    }

    @Test
    fun `the zlint results name the zlint pin`() {
        val header = String(ProducerCorpus.resource("producer/zlint.tsv")).lineSequence().first()
        val goMod =
            File(
                checkNotNull(System.getProperty("revokt.zlintGoMod")) { "revokt.zlintGoMod not set" },
            ).readLines()
        val pin = goMod.single { it.trim().startsWith("github.com/zmap/zlint/v3 ") }.trim().split(' ')[1]
        assertEquals("# zlint pin: $pin", header.substringBefore(" (native"), "re-record zlint.tsv after a zlint bump")
    }

    /**
     * Whether basicConstraints marks [c] a CA, read from its extension value independently of the keyability profile. A
     * basicConstraints value that cannot be decoded reads as not a CA, so such a mutant of a CA would count as a leaf;
     * none in the corpus does (the gap's CA-derived entries carry no extensions at all).
     */
    private fun isCa(c: ParsedCertificate): Boolean {
        val value =
            c.tbs.extensions
                .firstOrNull { it.oidDotted == "2.5.29.19" }
                ?.value
                ?.bytes(c.tbsBytes)
        val first = value?.let { runCatching { DerNode.parse(it).children?.firstOrNull() }.getOrNull() }
        return first != null && first.tag == 0x01 && first.content.any { it != 0.toByte() }
    }

    /** The pinned zlint result of a gap entry: its error lints, `-` for none, or `unparseable`/`panic`. */
    private fun zlintErrors(o: Outcome): String {
        val line =
            zlint[o.input.canonSha256]
                ?: fail("${o.input.name}: no zlint result; run native/producer-oracle/record-goldens.sh")
        return if (line.startsWith("LINT ")) line.split(' ')[1] else line.substringBefore(' ').lowercase()
    }

    private companion object {
        /**
         * The D8-gap entries with no zlint error, each needing a written justification before a release (the corpus
         * records carry them): four inner-header mutants of a leaf's `extnValue` content keyed only through zcrypto, and
         * seven inputs zcrypto cannot parse for zlint.
         */
        val LINT_CLEAN: Set<String> =
            setOf(
                "boundary/reject-printable-at",
                "boundary/reject-serial-non-minimal",
                "envelope/letsencrypt.org-1/tbs-indefinite-serial-eoc-content",
            ) +
                listOf(
                    "github.com-1" to 3,
                    "letsencrypt.org-1" to 2,
                    "www.google.com-1" to 2,
                    "www.mozilla.org-1" to 2,
                ).map {
                    "mutant/certs/${it.first}/0:30/0:30/7:a3/0:30/${it.second}:30/2:04~/0:30"
                } +
                listOf("", "/0:30", "/0:30/0:06", "/0:30/1:16").map {
                    "mutant/certs/github.com-1/0:30/0:30/7:a3/0:30/5:30/1:04~/0:30/0:30/1:30$it"
                }

        /** The fixtures that are CA certificates: every chain's issuers, and Mozilla's content-signing root and intermediate. */
        val CA_FIXTURES: Set<String> =
            setOf(
                "github.com-2",
                "github.com-3",
                "letsencrypt.org-2",
                "letsencrypt.org-3",
                "letsencrypt.org-4",
                "www.google.com-2",
                "www.google.com-3",
                "www.mozilla.org-2",
                "www.mozilla.org-3",
                "mozilla-content-signing-c1",
                "mozilla-content-signing-c2",
            )

        /** The structural variants revokt rejects as `STRUCTURE` by rule (spec §9.2, the D7 list). */
        val STRICT_VARIANTS =
            listOf(
                "cert-null-after-signature",
                "extension-null-between-oid-and-value",
                "extensions-seq-with-null-element",
                "tbs-junk-before-extensions",
                "validity-null-after-times",
                "version-wrapper-trailing",
            )

        /** The fuzz seeds that are malformed by design (empty, over-long length, indefinite serial, cut short). */
        val MALFORMED_FUZZ_SEEDS = listOf("empty", "huge-length", "indefinite", "trailing-byte", "truncated-leaf")

        const val BASELINE_HEADER =
            "# The D8 gap of the replay corpus (spec §9.2): input <TAB> first failing clause <TAB> oracle-4 path\n" +
                "# <TAB> zlint errors (- for none).\n" +
                "# Regenerate with native/producer-oracle/record-goldens.sh; a new entry needs a justification in its PR.\n"

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
