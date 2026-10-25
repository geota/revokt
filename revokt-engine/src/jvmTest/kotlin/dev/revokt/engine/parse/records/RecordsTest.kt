// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.oracle.Oracle1
import dev.revokt.engine.parse.oracle.Oracle3a
import dev.revokt.engine.parse.oracle.Oracle3b
import dev.revokt.engine.parse.oracle.OracleReplay
import dev.revokt.engine.parse.oracle.ReferenceView
import dev.revokt.engine.parse.producer.ProducerCorpus
import dev.revokt.engine.parse.records.CorpusRecord.RecordClass
import java.io.File
import java.time.LocalDate
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The corpus records of spec §9.2 against the replay on the test JDK: every input the replay classes as D1-dom, as an
 * SPKI the JDK re-encodes (D2's allow-list), as a D3 divergence or as a D8-gap entry has its committed record, with the
 * same fields and a written justification, and no record is stale. D1_DOM and D2_REENCODE_ALLOW depend on oracle 1, so
 * those records count on a JDK only when their oracle-1 entry for it accepts; the other classes do not.
 *
 * Regenerate with `native/producer-oracle/record-goldens.sh`, which runs the writer hook once per matrix JDK; it keeps
 * every justification and `added` date already written, and a new record needing a written justification gets none.
 */
class RecordsTest {
    private val version = Runtime.version().feature().toString()

    @Test
    fun `the committed records equal the replay's classes on this JDK`() {
        val computed = computed().associateBy { it.key }
        val committed = CorpusRecord.committed()
        assertEquals(committed.size, committed.map { it.key }.toSet().size, "one record per input and class")
        val here = committed.filter { counts(it) }.associateBy { it.key }
        assertEquals(emptySet(), here.keys - computed.keys, "stale records on JDK $version: regenerate them")
        assertEquals(emptySet(), computed.keys - here.keys, "unrecorded entries on JDK $version: record them")
        for ((key, record) in here) assertEquals(fields(computed.getValue(key)), fields(record), record.path)
        val unjustified = committed.filter { it.justification.isBlank() }.map { "${it.path} ${it.recordClass}" }
        assertEquals(emptyList(), unjustified, "records without a written justification")
    }

    @Test
    fun `the records writer merges this JDK's view when requested`() {
        val path = System.getProperty("revokt.writeRecords") ?: return
        val file = File(path)
        val existing = if (file.exists()) file.readLines().filter { it.isNotBlank() }.map { CorpusRecord.fromJson(Json.parse(it) as Json.Obj) } else emptyList()
        CorpusRecord.write(file, merge(existing, computed()))
    }

    /** Whether [r] counts on this JDK: oracle-dependent classes only where its oracle-1 entry for this JDK accepts. */
    private fun counts(r: CorpusRecord): Boolean = r.recordClass !in JDK_DEPENDENT || r.acceptedOn(version)

    /** The record's fields that the replay decides: everything but the justification, the date and other JDKs' entries. */
    private fun fields(r: CorpusRecord): String {
        val own = r.oracles.filter { it.id != "1" || it.version == version }
        return CorpusRecord(r.sha256, r.path, r.revokt, own, r.recordClass, r.divergence, r.keyability, "", "").toJson().write()
    }

    /**
     * [existing] with this JDK's view merged in: this JDK's oracle-1 entry replaced on every record, a JDK-dependent record
     * dropped once no JDK counts it, and every justification and date already written kept.
     */
    private fun merge(
        existing: List<CorpusRecord>,
        computed: List<CorpusRecord>,
    ): List<CorpusRecord> {
        val byKey = computed.associateBy { it.key }
        val out = LinkedHashMap<Pair<String, RecordClass>, CorpusRecord>()
        for (e in existing) {
            val c = byKey[e.key]
            val others = e.oracles.filter { it.id == "1" && it.version != version }
            if (c == null) {
                if (e.recordClass in JDK_DEPENDENT && others.any { it.outcome == "Accept" }) out[e.key] = with(e, others + e.oracles.filter { it.id != "1" })
                continue
            }
            val justification = e.justification.ifBlank { c.justification }
            out[e.key] = CorpusRecord(c.sha256, c.path, c.revokt, sortOracles(others + c.oracles), c.recordClass, c.divergence, c.keyability, justification, e.added)
        }
        for (c in computed) if (c.key !in out) out[c.key] = c
        return out.values.toList()
    }

    private fun with(
        e: CorpusRecord,
        oracles: List<CorpusRecord.Oracle>,
    ) = CorpusRecord(e.sha256, e.path, e.revokt, sortOracles(oracles), e.recordClass, e.divergence, e.keyability, e.justification, e.added)

    private fun sortOracles(oracles: List<CorpusRecord.Oracle>) = oracles.sortedWith(compareBy({ ORACLE_ORDER.indexOf(it.id) }, { it.version.padStart(3, '0') }))

    /** The records the replay classes on this JDK, with rule-based justifications where the rule is the justification. */
    private fun computed(): List<CorpusRecord> {
        val inputs = ProducerCorpus.inputs.associateBy { it.name }
        val out = ArrayList<CorpusRecord>()
        for (a in OracleReplay.accepted) {
            val reason = OracleReplay.outsideDomain(a) ?: continue
            out += record(inputs.getValue(a.name), RecordClass.D1_DOM, null, null, d1Justification(a, reason))
        }
        for (name in OracleReplay.spkiReencoded) out += record(inputs.getValue(name), RecordClass.D2_REENCODE_ALLOW, null, null, REENCODE)
        for (input in ProducerCorpus.inputs) {
            val c = (CertificateParser.parse(input.der) as? CertificateParse.Parsed)?.certificate ?: continue
            for (d in ReferenceView.of(OracleReplay.sha(input.der))?.divergences.orEmpty()) {
                out += record(input, RecordClass.D3_DIVERGENCE, d, null, DIVERGENCE.getValue(d))
            }
            val clause = Keyability.firstFailing(c) ?: continue
            val golden = OracleReplay.producer[input.canonSha256] ?: continue
            if (!golden.startsWith("OK ")) continue
            val k = CorpusRecord.Keyability(golden.substringAfterLast(' '), clause.name, zlintErrors(input))
            out += record(input, RecordClass.KEYABILITY_GAP, null, k, gapJustification(k))
        }
        return out
    }

    private fun record(
        input: ProducerCorpus.Input,
        recordClass: RecordClass,
        divergence: String?,
        keyability: CorpusRecord.Keyability?,
        justification: String,
    ): CorpusRecord {
        val sha = OracleReplay.sha(input.der)
        val revokt =
            when (val p = CertificateParser.parse(input.der)) {
                is CertificateParse.Failed -> CorpusRecord.Revokt(p.reason.name, null, null, emptyList())
                is CertificateParse.Parsed ->
                    p.certificate.let { c ->
                        CorpusRecord.Revokt(
                            "Parsed",
                            Oracle3a.hex(c.rawSerial()),
                            OracleReplay.sha(c.rawSpki()),
                            c.fields.scts.map { "${Oracle3a.hex(it.logId.toByteArray())}@${it.timestamp}" }.sorted(),
                        )
                    }
            }
        val a = OracleReplay.accepted.firstOrNull { it.name == input.name }
        val one =
            CorpusRecord.Oracle(
                "1",
                version,
                if (a != null) "Accept" else "Reject",
                a?.read?.der?.let(OracleReplay::sha)?.takeIf { it != sha },
            )
        val oracles =
            listOf(
                one,
                CorpusRecord.Oracle("3a", X509_PARSER, Oracle3a.reply(sha)!!.substringBefore('\t')),
                CorpusRecord.Oracle("3b", LOCATOR, Oracle3b.reply(sha)!!.substringBefore('\t')),
                CorpusRecord.Oracle("4", PRODUCER, input.canonSha256?.let { OracleReplay.producer[it] } ?: "no canon"),
            )
        return CorpusRecord(sha, input.name, revokt, oracles, recordClass, divergence, keyability, justification, today)
    }

    private fun d1Justification(
        a: OracleReplay.Accepted,
        reason: String,
    ): String =
        when (reason) {
            OracleReplay.PRODUCER_REJECTS -> "Oracle 4 rejects canon of the bytes read (${OracleReplay.producerGolden(a).removePrefix("REJECT ")}): no filter can contain it, so it is never queried (§9.2 D1-dom)."
            OracleReplay.PRODUCER_KEYS_OTHER_BYTES -> "Oracle 4 keys bytes other than the reference view's: no filter holds this certificate's key (§9.2 D1-dom)."
            OracleReplay.VERSION_TRAILING -> "Content after the INTEGER inside [0]: D1-dom by rule, the [0] flattening of §9.2."
            OracleReplay.NO_PLATFORM_CANON -> "No platform canon can be built: D1-dom by rule (§9.2, revision 39)."
            else -> fail("${a.name}: unknown D1-dom reason $reason")
        }

    /** The rule-based justification of a D8-gap entry with zlint errors; a lint-clean entry needs one written by hand. */
    private fun gapJustification(k: CorpusRecord.Keyability): String =
        when (k.zlint) {
            "-" -> ""
            "unparseable" -> "Outside the keyability profile at ${k.clause}, keyed through ${k.parser}; zcrypto cannot parse it for zlint, so it is not CA/B-conformant (§9.2 D8 gap)."
            else -> "Outside the keyability profile at ${k.clause}, keyed through ${k.parser}; zlint reports ${k.zlint.split(',').size} errors, so it is not CA/B-conformant (§9.2 D8 gap)."
        }

    private fun zlintErrors(input: ProducerCorpus.Input): String {
        val line = zlint[input.canonSha256] ?: fail("${input.name}: no zlint result; run native/producer-oracle/record-goldens.sh")
        return if (line.startsWith("LINT ")) line.split(' ')[1] else line.substringBefore(' ').lowercase()
    }

    private val zlint by lazy { ProducerCorpus.zlint() }

    private val today = LocalDate.now(ZoneOffset.UTC).toString()

    private companion object {
        val JDK_DEPENDENT = setOf(RecordClass.D1_DOM, RecordClass.D2_REENCODE_ALLOW)

        val ORACLE_ORDER = listOf("1", "2", "3a", "3b", "3c", "4")

        /** The oracle pins (spec §9.2, Appendix A): 3a in native/revokt-oracle/Cargo.toml, 4 in native/producer-oracle/go.mod. */
        const val X509_PARSER = "x509-parser 0.18.1"

        const val LOCATOR = "revokt-oracle locate"

        const val PRODUCER = "mozilla/crlite go 008299826177"

        const val REENCODE = "The JDK re-encodes this SPKI's non-minimal headers in getPublicKey().getEncoded(), and keeps the key; allowed by the §9.2 re-encoding rule."

        val DIVERGENCE =
            mapOf(
                "3A_HEADER_LAX" to "x509-parser yields pairs under an inner identifier other than 0x04 (tag number 4 in another class or form); §9.2 fails the list, as Firefox and webpki do (3A_HEADER_LAX).",
                "3A_TBS_LAX" to "x509-parser takes an element with tag number 3 that is not a constructed context-specific [3] as extensions; the JDK and revokt ignore it (3A_TBS_LAX).",
                "DUPLICATE_EXTENSION" to "x509-parser reports a duplicate SCT-list extension as an error; revokt takes the union of the extensions' pairs (§9.2 D3).",
            )
    }
}
