// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.ParsedCertificate
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
import kotlin.test.assertFalse
import kotlin.test.fail

/**
 * The corpus records of spec §9.2 against the replay on the test JDK: every input the replay classes as D1-dom, as an
 * SPKI the JDK re-encodes (D2's allow-list), as a D3 divergence or as a D8-gap entry has its committed record, with the
 * same fields, and no record is stale. A rule-based justification (the producer's error, the D1-dom rule, the class's
 * reason, the zlint errors) is compared too, so a changed reason fails; a record whose rule yields none (a D8-gap entry
 * with no zlint error, a release blocker) needs one written by hand. Every record of a D8-gap input carries
 * `keyability`, and a `KEYABILITY_GAP` record exists only for an input with no other class.
 *
 * D1_DOM, D2_REENCODE_ALLOW and KEYABILITY_GAP depend on oracle 1: each record has an oracle-1 entry per matrix JDK, and
 * counts on a JDK where that entry `holds`. Regenerate with `native/producer-oracle/record-goldens.sh`, which runs the
 * writer hook once per matrix JDK; it keeps every hand-written justification and `added` date.
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
        for ((key, record) in here) {
            val c = computed.getValue(key)
            val rule = c.justification.isNotBlank()
            assertEquals(fields(c, rule), fields(record, rule), record.path)
            // Where the rule yields none (a release blocker), the justification must be written by hand, not a stale rule.
            if (!rule) assertFalse(GAP_RULE in record.justification, "${record.path}: a stale rule-based justification")
        }
        val unjustified = committed.filter { it.justification.isBlank() }.map { "${it.path} ${it.recordClass}" }
        assertEquals(emptyList(), unjustified, "records without a written justification")
        val gapInputs = committed.filter { it.keyability != null }.map { it.sha256 }.toSet()
        val bare =
            committed
                .filter {
                    it.sha256 in gapInputs && it.keyability == null
                }.map { "${it.path} ${it.recordClass}" }
        assertEquals(emptyList(), bare, "records of a D8-gap input without keyability")
        val gapAlongside =
            committed
                .filter { it.recordClass == RecordClass.KEYABILITY_GAP }
                .filter { g -> committed.any { it.sha256 == g.sha256 && it.recordClass != RecordClass.KEYABILITY_GAP } }
        assertEquals(emptyList(), gapAlongside.map { it.path }, "KEYABILITY_GAP records of inputs admitted otherwise")
        val gap = computed.values.mapNotNull { it.keyability?.let { k -> "${k.clause}/${k.parser}" } }
        println("D8 gap on JDK $version (clause/path → inputs): ${gap.groupingBy { it }.eachCount().toSortedMap()}")
    }

    @Test
    fun `the records writer merges this JDK's view when requested`() {
        val path = System.getProperty("revokt.writeRecords") ?: return
        val file = File(path)
        val existing =
            if (file.exists()) {
                file.readLines().filter { it.isNotBlank() }.map { CorpusRecord.fromJson(Json.parse(it) as Json.Obj) }
            } else {
                emptyList()
            }
        CorpusRecord.write(file, merge(existing, computed()))
    }

    /** Whether [r] counts on this JDK: an oracle-dependent class only where its oracle-1 entry for this JDK holds. */
    private fun counts(r: CorpusRecord): Boolean =
        r.recordClass !in JDK_DEPENDENT || r.oracles.any { it.id == "1" && it.version == version && it.holds == true }

    /**
     * The record's fields that the replay decides: everything but the date and other JDKs' oracle-1 entries, and the
     * justification only when [withJustification] (the replay's own justification is rule-based).
     */
    private fun fields(
        r: CorpusRecord,
        withJustification: Boolean,
    ): String {
        val own = r.oracles.filter { it.id != "1" || it.version == version }
        val justification = if (withJustification) r.justification else ""
        return r.copy(oracles = own, justification = justification, added = "").toJson().write()
    }

    /**
     * [existing] with this JDK's view merged in. Every record's oracle-1 entry for this JDK is replaced: a computed record
     * takes the computed one; a JDK-dependent record not computed here records this JDK's outcome with `holds` false,
     * and is dropped once no JDK holds it; any other record not computed here is stale and dropped. A rule-based
     * justification replaces the one written; a hand-written one is kept only where the rule yields none.
     */
    private fun merge(
        existing: List<CorpusRecord>,
        computed: List<CorpusRecord>,
    ): List<CorpusRecord> {
        val byKey = computed.associateBy { it.key }
        val out = LinkedHashMap<Pair<String, RecordClass>, CorpusRecord>()
        for (e in existing) {
            val others = e.oracles.filter { it.id == "1" && it.version != version }
            val c = byKey[e.key]
            if (c != null) {
                out[e.key] =
                    c.copy(
                        oracles = sortOracles(others + c.oracles),
                        justification = c.justification.ifBlank { e.justification },
                        added = e.added,
                    )
            } else if (e.recordClass in JDK_DEPENDENT) {
                val accepted = acceptedByName.containsKey(e.path)
                val here = CorpusRecord.Oracle("1", version, if (accepted) "Accept" else "Reject", holds = false)
                val oracles = sortOracles(others + here + e.oracles.filter { it.id != "1" })
                if (oracles.any { it.holds == true }) out[e.key] = e.copy(oracles = oracles)
            }
        }
        for (c in computed) if (c.key !in out) out[c.key] = c
        return out.values.toList()
    }

    private fun sortOracles(oracles: List<CorpusRecord.Oracle>) =
        oracles.sortedWith(compareBy({ ORACLE_ORDER.indexOf(it.id) }, { it.version.padStart(3, '0') }))

    private val acceptedByName: Map<String, OracleReplay.Accepted> by lazy {
        OracleReplay.accepted.associateBy { it.name }
    }

    /**
     * The records the replay classes on this JDK. A D8-gap input's keyability rides on each of its records, with the gap
     * justification appended; it gets a `KEYABILITY_GAP` record of its own only when it has no other class.
     */
    private fun computed(): List<CorpusRecord> {
        val inputs = ProducerCorpus.inputs.associateBy { it.name }
        val classed = classed(inputs)
        val gap = OracleReplay.accepted.mapNotNull { a -> gap(a)?.let { a.name to it } }.toMap()
        val out =
            classed.map {
                record(
                    it.input,
                    it.recordClass,
                    it.divergence,
                    gap[it.input.name],
                    withGap(it.reason, gap[it.input.name]),
                )
            }
        val otherwise = classed.map { it.input.name }.toSet()
        val gapOnly = gap.filterKeys { it !in otherwise }
        return out +
            gapOnly.map { (name, k) ->
                record(inputs.getValue(name), RecordClass.KEYABILITY_GAP, null, k, gapJustification(k))
            }
    }

    /** [reason] with [k]'s gap justification appended; none when the gap's rule yields none (a hand-written one is due). */
    private fun withGap(
        reason: String,
        k: CorpusRecord.Keyability?,
    ): String {
        val gap = k?.let(::gapJustification) ?: return reason
        return if (gap.isEmpty()) "" else "$reason $gap"
    }

    /** One class the replay assigns an input, with its divergence and its rule-based reason. */
    private class Classed(
        val input: ProducerCorpus.Input,
        val recordClass: RecordClass,
        val divergence: String?,
        val reason: String,
    )

    /** The D1_DOM, D2_REENCODE_ALLOW and D3_DIVERGENCE classes on this JDK. */
    private fun classed(inputs: Map<String, ProducerCorpus.Input>): List<Classed> {
        val classed = ArrayList<Classed>()
        for (a in OracleReplay.accepted) {
            val reason = OracleReplay.outsideDomain(a) ?: continue
            classed += Classed(inputs.getValue(a.name), RecordClass.D1_DOM, null, d1Justification(a, reason))
        }
        for (name in OracleReplay.spkiReencoded) {
            classed += Classed(inputs.getValue(name), RecordClass.D2_REENCODE_ALLOW, null, REENCODE)
        }
        for (input in ProducerCorpus.inputs) {
            if (CertificateParser.parse(input.der) !is CertificateParse.Parsed) continue
            for (d in ReferenceView.of(OracleReplay.sha(input.der))?.divergences.orEmpty()) {
                classed += Classed(input, RecordClass.D3_DIVERGENCE, d, DIVERGENCE.getValue(d))
            }
        }
        return classed
    }

    /**
     * The D8-gap fields of a platform-accepted input in the D1 domain whose read parses outside the profile: end-entity
     * inputs only, since `producerKeyable` is a leaf predicate (spec §9.2); null otherwise.
     */
    private fun gap(a: OracleReplay.Accepted): CorpusRecord.Keyability? {
        val c = a.certificate ?: return null
        val clause = Keyability.firstFailing(c)?.takeUnless { isCa(c) || OracleReplay.outsideDomain(a) != null }
        return clause?.let {
            val golden = OracleReplay.producerGolden(a)
            CorpusRecord.Keyability(golden.substringAfterLast(' '), it.name, zlintResult(a.readInput))
        }
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
                is CertificateParse.Failed -> {
                    CorpusRecord.Revokt(p.reason.name, null, null, emptyList())
                }

                is CertificateParse.Parsed -> {
                    val c = p.certificate
                    val scts = c.fields.scts.map { "${Oracle3a.hex(it.logId.toByteArray())}@${it.timestamp}" }
                    CorpusRecord.Revokt(
                        "Parsed",
                        Oracle3a.hex(c.rawSerial()),
                        OracleReplay.sha(c.rawSpki()),
                        scts.sorted(),
                    )
                }
            }
        val a = acceptedByName[input.name]
        val read =
            a
                ?.read
                ?.der
                ?.let(OracleReplay::sha)
                ?.takeIf { it != sha }
        val holds = if (recordClass in JDK_DEPENDENT) true else null
        val missing = "no golden for ${input.name}; run native/revokt-oracle/record-goldens.sh"
        val oracles =
            listOf(
                CorpusRecord.Oracle("1", version, if (a != null) "Accept" else "Reject", read, holds),
                CorpusRecord.Oracle(
                    "3a",
                    X509_PARSER,
                    checkNotNull(Oracle3a.reply(sha)) { missing }.substringBefore('\t'),
                ),
                CorpusRecord.Oracle("3b", LOCATOR, checkNotNull(Oracle3b.reply(sha)) { missing }.substringBefore('\t')),
                CorpusRecord.Oracle("4", PRODUCER, producerOutcome(input, a)),
            )
        return CorpusRecord(sha, input.name, revokt, oracles, recordClass, divergence, keyability, justification, today)
    }

    /** Oracle 4's golden for canon of the input, else for canon of the bytes read (marked `read:`), else `no canon`. */
    private fun producerOutcome(
        input: ProducerCorpus.Input,
        a: OracleReplay.Accepted?,
    ): String {
        input.canonSha256?.let { sha -> OracleReplay.producer[sha]?.let { return it } }
        val read = a?.read?.canonSha256?.let { OracleReplay.producer[it] }
        return read?.let { "read: $it" } ?: "no canon"
    }

    private fun d1Justification(
        a: OracleReplay.Accepted,
        reason: String,
    ): String =
        when (reason) {
            OracleReplay.PRODUCER_REJECTS -> {
                val error = OracleReplay.producerGolden(a).removePrefix("REJECT ")
                "Oracle 4 rejects canon of the bytes read ($error): no filter can contain it, so it is never queried " +
                    "(§9.2 D1-dom)."
            }

            OracleReplay.PRODUCER_KEYS_OTHER_BYTES -> {
                "Oracle 4 keys bytes other than the reference view's: no filter holds this certificate's key " +
                    "(§9.2 D1-dom)."
            }

            OracleReplay.VERSION_TRAILING -> {
                "Content after the INTEGER inside [0]: D1-dom by rule, the [0] flattening of §9.2."
            }

            OracleReplay.NO_PLATFORM_CANON -> {
                "No platform canon can be built: D1-dom by rule (§9.2, revision 39)."
            }

            else -> {
                fail("${a.name}: unknown D1-dom reason $reason")
            }
        }

    /**
     * The rule-based justification of a D8-gap entry with zlint errors. An entry with no zlint error, read conservatively
     * to include one zlint could not lint (`unparseable`, `panic`), is a profile defect that blocks the release: the rule
     * yields none, so it needs a justification written by hand (spec §9.2).
     */
    private fun gapJustification(k: CorpusRecord.Keyability): String {
        val errors = k.zlint.substringBefore(' ')
        if (errors in setOf("-", "unparseable", "panic")) return ""
        return "Outside the keyability profile at ${k.clause}, keyed through ${k.parser}; zlint reports " +
            "${errors.split(',').size} $GAP_RULE"
    }

    @Test
    fun `the D8 gap's CA test reads the CA fixtures as CAs and the leaves as end entities`() {
        val read =
            ProducerCorpus.fixtures.associateWith {
                val p = CertificateParser.parse(ProducerCorpus.resource("certs/$it.der")) as CertificateParse.Parsed
                isCa(p.certificate)
            }
        assertEquals(CA_FIXTURES, read.filterValues { it }.keys, "CA fixtures")
    }

    /**
     * Whether basicConstraints marks [c] a CA, read from its extension value independently of the keyability profile. A
     * value that cannot be decoded reads as not a CA.
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

    /**
     * The pinned zlint result of canon of [read]: `<errors> <fatals>` (each comma-joined, `-` for none), or `unparseable`
     * or `panic` where zlint could not run.
     */
    private fun zlintResult(read: ProducerCorpus.Input): String {
        val line =
            zlint[read.canonSha256]
                ?: fail("${read.name}: no zlint result; run native/producer-oracle/record-goldens.sh")
        return if (line.startsWith("LINT ")) {
            line.split(' ').let {
                "${it[1]} ${it[2]}"
            }
        } else {
            line.substringBefore(' ').lowercase()
        }
    }

    private val zlint by lazy { ProducerCorpus.zlint() }

    private val today = LocalDate.now(ZoneOffset.UTC).toString()

    private companion object {
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

        /** The tail of the D8-gap rule's justification, which a hand-written one never repeats. */
        const val GAP_RULE = "errors, so it is not CA/B-conformant (§9.2 D8 gap)."

        val JDK_DEPENDENT = setOf(RecordClass.D1_DOM, RecordClass.D2_REENCODE_ALLOW, RecordClass.KEYABILITY_GAP)

        val ORACLE_ORDER = listOf("1", "2", "3a", "3b", "3c", "4")

        /** The oracle pins (spec §9.2, Appendix A): 3a in native/revokt-oracle/Cargo.toml, 4 in native/producer-oracle/go.mod. */
        const val X509_PARSER = "x509-parser 0.18.1"

        const val LOCATOR = "revokt-oracle locate"

        const val PRODUCER = "mozilla/crlite go 008299826177"

        const val REENCODE =
            "The JDK re-encodes this SPKI's non-minimal headers in getPublicKey().getEncoded(), and keeps the key; " +
                "allowed by the §9.2 re-encoding rule."

        val DIVERGENCE =
            mapOf(
                "3A_HEADER_LAX" to
                    "x509-parser yields pairs under an inner identifier other than 0x04 (tag number 4 in another " +
                    "class or form); §9.2 fails the list, as Firefox and webpki do (3A_HEADER_LAX).",
                "3A_TBS_LAX" to
                    "x509-parser takes an element with tag number 3 that is not a constructed context-specific [3] " +
                    "as extensions; the JDK and revokt ignore it (3A_TBS_LAX).",
                "DUPLICATE_EXTENSION" to
                    "x509-parser reports a duplicate SCT-list extension as an error; revokt takes the union of the " +
                    "extensions' pairs (§9.2 D3).",
            )
    }
}
