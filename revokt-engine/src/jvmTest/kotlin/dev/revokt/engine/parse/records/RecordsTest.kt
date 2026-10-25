// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.records

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.oracle.Oracle1
import dev.revokt.engine.parse.oracle.Oracle2
import dev.revokt.engine.parse.oracle.Oracle3a
import dev.revokt.engine.parse.oracle.Oracle3b
import dev.revokt.engine.parse.oracle.PlatformReplay
import dev.revokt.engine.parse.oracle.ReferenceView
import dev.revokt.engine.parse.producer.D7Corpus
import dev.revokt.engine.parse.producer.ExternalCorpus
import dev.revokt.engine.parse.producer.ProducerCorpus
import dev.revokt.engine.parse.records.CorpusRecord.RecordClass
import java.io.File
import java.time.LocalDate
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The corpus records of spec §9.2 against the replay on this run's platform oracles (the test JDK, Conscrypt): every
 * input the replay classes as D1-dom, as an SPKI a platform re-encodes (D2's allow-list), as a D3 divergence or as a D8-gap entry has its committed record, with the
 * same fields, and no record is stale. A rule-based justification (the producer's error, the D1-dom rule, the class's
 * reason, the zlint errors) is compared too, so a changed reason fails; a record whose rule yields none (a D8-gap entry
 * with no zlint error, a release blocker) needs one written by hand. Every record of a D8-gap input carries
 * `keyability`, and a `KEYABILITY_GAP` record exists only for an input with no other class.
 *
 * D1_DOM, D2_REENCODE_ALLOW and KEYABILITY_GAP depend on the platform oracles: each record has an entry per oracle
 * version (oracle 1 per matrix JDK, oracle 2 per Conscrypt release), and counts on a run where an entry of its versions
 * `holds`. Regenerate with `native/producer-oracle/record-goldens.sh`, which runs the writer hook once per matrix JDK and
 * once on the previous Conscrypt (`jvmTestConscryptPrevious`); it keeps every hand-written justification and `added`
 * date, and prunes entries of versions that have left the matrix. Fields taken once per record from the preferred oracle
 * (keyability, the justification, oracle 4's `read:`) must agree across Conscrypt versions; if they ever differ, the
 * runs fail rather than silently keep the last writer's view.
 */
class RecordsTest {
    private val platforms = PlatformReplay.all

    /** This run's platform oracles and versions, as failures name them. */
    private val run = platforms.joinToString { it.oracle.label }

    private fun isPlatform(o: CorpusRecord.Oracle) = platforms.any { it.oracle.id == o.id }

    private fun isCurrent(o: CorpusRecord.Oracle) =
        platforms.any {
            it.oracle.id == o.id &&
                it.oracle.version == o.version
        }

    /** The matrix's versions per platform oracle (gradle/oracle-matrix.properties, passed in by the build). */
    private val matrix: Map<String, Set<String>> =
        mapOf("1" to "revokt.matrixJdks", "2" to "revokt.matrixConscrypt").mapValues { (_, key) ->
            System
                .getProperty(key)
                .orEmpty()
                .split(',')
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .toSet()
        }

    /** Whether [o]'s version is still in the matrix; an entry of a version that has left it is pruned on the next write. */
    private fun inMatrix(o: CorpusRecord.Oracle): Boolean =
        matrix[o.id]?.takeIf { it.isNotEmpty() }?.contains(o.version) ?: true

    @Test
    fun `the committed records equal the replay's classes on this run`() {
        val computed = computed().associateBy { it.key }
        val committed = CorpusRecord.committed()
        assertEquals(
            committed.size,
            committed.map { it.key }.toSet().size,
            "one record per input, class and divergence",
        )
        val here = committed.filter { counts(it) }.associateBy { it.key }
        assertEquals(emptySet(), here.keys - computed.keys, "stale records on $run: regenerate them")
        assertEquals(emptySet(), computed.keys - here.keys, "unrecorded entries on $run: record them")
        for ((key, record) in here) {
            val c = computed.getValue(key)
            val rule = c.justification.isNotBlank()
            assertEquals(fields(c, rule), fields(record, rule), record.path)
            // Where the rule yields none (a release blocker), the justification must be written by hand, not a stale rule.
            if (!rule) {
                assertFalse(
                    RULE_TEXTS.any {
                        it in record.justification
                    },
                    "${record.path}: a stale rule-based justification",
                )
            }
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
        // KEYABILITY_GAP only for an input with no other class; an oracle-dependent class may hold on other oracle versions than the gap.
        val independent = committed.filterNot(::dependent)
        val gapAlongside =
            committed
                .filter { it.recordClass == RecordClass.KEYABILITY_GAP }
                .filter { g -> independent.any { it.sha256 == g.sha256 } }
        assertEquals(emptyList(), gapAlongside.map { it.path }, "KEYABILITY_GAP records of inputs admitted otherwise")
        // Keyability on an oracle-independent record must hold on every JDK: the input is accepted wherever it is recorded.
        val unevenGap =
            independent.filter {
                it.keyability != null &&
                    it.oracles.any { o -> o.id == "1" && o.outcome != "Accept" }
            }
        assertEquals(
            emptyList(),
            unevenGap.map {
                it.path
            },
            "D8-gap inputs of an oracle-independent class not in the gap on every JDK",
        )
        val gap = computed.values.mapNotNull { it.keyability?.let { k -> "${k.clause}/${k.parser}" } }
        println("D8 gap on $run (clause/path → inputs): ${gap.groupingBy { it }.eachCount().toSortedMap()}")
    }

    @Test
    fun `the records writer merges this run's view when requested`() {
        val path = System.getProperty("revokt.writeRecords") ?: return
        // The committed records go to [path], the large corpus's to its replay/records.jsonl on a run with its checkout.
        val files = listOfNotNull(File(path), CorpusRecord.external)
        val existing = files.filter { it.exists() }.flatMap { CorpusRecord.parse(it.readText()) }
        val (external, committed) = merge(existing, computed()).partition { ExternalCorpus.owns(it.path) }
        CorpusRecord.write(files[0], committed)
        CorpusRecord.external?.let { CorpusRecord.write(it.apply { parentFile.mkdirs() }, external) }
    }

    /** Whether [r]'s class (or divergence) depends on the platform oracles, so that it holds per oracle version. */
    private fun dependent(r: CorpusRecord): Boolean =
        r.recordClass in ORACLE_DEPENDENT || r.divergence in CorpusRecord.ORACLE_DIVERGENCES

    /** Whether [r] counts on this run: an oracle-dependent class only where a platform entry of this run holds. */
    private fun counts(r: CorpusRecord): Boolean = !dependent(r) || r.oracles.any { isCurrent(it) && it.holds == true }

    /**
     * The record's fields that the replay decides: everything but the date and the platform entries of other versions, and
     * the justification only when [withJustification] (the replay's own justification is rule-based).
     */
    private fun fields(
        r: CorpusRecord,
        withJustification: Boolean,
    ): String {
        val own = r.oracles.filter { !isPlatform(it) || isCurrent(it) }
        val justification = if (withJustification) r.justification else ""
        return r.copy(oracles = own, justification = justification, added = "").toJson().write()
    }

    /**
     * [existing] with this run's view merged in. Every record's platform entries for this run's versions are replaced: a
     * computed record takes the computed ones; an oracle-dependent record not computed here records each platform's
     * outcome with `holds` false, and is dropped once no platform version holds it; any other record not computed here is
     * stale and dropped. A rule-based justification replaces the one written; a hand-written one is kept only where the
     * rule yields none.
     */
    private fun merge(
        existing: List<CorpusRecord>,
        computed: List<CorpusRecord>,
    ): List<CorpusRecord> {
        val byKey = computed.associateBy { it.key }
        val out = LinkedHashMap<Triple<String, RecordClass, String?>, CorpusRecord>()
        for (e in existing) {
            val others = e.oracles.filter { isPlatform(it) && !isCurrent(it) && inMatrix(it) }
            val c = byKey[e.key]
            if (c != null) {
                out[e.key] =
                    c.copy(
                        oracles = sortOracles(others + c.oracles),
                        justification = c.justification.ifBlank { e.justification },
                        added = e.added,
                    )
            } else if (dependent(e)) {
                val here = platforms.map { entry(it, e.path, e.sha256, holds = false) }
                val oracles = sortOracles(others + here + e.oracles.filterNot(::isPlatform))
                if (oracles.any { it.holds == true }) out[e.key] = e.copy(oracles = oracles)
            }
        }
        for (c in computed) if (c.key !in out) out[c.key] = c
        return out.values.toList()
    }

    private fun sortOracles(oracles: List<CorpusRecord.Oracle>) =
        oracles.sortedWith(
            compareBy<CorpusRecord.Oracle> { ORACLE_ORDER.indexOf(it.id) }.thenComparator {
                a,
                b,
                ->
                versionOrder(a.version, b.version)
            },
        )

    /** Versions compared numerically part by part (`2.9.0` before `2.10.0`), falling back to text. */
    private fun versionOrder(
        a: String,
        b: String,
    ): Int {
        val (x, y) = listOf(a, b).map { v -> v.split('.').map { it.toIntOrNull() } }
        for ((p, q) in x.zip(y)) {
            if (p == null || q == null) return a.compareTo(b)
            if (p != q) return p.compareTo(q)
        }
        return x.size.compareTo(y.size)
    }

    /** [p]'s entry for the input at [path]: its outcome, the bytes it reads where they differ, and whether the class holds. */
    private fun entry(
        p: PlatformReplay,
        path: String,
        sha256: String,
        holds: Boolean?,
    ): CorpusRecord.Oracle {
        val a = p.acceptedByName[path]
        val read =
            a
                ?.read
                ?.der
                ?.let(PlatformReplay::sha)
                ?.takeIf { it != sha256 }
        return CorpusRecord.Oracle(p.oracle.id, p.oracle.version, if (a != null) "Accept" else "Reject", read, holds)
    }

    /**
     * The records the replay classes on this run. Rule-based fields come from the platform oracles in [preferred] order. A
     * D8-gap input's keyability rides on each of its records, with the gap justification appended; it gets a
     * `KEYABILITY_GAP` record holding on the platform oracles where it is in the gap and has no other class.
     */
    private fun computed(preferred: List<PlatformReplay> = PlatformReplay.preferred): List<CorpusRecord> {
        val inputs = ProducerCorpus.inputs.associateBy { it.name }
        val classed = classed(inputs, preferred)
        // Each D8-gap input's keyability per platform oracle, in preferred order.
        val gap = LinkedHashMap<String, LinkedHashMap<String, CorpusRecord.Keyability>>()
        for (p in preferred) {
            for (a in p.accepted) gap(p, a)?.let { gap.getOrPut(a.name) { LinkedHashMap() }[p.oracle.id] = it }
        }
        val out =
            classed.map { c ->
                val k = gap[c.input.name]?.values?.first()
                // A D7 case is named by §9.2 itself, so its text stands where the gap's rule yields none.
                val justification =
                    if (c.recordClass == RecordClass.D7_LENIENCY) {
                        listOfNotNull(c.reason, k?.let(::gapJustification)?.ifEmpty { null }).joinToString(" ")
                    } else {
                        withGap(c.reason, k)
                    }
                record(c.input, c.recordClass, c.divergence, k, justification, c.holdsOn)
            }
        val gapOnly =
            gap.mapNotNull { (name, byPlatform) ->
                val others = classed.filter { it.input.name == name }
                val holdsOn = byPlatform.keys.filter { id -> others.none { !it.dependent || id in it.holdsOn } }
                holdsOn.firstOrNull()?.let { first ->
                    val k = byPlatform.getValue(first)
                    record(
                        inputs.getValue(name),
                        RecordClass.KEYABILITY_GAP,
                        null,
                        k,
                        gapJustification(k),
                        holdsOn.toSet(),
                    )
                }
            }
        return out + gapOnly
    }

    /** [reason] with [k]'s gap justification appended; none when the gap's rule yields none (a hand-written one is due). */
    private fun withGap(
        reason: String,
        k: CorpusRecord.Keyability?,
    ): String {
        val gap = k?.let(::gapJustification) ?: return reason
        return if (gap.isEmpty()) "" else "$reason $gap"
    }

    /**
     * One class the replay assigns an input, with its divergence, its rule-based reason (from the first preferred platform
     * oracle the class holds on) and, for an oracle-dependent class, the platform oracles it holds on.
     */
    private class Classed(
        val input: ProducerCorpus.Input,
        val recordClass: RecordClass,
        val divergence: String?,
        val reason: String,
        val dependent: Boolean,
        val holdsOn: MutableSet<String> = HashSet(),
    )

    /**
     * The D1_DOM, D2_REENCODE_ALLOW, D3_DIVERGENCE and D7_LENIENCY classes on this run, the oracle-dependent ones from
     * [preferred].
     */
    private fun classed(
        inputs: Map<String, ProducerCorpus.Input>,
        preferred: List<PlatformReplay>,
    ): List<Classed> {
        val classed = LinkedHashMap<Triple<String, RecordClass, String?>, Classed>()

        fun add(
            name: String,
            recordClass: RecordClass,
            divergence: String?,
            reason: () -> String,
            p: PlatformReplay,
        ) {
            val key = Triple(name, recordClass, divergence)
            classed.getOrPut(key) { Classed(inputs.getValue(name), recordClass, divergence, reason(), true) }.holdsOn +=
                p.oracle.id
        }
        for (p in preferred) {
            classedOn(p) { name, recordClass, divergence, reason -> add(name, recordClass, divergence, reason, p) }
        }
        val out = classed.values.toMutableList()
        for ((name, cases) in D7Corpus.byInput) {
            out += Classed(inputs.getValue(name), RecordClass.D7_LENIENCY, null, d7Justification(cases), false)
        }
        for (input in ProducerCorpus.inputs) {
            if (CertificateParser.parse(input.der) !is CertificateParse.Parsed) continue
            for (d in ReferenceView.of(PlatformReplay.sha(input.der))?.divergences.orEmpty()) {
                out += Classed(input, RecordClass.D3_DIVERGENCE, d, DIVERGENCE.getValue(d), false)
            }
        }
        return out
    }

    /** The oracle-dependent classes [p] assigns, each passed to [add] with its rule-based reason. */
    private fun classedOn(
        p: PlatformReplay,
        add: (String, RecordClass, String?, () -> String) -> Unit,
    ) {
        for (a in p.accepted) {
            p.outsideDomain(a)?.let { reason -> add(a.name, RecordClass.D1_DOM, null) { d1Justification(a, reason) } }
        }
        for (name in p.spkiReencoded) add(name, RecordClass.D2_REENCODE_ALLOW, null) { REENCODE }
        for (name in p.spkiNullParameters) add(name, RecordClass.D2_REENCODE_ALLOW, null) { REENCODE_NULL }
        p.oracle.tbsDivergence?.let { d ->
            for (name in p.tbsDiffering) add(name, RecordClass.D3_DIVERGENCE, d) { DIVERGENCE.getValue(d) }
        }
        p.oracle.timeDivergence?.let { d ->
            for (name in p.timeOffsetDropped.keys) add(name, RecordClass.D3_DIVERGENCE, d) { DIVERGENCE.getValue(d) }
        }
    }

    /**
     * A record holding on one Conscrypt version only counts on runs of that version: its other version's entry is
     * neither counted nor compared here.
     */
    @Test
    fun `a record that holds on one oracle version counts only on that version's runs`() {
        val base = CorpusRecord.committed().first { it.recordClass == RecordClass.D1_DOM }
        val elsewhere = CorpusRecord.Oracle(Oracle2.id, "0.0.1", "Accept", holds = true)
        val here = CorpusRecord.Oracle(Oracle2.id, Oracle2.version, "Reject", holds = false)
        val otherOnly =
            base.copy(
                oracles =
                    base.oracles.filter { it.id != Oracle2.id && it.id != Oracle1.id } + elsewhere + here,
            )
        assertFalse(counts(otherOnly), "holds on another Conscrypt version only")
        assertTrue(
            counts(
                otherOnly.copy(
                    oracles =
                        otherOnly.oracles - here + here.copy(outcome = "Accept", holds = true),
                ),
            ),
        )
        assertEquals(listOf(here), otherOnly.oracles.filter(::isCurrent), "only this run's entries are compared")
    }

    /**
     * The replay reads an oracle-dependent divergence only on the oracle versions it holds on: a `CONSCRYPT_TBS` record
     * holding on Conscrypt counts there and nowhere else.
     */
    @Test
    fun `an oracle-dependent divergence counts only on the oracle versions it holds on`() {
        val base = CorpusRecord.committed().first { it.recordClass == RecordClass.D3_DIVERGENCE }
        val oracles = listOf(CorpusRecord.Oracle(Oracle2.id, Oracle2.version, "Accept", holds = true))
        val tbs = base.copy(divergence = "CONSCRYPT_TBS", oracles = oracles)
        assertEquals(setOf(base.path), CorpusRecord.divergences(listOf(tbs), Oracle2)["CONSCRYPT_TBS"])
        assertEquals(null, CorpusRecord.divergences(listOf(tbs), Oracle1)["CONSCRYPT_TBS"])
        val older = tbs.copy(oracles = oracles.map { it.copy(version = "0.0.1") })
        assertEquals(
            null,
            CorpusRecord.divergences(listOf(older), Oracle2)["CONSCRYPT_TBS"],
            "another Conscrypt version",
        )
        assertEquals(setOf(base.path), CorpusRecord.divergences(listOf(base), Oracle1)[base.divergence], "independent")
    }

    /**
     * A platform oracle whose `getTBSCertificate()` never matches `Cert.tbs` lands every input it parses in its divergence
     * class (`CONSCRYPT_TBS` for Conscrypt), holding on that oracle only (spec §9.2 D2: recorded, not a violation).
     */
    @Test
    fun `a TBS that differs from the platform's is classed as the platform's divergence`() {
        val tampered = PlatformReplay(TamperedTbsOracle)
        val classed = classed(ProducerCorpus.inputs.associateBy { it.name }, listOf(tampered))
        val divergent =
            classed.filter {
                it.recordClass == RecordClass.D3_DIVERGENCE &&
                    it.divergence == TamperedTbsOracle.tbsDivergence
            }
        assertEquals(
            tampered.accepted
                .filter {
                    it.certificate != null
                }.map { it.name }
                .toSet(),
            divergent.map { it.input.name }.toSet(),
        )
        assertTrue(
            divergent.isNotEmpty() && divergent.all { it.dependent && it.holdsOn == setOf(TamperedTbsOracle.id) },
        )
    }

    /**
     * The D8-gap fields of a platform-accepted input in the D1 domain whose read parses outside the profile: end-entity
     * inputs only, since `producerKeyable` is a leaf predicate (spec §9.2); null otherwise.
     */
    private fun gap(
        p: PlatformReplay,
        a: PlatformReplay.Accepted,
    ): CorpusRecord.Keyability? {
        val c = a.certificate ?: return null
        val clause = Keyability.firstFailing(c)?.takeUnless { isCa(c) || p.outsideDomain(a) != null }
        return clause?.let {
            val golden = PlatformReplay.producerGolden(a)
            CorpusRecord.Keyability(golden.substringAfterLast(' '), it.name, zlintResult(a.readInput))
        }
    }

    private fun record(
        input: ProducerCorpus.Input,
        recordClass: RecordClass,
        divergence: String?,
        keyability: CorpusRecord.Keyability?,
        justification: String,
        holdsOn: Set<String>,
    ): CorpusRecord {
        val sha = PlatformReplay.sha(input.der)
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
                        PlatformReplay.sha(c.rawSpki()),
                        scts.sorted(),
                    )
                }
            }
        val dependent = recordClass in ORACLE_DEPENDENT || divergence in CorpusRecord.ORACLE_DIVERGENCES
        val missing = "no golden for ${input.name}; run native/revokt-oracle/record-goldens.sh"
        val oracles =
            platforms.map { entry(it, input.name, sha, if (dependent) it.oracle.id in holdsOn else null) } +
                listOf(
                    CorpusRecord.Oracle(
                        "3a",
                        X509_PARSER,
                        checkNotNull(Oracle3a.reply(sha)) { missing }.substringBefore('\t'),
                    ),
                    CorpusRecord.Oracle(
                        "3b",
                        LOCATOR,
                        checkNotNull(Oracle3b.reply(sha)) { missing }.substringBefore('\t'),
                    ),
                    CorpusRecord.Oracle("4", PRODUCER, producerOutcome(input)),
                )
        return CorpusRecord(sha, input.name, revokt, oracles, recordClass, divergence, keyability, justification, today)
    }

    /**
     * Oracle 4's golden for canon of the input, else for canon of the bytes the first platform oracle that reads any reads
     * (marked `read:`), else `no canon`.
     */
    private fun producerOutcome(input: ProducerCorpus.Input): String {
        input.canonSha256?.let { sha -> PlatformReplay.producer[sha]?.let { return it } }
        val read = PlatformReplay.preferred.firstNotNullOfOrNull { it.acceptedByName[input.name]?.read?.canonSha256 }
        return read?.let { PlatformReplay.producer[it] }?.let { "read: $it" } ?: "no canon"
    }

    private fun d1Justification(
        a: PlatformReplay.Accepted,
        reason: String,
    ): String =
        when (reason) {
            PlatformReplay.PRODUCER_REJECTS -> {
                val error = PlatformReplay.producerGolden(a).removePrefix("REJECT ")
                "Oracle 4 rejects canon of the bytes read ($error): no filter can contain it, so it is never queried " +
                    "$D1_RULE"
            }

            PlatformReplay.PRODUCER_KEYS_OTHER_BYTES -> {
                "Oracle 4 keys bytes other than the reference view's: no filter holds this certificate's key " +
                    "(§9.2 D1-dom)."
            }

            PlatformReplay.VERSION_TRAILING -> {
                "Content after the INTEGER inside [0]: D1-dom by rule, the [0] flattening of §9.2."
            }

            PlatformReplay.NO_PLATFORM_CANON -> {
                "No platform canon can be built: D1-dom by rule (§9.2, revision 39)."
            }

            else -> {
                fail("${a.name}: unknown D1-dom reason $reason")
            }
        }

    /** The D7 cases an input carries, as §9.2 names them. */
    private fun d7Justification(cases: List<D7Corpus.Case>): String =
        "$D7_RULE ${cases.joinToString("; ") { it.text }}."

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

        /** D1-dom rule texts, which a hand-written justification never repeats. */
        const val D1_RULE = "(§9.2 D1-dom)."

        const val D1_BY_RULE = "D1-dom by rule"

        const val D7_RULE = "A §9.2 D7 leniency case:"

        val ORACLE_DEPENDENT = setOf(RecordClass.D1_DOM, RecordClass.D2_REENCODE_ALLOW, RecordClass.KEYABILITY_GAP)

        val ORACLE_ORDER = listOf("1", "2", "3a", "3b", "3c", "4")

        /** The oracle pins (spec §9.2, Appendix A): 3a in native/revokt-oracle/Cargo.toml, 4 in native/producer-oracle/go.mod. */
        const val X509_PARSER = "x509-parser 0.18.1"

        const val LOCATOR = "revokt-oracle locate"

        const val PRODUCER = "mozilla/crlite go 008299826177"

        const val REENCODE =
            "The platform re-encodes this SPKI's non-minimal headers in getPublicKey().getEncoded(), and keeps " +
                "the key; allowed by the §9.2 re-encoding rule."

        const val REENCODE_NULL =
            "The platform does not know this key's algorithm: its generic key's getEncoded() adds NULL parameters to " +
                "the AlgorithmIdentifier and keeps the OID and the key bits; allowed by the §9.2 re-encoding rule's " +
                "second case (revision 41)."

        val DIVERGENCE =
            mapOf(
                "3A_HEADER_LAX" to
                    "x509-parser yields pairs under an inner identifier other than 0x04 (tag number 4 in another " +
                    "class or form); §9.2 fails the list, as Firefox and webpki do (3A_HEADER_LAX).",
                "3A_TBS_LAX" to
                    "x509-parser takes an element with tag number 3 that is not a constructed context-specific [3] " +
                    "as extensions; the JDK and revokt ignore it (3A_TBS_LAX).",
                "CONSCRYPT_TIME_OFFSET" to
                    "Conscrypt reads this UTCTime's ±hhmm differential as if it were Z; revokt decodes it as the JDK " +
                    "does, so the platform's time differs by exactly the differential (§9.2 D2, CONSCRYPT_TIME_OFFSET).",
                "CONSCRYPT_TBS" to
                    "Conscrypt's getTBSCertificate() differs from Cert.tbs: Conscrypt verifies over the presented " +
                    "TBS TLV, so it cannot verify this input (§9.2 D2, CONSCRYPT_TBS).",
                "DUPLICATE_EXTENSION" to
                    "x509-parser reports a duplicate SCT-list extension as an error; revokt takes the union of the " +
                    "extensions' pairs (§9.2 D3).",
            )

        /** Every rule's text: where a rule yields no justification, a hand-written one must contain none of them. */
        val RULE_TEXTS: List<String> =
            listOf(GAP_RULE, D1_RULE, D1_BY_RULE, D7_RULE, REENCODE, REENCODE_NULL) + DIVERGENCE.values
    }
}
