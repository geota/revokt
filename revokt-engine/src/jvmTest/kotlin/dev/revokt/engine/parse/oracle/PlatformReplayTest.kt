// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.oracle.PlatformReplay.Accepted
import dev.revokt.engine.parse.producer.ProducerCorpus
import dev.revokt.engine.parse.records.CorpusRecord
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The PR-tier replay of spec §9.2 against one platform oracle, live, with the recorded 3a, 3b and oracle-4 goldens: D1
 * and its recorded domain, D2 and D3 on `parse(encoded)`, the "no raw-byte reference" gate metric, and D6. [floor] is the
 * least number of inputs D1's domain and D2 must exercise; [tbsDivergence] names the divergence class a difference from
 * the platform's `getTBSCertificate()` is recorded under, or null where it is a D2 violation (oracle 1).
 */
@Suppress("UnnecessaryAbstractClass") // abstract so that JUnit runs only the per-oracle subclasses
abstract class PlatformReplayTest internal constructor(
    private val replay: PlatformReplay,
    private val floor: Int,
    private val tbsDivergence: String?,
) {
    private val accepted get() = replay.accepted

    @Test
    fun `D1 - every platform-accepted input in the producer's domain parses`() {
        val dom = HashMap<String, MutableSet<String>>()
        val violations = ArrayList<String>()
        var inside = 0
        for (a in accepted) {
            val reason = replay.outsideDomain(a)
            if (reason != null) {
                dom.getOrPut(reason) { HashSet() } += a.name
            } else {
                inside++
                if (a.certificate == null) violations += "${a.name}: ${(a.parse as CertificateParse.Failed).detail}"
            }
        }
        val counts = dom.mapValues { it.value.size }
        println("D1 on ${replay.oracle.label}: ${accepted.size} accepted, $inside in the domain; D1-dom $counts")
        assertEquals(emptyList(), violations, "D1 violations")
        assertTrue(inside > floor, "D1 exercised on only $inside inputs")
        // The by-rule classes are pinned, so a locator or `[0]` regression cannot move inputs out of the domain unseen.
        assertEquals<Set<String>?>(null, dom[PlatformReplay.NO_PLATFORM_CANON], "inputs with no platform canon")
        // Every other D1-dom entry is a corpus record (RecordsTest), with its reason.
    }

    @Test
    fun `no platform-accepted input lacks a raw-byte reference, outside the unparsed inputs the producer cannot key`() {
        val missing =
            accepted
                .filter { it.reference == null }
                .filterNot {
                    it.certificate == null &&
                        replay.outsideDomain(it) in
                        setOf(PlatformReplay.PRODUCER_REJECTS, PlatformReplay.NO_PLATFORM_CANON)
                }.map { it.name }
        assertEquals(emptyList(), missing, "platform-accepted inputs with no raw-byte reference")
    }

    @Test
    fun `D2 and D3 - on every parsed encoding revokt's fields equal canon, the platform's and the reference view`() {
        var compared = 0
        val unavailable = HashMap<String, Int>()
        val divergences = HashMap<String, MutableSet<String>>()
        val javaFields = ArrayList<String>()
        val reencoded = HashSet<String>()
        for (a in accepted) {
            val c = a.certificate ?: continue
            val r = a.reference ?: fail("${a.name}: revokt parses it and it has no raw-byte reference")
            val parts = a.readInput.canonParts ?: fail("${a.name}: revokt parses it and canon cannot be located")
            compared++
            if (!assertEnvelope(a, c, parts, r)) divergences.getOrPut(tbsDivergence!!) { HashSet() } += a.name
            assertReference(a.name, c, r)
            r.divergences.forEach { divergences.getOrPut(it) { HashSet() } += a.name }
            if (Keyability.firstFailing(c) == null) assertProducerBytes(a, c)
            compareJavaFields(a, c, unavailable, reencoded, javaFields)
        }
        println("D2 on ${replay.oracle.label}: $compared compared; unavailable $unavailable; divergences $divergences")
        assertEquals(emptyList(), javaFields, "normalised Java fields that differ from ${replay.oracle.label}'s")
        assertEquals(emptyMap(), unavailable, "${replay.oracle.label} getters that threw on the committed corpus")
        // The re-encoding allow-list (§9.2): the JDK re-encodes the non-minimal headers of an SPKI, outside the key the
        // BIT STRING encapsulates, and nothing else.
        val spkiMutants =
            accepted
                .filter { it.certificate != null && SPKI_PATH in it.name && "$SPKI_PATH/1:03~" !in it.name }
                .map { it.name }
        assertEquals(spkiMutants.toSet(), reencoded, "inputs whose SPKI the JDK re-encodes")
        // The divergence classes among the inputs compared are the committed D3_DIVERGENCE records (spec §9.2 D3).
        val parsed = accepted.filter { it.certificate != null }.map { it.name }.toSet()
        val recorded =
            CorpusRecord
                .divergences()
                .mapValues { (_, paths) -> paths.filter { it in parsed }.toSet() }
                .filterValues { it.isNotEmpty() }
        assertEquals(recorded, divergences, "D3 divergence classes")
        assertTrue(compared > floor, "D2 exercised on only $compared inputs")
    }

    /** The normalised Java fields against the platform's, with the SPKI re-encoding allow-list's rule applied. */
    private fun compareJavaFields(
        a: Accepted,
        c: ParsedCertificate,
        unavailable: MutableMap<String, Int>,
        reencoded: MutableSet<String>,
        mismatches: MutableList<String>,
    ) {
        val (unavailableHere, differing) = JavaFields.compare(a.x509, c).partition { it.unavailable }
        unavailableHere.forEach { unavailable.merge(it.name, 1, Int::plus) }
        for (f in differing.filter { it.mismatch != null }) {
            if (f.name == "spki" && PlatformReplay.reencodesSpki(c.rawSpki(), a.x509.publicKey.encoded)) {
                reencoded += a.name
            } else {
                mismatches += "${a.name}: ${f.name}: ${f.mismatch}"
            }
        }
    }

    /**
     * `Cert.tbs` against canon's first element and the platform's `getTBSCertificate()`, and `Cert.sig` against canon's.
     * Returns whether `Cert.tbs` equals the platform's; a difference fails unless [tbsDivergence] records it.
     */
    private fun assertEnvelope(
        a: Accepted,
        c: ParsedCertificate,
        parts: Oracle3b.Parts,
        r: ReferenceView,
    ): Boolean {
        assertEquals(parts.tbs, Oracle3a.hex(c.tbsBytes), "${a.name}: Cert.tbs against canon")
        val signature = Oracle3a.cleared(parts.signature, r.unusedBits)
        assertEquals(signature, Oracle3a.hex(c.envelope.signature), "${a.name}: Cert.sig")
        val same = a.x509.tbsCertificate.contentEquals(c.tbsBytes)
        if (tbsDivergence == null) {
            assertEquals(
                Oracle3a.hex(a.x509.tbsCertificate),
                Oracle3a.hex(c.tbsBytes),
                "${a.name}: Cert.tbs against ${replay.oracle.label}",
            )
        }
        return same
    }

    private fun assertReference(
        name: String,
        c: ParsedCertificate,
        r: ReferenceView,
    ) {
        val label = "$name against ${r.source}"
        assertEquals(r.serial, Oracle3a.hex(c.rawSerial()), "$label: serial")
        assertEquals(r.spki, Oracle3a.hex(c.rawSpki()), "$label: spki")
        assertEquals(r.subject, Oracle3a.hex(c.rawSubject()), "$label: subject")
        assertEquals(r.issuer, Oracle3a.hex(c.rawIssuer()), "$label: issuer")
        val table =
            c.tbs.extensions.map {
                "${Oracle3a.hex(it.oid.bytes(c.tbsBytes))},${it.critical},${Oracle3a.hex(it.value.bytes(c.tbsBytes))}"
            }
        assertEquals(r.extensions, table, "$label: extension table")
        val scts =
            c.fields.scts
                .map { Oracle3a.hex(it.logId.toByteArray()) to it.timestamp }
                .toSet()
        assertEquals(r.scts, scts, "$label: SCT pairs")
    }

    /** D2's producer clause where `producerKeyable`: revokt's serial and SPKI are the bytes oracle 4 keys. */
    private fun assertProducerBytes(
        a: Accepted,
        c: ParsedCertificate,
    ) {
        val golden = PlatformReplay.producerGolden(a)
        val (status, serial, spki) = golden.split(' ')
        assertEquals("OK", status, "${a.name}: producerKeyable and oracle 4 answers $golden")
        assertEquals(serial, Oracle3a.hex(c.rawSerial()), "${a.name}: rawSerial against oracle 4")
        assertEquals(spki, PlatformReplay.sha(c.rawSpki()), "${a.name}: SHA-256(rawSpki) against oracle 4")
    }

    @Test
    fun `D6 - parse is deterministic, its offsets re-slice Cert tbs and b, and parse(encoded) equals parse(b)`() {
        var resliced = 0
        for (input in ProducerCorpus.inputs) {
            val first = CertificateParser.parse(input.der)
            assertEquals(fingerprint(first, true), fingerprint(CertificateParser.parse(input.der), true), input.name)
            val c = (first as? CertificateParse.Parsed)?.certificate ?: continue
            if (assertOffsets(input.name, c)) resliced++
        }
        var roundTrips = 0
        val bothParsed =
            accepted.mapNotNull { a ->
                CertificateParser
                    .parse(a.presented)
                    .takeIf { it is CertificateParse.Parsed && a.parse is CertificateParse.Parsed }
                    ?.let { Triple(a.name, it, a.parse) }
            }
        for ((name, fromB, fromEncoded) in bothParsed) {
            assertEquals(fingerprint(fromB, false), fingerprint(fromEncoded, false), "$name: parse(encoded)")
            roundTrips++
        }
        assertTrue(resliced > 1000 && roundTrips > floor, "D6 exercised on $resliced and $roundTrips inputs only")
    }

    /** Every TBS offset lies in `Cert.tbs` from its tag octet; shifted, it re-slices `b` when the TBS is definite. */
    private fun assertOffsets(
        name: String,
        c: ParsedCertificate,
    ): Boolean {
        assertEquals(Span(0, c.tbsBytes.size), c.tbs.tlv, "$name: Cert.tbs spans the TBS from its tag octet")
        val spans = tbsSpans(c)
        for (s in spans) assertTrue(s.start in 0..s.end && s.end <= c.tbsBytes.size, "$name: span $s outside Cert.tbs")
        if (c.envelope.tbsIndefinite) return false
        val header = checkNotNull(Oracle1.header(c.tbsBytes, 0)) { "$name: Cert.tbs header" }.size
        val shift = c.envelope.presentedTbs.content.start - header
        for (s in spans.filter { it.start >= header }) {
            assertEquals(
                Oracle3a.hex(s.bytes(c.tbsBytes)),
                Oracle3a.hex(c.der.copyOfRange(s.start + shift, s.end + shift)),
                "$name: span $s re-sliced from b",
            )
        }
        return true
    }

    private fun tbsSpans(c: ParsedCertificate): List<Span> {
        val t = c.tbs
        return listOfNotNull(t.version, t.serial, t.signature, t.issuer, t.validity.notBefore, t.validity.notAfter) +
            listOfNotNull(t.subject, t.spki, t.tail.wrapper, c.fields.ski, c.fields.akiKeyId) +
            t.extensions.flatMap { listOf(it.oid, it.value, it.tlv) } + c.ignoredElements.map { it.span }
    }

    /**
     * Every field of a parse, as text. [presented] adds the offsets into `b` (the envelope and the non-minimal headers),
     * which `encoded` may move.
     */
    private fun fingerprint(
        parse: CertificateParse,
        presented: Boolean,
    ): String {
        val c =
            when (parse) {
                is CertificateParse.Failed -> return "Failed ${parse.reason} ${parse.detail}"
                is CertificateParse.Parsed -> parse.certificate
            }
        val t = c.tbs
        val fields =
            listOf(
                Oracle3a.hex(c.tbsBytes),
                tbsSpans(c),
                t.validity.notBeforeMillis,
                t.validity.notAfterMillis,
                t.extensions.map { "${it.oidDotted}/${it.critical}" },
                t.tail.uniqueIds,
                c.fields.scts,
                c.ignoredElements.map { it.site },
                Oracle3a.hex(c.envelope.signature),
                c.envelope.algorithmIdMismatch,
                Keyability.firstFailing(c),
            )
        val offsets =
            listOf(
                c.envelope.presentedTbs.tlv,
                c.envelope.signatureAlgorithm,
                c.envelope.signatureValue,
                c.envelope.tbsIndefinite,
                c.nonMinimalHeaders.map { "${it.offset}/${it.site}" },
                c.steps,
            )
        return (if (presented) fields + offsets else fields).joinToString(" | ")
    }

    private companion object {
        /** The length-mutant path of a header in the SPKI, its own included (`LengthMutants`). */
        const val SPKI_PATH = "/0:30/0:30/6:30"
    }
}
