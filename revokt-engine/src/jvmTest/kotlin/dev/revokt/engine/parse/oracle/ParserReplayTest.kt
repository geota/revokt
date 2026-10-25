// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerNode
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.producer.ProducerCorpus
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The PR-tier replay of spec §9.2 against oracle 1 (the test JDK's `SUN` factory, live) with the recorded 3a, 3b and
 * oracle-4 goldens: D1 and its recorded domain, D2 and D3 on `parse(encoded)`, the "no raw-byte reference" gate metric,
 * and D6. Run it on every matrix JDK with `-Prevokt.testJdk`.
 */
class ParserReplayTest {
    /**
     * One platform-accepted input: [encoded] is the bytes revokt reads (`getEncoded()`, or the platform canon, spec §9.2
     * revision 39), null when no platform canon can be built; with its reference view and parse.
     */
    private class Accepted(
        val name: String,
        val presented: ByteArray,
        val jdk: java.security.cert.X509Certificate,
        val encoded: ProducerCorpus.Input?,
        val reference: ReferenceView?,
        val parse: CertificateParse,
    ) {
        val certificate: ParsedCertificate? get() = (parse as? CertificateParse.Parsed)?.certificate
    }

    private val producer by lazy { ProducerCorpus.goldens() }

    private val accepted: List<Accepted> by lazy {
        ProducerCorpus.inputs.mapNotNull { input ->
            when (val o = Oracle1.run(input.der)) {
                is Oracle1.Outcome.Accept -> accepted(input, o.certificate)
                is Oracle1.Outcome.Reject -> null
                is Oracle1.Outcome.Crash -> fail("${input.name}: oracle 1 crashed on the committed corpus: ${o.error}")
            }
        }
    }

    private fun accepted(
        input: ProducerCorpus.Input,
        jdk: java.security.cert.X509Certificate,
    ): Accepted {
        val name = input.name
        val encoded = Oracle1.read(name, jdk)
        val reference =
            try {
                encoded?.let { ReferenceView.of(sha(it.der)) }
            } catch (e: IllegalStateException) {
                fail("$name: ${e.message}; run native/revokt-oracle/record-goldens.sh on JDK ${Oracle1.version}")
            }
        return Accepted(name, input.der, jdk, encoded, reference, CertificateParser.parse(encoded?.der ?: jdk.encoded))
    }

    /** Why a platform-accepted input is outside the D1 domain, or null when it is inside. */
    private fun outsideDomain(a: Accepted): String? {
        val read = a.encoded ?: return NO_PLATFORM_CANON
        val parts = read.canonParts ?: return null
        return if (versionTrailing(Oracle3a.bytes(parts.tbs))) {
            "rule: content after the INTEGER inside [0]"
        } else {
            producerOutside(a, producer[read.canonSha256] ?: fail("${a.name}: no oracle-4 golden for canon"))
        }
    }

    private fun producerOutside(
        a: Accepted,
        golden: String,
    ): String? {
        if (!golden.startsWith("OK ")) return PRODUCER_REJECTS
        val (_, serial, spki) = golden.split(' ')
        val r = a.reference ?: return null
        return if (serial == r.serial && spki == sha(Oracle3a.bytes(r.spki))) null else "oracle 4 keys other bytes"
    }

    @Test
    fun `D1 - every platform-accepted input in the producer's domain parses`() {
        val dom = HashMap<String, Int>()
        val violations = ArrayList<String>()
        var inside = 0
        for (a in accepted) {
            val reason = outsideDomain(a)
            if (reason != null) {
                dom.merge(reason, 1, Int::plus)
            } else if (a.encoded?.canonParts != null) {
                inside++
                if (a.certificate == null) violations += "${a.name}: ${(a.parse as CertificateParse.Failed).detail}"
            }
        }
        println("D1 on JDK ${Oracle1.version}: ${accepted.size} platform-accepted, $inside in the domain; D1-dom $dom")
        assertEquals(emptyList(), violations, "D1 violations")
        assertTrue(inside > 300, "D1 exercised on only $inside inputs")
    }

    @Test
    fun `no platform-accepted input lacks a raw-byte reference, outside the unparsed inputs the producer cannot key`() {
        val missing =
            accepted
                .filter { it.reference == null }
                .filterNot { it.certificate == null && outsideDomain(it) in setOf(PRODUCER_REJECTS, NO_PLATFORM_CANON) }
                .map { it.name }
        assertEquals(emptyList(), missing, "platform-accepted inputs with no raw-byte reference")
    }

    @Test
    fun `D2 and D3 - on every parsed encoding revokt's fields equal canon, oracle 1 and the reference view`() {
        var compared = 0
        val unavailable = HashMap<String, Int>()
        val divergences = HashMap<String, MutableSet<String>>()
        val javaFields = ArrayList<String>()
        val reencoded = HashSet<String>()
        for (a in accepted) {
            val c = a.certificate ?: continue
            val r = a.reference ?: fail("${a.name}: revokt parses it and it has no raw-byte reference")
            val parts = a.encoded!!.canonParts ?: fail("${a.name}: revokt parses it and canon cannot be located")
            compared++
            assertEnvelope(a, c, parts, r)
            assertReference(a.name, c, r)
            r.divergences.forEach { divergences.getOrPut(it) { HashSet() } += a.name }
            if (Keyability.firstFailing(c) == null) assertProducerBytes(a, c)
            val (unavailableHere, differing) = Oracle1.compare(a.jdk, c).partition { it.unavailable }
            unavailableHere.forEach { unavailable.merge(it.name, 1, Int::plus) }
            for (f in differing.filter { it.mismatch != null }) {
                if (f.name == "spki" && reencodesSpki(a, c)) {
                    reencoded += a.name
                } else {
                    javaFields += "${a.name}: ${f.name}: ${f.mismatch}"
                }
            }
        }
        println("D2 on JDK ${Oracle1.version}: $compared compared; unavailable $unavailable; divergences $divergences")
        assertEquals(emptyList(), javaFields, "normalised Java fields that differ from oracle 1's")
        assertEquals(emptyMap(), unavailable, "oracle-1 getters that threw on the committed corpus")
        // The re-encoding allow-list (§9.2): the JDK re-encodes the non-minimal headers of an SPKI, outside the key the
        // BIT STRING encapsulates, and nothing else.
        val spkiMutants =
            accepted
                .filter { it.certificate != null && SPKI_PATH in it.name && "$SPKI_PATH/1:03~" !in it.name }
                .map { it.name }
        assertEquals(spkiMutants.toSet(), reencoded, "inputs whose SPKI the JDK re-encodes")
        assertEquals(DIVERGENCES, divergences, "D3 divergence classes")
        assertTrue(compared > 1000, "D2 exercised on only $compared inputs")
    }

    /** `Cert.tbs` against canon's first element and oracle 1's `getTBSCertificate()`; `Cert.sig` against canon's. */
    private fun assertEnvelope(
        a: Accepted,
        c: ParsedCertificate,
        parts: Oracle3b.Parts,
        r: ReferenceView,
    ) {
        assertEquals(parts.tbs, Oracle3a.hex(c.tbsBytes), "${a.name}: Cert.tbs against canon")
        assertEquals(
            Oracle3a.hex(a.jdk.tbsCertificate),
            Oracle3a.hex(c.tbsBytes),
            "${a.name}: Cert.tbs against oracle 1",
        )
        val signature = Oracle3a.cleared(parts.signature, r.unusedBits)
        assertEquals(signature, Oracle3a.hex(c.envelope.signature), "${a.name}: Cert.sig")
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
        val golden = producer[a.encoded!!.canonSha256] ?: fail("${a.name}: no oracle-4 golden for canon")
        val (status, serial, spki) = golden.split(' ')
        assertEquals("OK", status, "${a.name}: producerKeyable and oracle 4 answers $golden")
        assertEquals(serial, Oracle3a.hex(c.rawSerial()), "${a.name}: rawSerial against oracle 4")
        assertEquals(spki, sha(c.rawSpki()), "${a.name}: SHA-256(rawSpki) against oracle 4")
    }

    /** Whether oracle 1's `getPublicKey().getEncoded()` is revokt's `rawSpki` with every header minimal. */
    private fun reencodesSpki(
        a: Accepted,
        c: ParsedCertificate,
    ): Boolean = DerNode.parse(c.rawSpki()).encode().contentEquals(a.jdk.publicKey.encoded)

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
        assertTrue(resliced > 1000 && roundTrips > 1000, "D6 exercised on $resliced and $roundTrips inputs only")
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
        val shift = c.envelope.presentedTbs.content.start - headerLength(c.tbsBytes, 0)
        for (s in spans.filter { it.start >= headerLength(c.tbsBytes, 0) }) {
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

    private fun headerLength(
        b: ByteArray,
        p: Int,
    ): Int {
        val first = b[p + 1].toInt() and 0xff
        return if (first < 0x80) 2 else 2 + (first and 0x7f)
    }

    /** Whether the TBS's `[0]` holds more than its first element (any definite header form). */
    private fun versionTrailing(tbs: ByteArray): Boolean =
        runCatching {
            val p = headerLength(tbs, 0)
            if (tbs[p] != 0xa0.toByte()) return false
            val end = p + headerLength(tbs, p) + length(tbs, p)
            val q = p + headerLength(tbs, p)
            q + headerLength(tbs, q) + length(tbs, q) < end
        }.getOrDefault(false)

    private fun length(
        b: ByteArray,
        p: Int,
    ): Int {
        val first = b[p + 1].toInt() and 0xff
        if (first < 0x80) return first
        return (0 until (first and 0x7f)).fold(0) { n, i -> (n shl 8) or (b[p + 2 + i].toInt() and 0xff) }
    }

    private fun sha(b: ByteArray): String = b.toByteString().sha256().hex()

    private companion object {
        const val PRODUCER_REJECTS = "oracle 4 rejects"

        /** D1-dom by rule (spec §9.2 revision 39): the producer cannot key a TBS whose AlgorithmIdentifier is not located. */
        const val NO_PLATFORM_CANON = "rule: no platform canon"

        /**
         * The D3 divergence classes among the platform-accepted inputs of the committed corpus (spec §9.2 D2, D3). The
         * duplicate-extension class is absent: the JDK rejects duplicate extension OIDs (`Oracle3aTest` covers it on b).
         */
        val DIVERGENCES: Map<String, Set<String>> =
            mapOf(
                "3A_HEADER_LAX" to setOf("d3/sct-inner-44", "d3/sct-inner-1f04"),
                "3A_TBS_LAX" to
                    (listOf("primitive-3") + listOf("03", "23", "43", "63", "c3", "e3").map { "tag3-$it" })
                        .map { "d3/$it" }
                        .toSet(),
            )

        /** The length-mutant path of a header in the SPKI, its own included (`LengthMutants`). */
        const val SPKI_PATH = "/0:30/0:30/6:30"
    }
}
