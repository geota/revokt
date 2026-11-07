// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.engine.walker.CandidateIndex

/**
 * Spec §9.1 target "the TBS/DER parser", §9.2 D5 and D6: the parser's only results are `Parsed` and `Failed`; a parse
 * stays within 8·len + 1024 steps; every span lies inside the input and every TLV span re-reads to itself; two parses
 * of the same input agree; the walker's view of a parsed certificate (`CandidateIndex.cert`: `Cert.of` and the §9.2
 * keyability profile, which decision step 3 runs on every presented leaf) never throws and agrees with itself. With `JAZZER_FUZZ` unset JUnit replays `CertificateParserFuzzTestInputs/`; the nightly job
 * runs it with `-max_len=262145 -timeout=1`.
 */
class CertificateParserFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun parse(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        /** An empty index: only its canonicaliser (the platform's, §3) is used, to build each `Cert`. */
        private val index = CandidateIndex(emptyList())

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            val first = CertificateParser.parse(data)
            val second = CertificateParser.parse(data)
            if (first is CertificateParse.Parsed) {
                val c = first.certificate
                check(c.steps <= 8L * data.size + 1024) { "D5: ${c.steps} steps for ${data.size} bytes" }
                check(
                    second is CertificateParse.Parsed && sameFields(c, second.certificate),
                ) { "D6: second parse differs" }
                val tbs = c.tbsBytes
                val spans =
                    listOf(c.tbs.tlv, c.tbs.signature, c.tbs.issuer, c.tbs.subject, c.tbs.spki) +
                        c.tbs.extensions.map { it.tlv }
                for (span in listOfNotNull(c.fields.ski, c.fields.akiKeyId)) {
                    check(span.start >= 0 && span.start <= span.end && span.end <= tbs.size) {
                        "D6: key id span $span outside ${tbs.size} bytes"
                    }
                }
                for (span in spans) {
                    check(span.start >= 0 && span.end <= tbs.size) { "D6: span $span outside ${tbs.size} bytes" }
                    val again = DerReader(tbs, span.start, span.end, ParseContext()).readAny(HeaderSite.CERTIFICATE)
                    check(again.tlv == span) { "D6: TLV at $span re-reads to ${again.tlv}" }
                }
                val outer = c.envelope.signatureAlgorithm
                check(outer.start >= 0 && outer.end <= data.size) { "D6: span $outer outside ${data.size} bytes" }
                val cert = index.cert(c)
                check(cert.canonicalIssuer == index.cert(c).canonicalIssuer) { "walker view: canonical issuer differs" }
                check(cert.keyabilityClause == Keyability.firstFailing(c)) { "walker view: keyability differs" }
                check(cert.producerKeyable == (cert.keyabilityClause == null)) { "walker view: producerKeyable" }
            } else {
                first as CertificateParse.Failed
                check(
                    second is CertificateParse.Failed && second.reason == first.reason && second.detail == first.detail,
                ) {
                    "D6: second parse differs"
                }
            }
        }

        private fun sameFields(
            a: ParsedCertificate,
            b: ParsedCertificate,
        ): Boolean = sameEnvelope(a, b) && sameTbs(a.tbs, b.tbs) && sameRecords(a, b)

        private fun sameEnvelope(
            a: ParsedCertificate,
            b: ParsedCertificate,
        ): Boolean =
            a.tbsBytes.contentEquals(b.tbsBytes) && a.envelope.signature.contentEquals(b.envelope.signature) &&
                a.envelope.algorithmIdMismatch == b.envelope.algorithmIdMismatch

        private fun sameTbs(
            a: Tbs,
            b: Tbs,
        ): Boolean =
            a.tlv == b.tlv && a.serial == b.serial && a.spki == b.spki && a.subject == b.subject &&
                a.issuer == b.issuer &&
                a.extensions.map { it.tlv } == b.extensions.map { it.tlv } &&
                a.validity.notBeforeMillis == b.validity.notBeforeMillis &&
                a.validity.notAfterMillis == b.validity.notAfterMillis

        private fun sameRecords(
            a: ParsedCertificate,
            b: ParsedCertificate,
        ): Boolean =
            a.nonMinimalHeaders.map { it.offset } == b.nonMinimalHeaders.map { it.offset } &&
                a.ignoredElements.map { it.span } == b.ignoredElements.map { it.span } &&
                a.fields.scts == b.fields.scts && a.fields.ski == b.fields.ski && a.fields.akiKeyId == b.fields.akiKeyId
    }
}
