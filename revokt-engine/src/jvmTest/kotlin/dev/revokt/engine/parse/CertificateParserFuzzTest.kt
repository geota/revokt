// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import com.code_intelligence.jazzer.junit.FuzzTest

/**
 * Spec §9.1 target "the TBS/DER parser", §9.2 D5 and D6: the parser's only results are `Parsed` and `Failed`; a parse
 * stays within 8·len + 1024 steps; every span lies inside the input and every TLV span re-reads to itself; two parses
 * of the same input agree. With `JAZZER_FUZZ` unset JUnit replays `CertificateParserFuzzTestInputs/`; the nightly job
 * runs it with `-max_len=262145 -timeout=1`.
 */
class CertificateParserFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun parse(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
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
                val spans =
                    listOf(c.tbs.tlv, c.tbs.signature, c.tbs.issuer, c.tbs.subject, c.tbs.spki, c.signatureAlgorithm) +
                        c.tbs.extensions.map { it.tlv }
                for (span in spans) {
                    check(span.start >= 0 && span.end <= data.size) { "D6: span $span outside ${data.size} bytes" }
                    val again = DerReader(data, span.start, span.end, ParseContext()).readAny(HeaderSite.CERTIFICATE)
                    check(again.tlv == span) { "D6: TLV at $span re-reads to ${again.tlv}" }
                }
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
        ): Boolean =
            a.tbs.tlv == b.tbs.tlv && a.tbs.serial == b.tbs.serial && a.tbs.spki == b.tbs.spki &&
                a.tbs.subject == b.tbs.subject &&
                a.tbs.issuer == b.tbs.issuer && a.tbs.extensions.map { it.tlv } == b.tbs.extensions.map { it.tlv } &&
                a.tbs.validity.notBeforeMillis == b.tbs.validity.notBeforeMillis &&
                a.tbs.validity.notAfterMillis == b.tbs.validity.notAfterMillis &&
                a.nonMinimalHeaders.map { it.offset } == b.nonMinimalHeaders.map { it.offset } &&
                a.ignoredElements.map { it.span } == b.ignoredElements.map { it.span }
    }
}
