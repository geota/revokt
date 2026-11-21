// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer

/**
 * Spec §9.1 target for the walker's name-constraint readers, which read server bytes: the first octet splits the
 * rest into a nameConstraints `extnValue` content and a second part, which is both a subjectAltName `extnValue`
 * content and the content of the certificate's subject. Checked:
 *
 * - [NameConstraints.read] and [PresentedName.of], with and without a subjectAltName and with and without the CN-ID,
 *   return or fail closed, never throw; the subject is always presented; without a subjectAltName the names after it
 *   are emailAddress attributes; the CN-ID adds at most one dNSName or iPAddress, and never beside a subjectAltName
 *   dNSName or iPAddress.
 * - A check never makes more comparisons than its budget allows, says `EXHAUSTED` only when the budget ran out and
 *   otherwise answers as with no budget; an unreadable name list is a violation.
 * - On the two halves of the second part: [DnsNameConstraint], [DirectoryNameConstraint] and [Rfc822NameConstraint]
 *   never throw; a Name is never outside itself, and none is outside the empty Name; a valid mailbox holds one `@` and
 *   matches itself; an IPv4 address [SubjectNames.ipv4] reads prints back as its input.
 *
 * With `JAZZER_FUZZ` unset JUnit replays `NameConstraintsFuzzTestInputs/`; the nightly job runs it with
 * `-max_len=65537`.
 */
class NameConstraintsFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun match(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private const val BUDGET = 4_096
        private const val SMALL_BUDGET = 8

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            if (data.isEmpty()) return
            val split = (data[0].toInt() and 0xff).coerceAtMost(data.size - 1)
            val ncValue = data.copyOfRange(1, 1 + split)
            val rest = data.copyOfRange(1 + split, data.size)
            val nc = NameConstraints.read(ncValue, Span(0, ncValue.size))
            val subject = TestDer.tlv(0x30, rest)
            val withSan = parse(TestCert(subject = subject, extensions = listOf(TestDer.extension("2.5.29.17", rest))))
            val withoutSan = parse(TestCert(subject = subject, extensions = emptyList()))
            for (p in listOfNotNull(withSan, withoutSan)) {
                val names = PresentedName.of(p, commonName = false)
                val asLeaf = PresentedName.of(p, commonName = true)
                names(p, names, asLeaf)
                for (list in listOf(names, asLeaf)) {
                    for (constraints in listOfNotNull(nc, NameConstraints.UNREADABLE)) budgeted(constraints, list)
                }
            }
            halves(rest)
        }

        private fun parse(t: TestCert): ParsedCertificate? {
            val der = t.der
            val parsed = CertificateParser.parse(der) as? CertificateParse.Parsed
            if (parsed ==
                null
            ) {
                check(der.size > RevoktLimits.MAX_CERT_BYTES) { "the wrapping certificate does not parse" }
            }
            return parsed?.certificate
        }

        private fun names(
            p: ParsedCertificate,
            names: List<PresentedName>?,
            asLeaf: List<PresentedName>?,
        ) {
            if (names == null) {
                check(asLeaf == null) { "the CN-ID made an unreadable certificate readable" }
                return
            }
            val subject = p.rawSubject()
            val at = names.indexOfFirst { it is PresentedName.Directory && it.name.contentEquals(subject) }
            check(at >= 0) { "the subject is not presented" }
            if (p.extensions("2.5.29.17").isEmpty()) {
                check(at == 0) { "names before the subject without a subjectAltName" }
                check(names.drop(1).all { it is PresentedName.Rfc822 }) { "a non-email name from the subject" }
            }
            if (asLeaf == null) return
            check(asLeaf.size - names.size in 0..1) { "more than one CN-ID" }
            if (asLeaf.size > names.size) {
                check(
                    asLeaf.last().let { it is PresentedName.Dns || it is PresentedName.Ip },
                ) { "a CN-ID of another form" }
                check(
                    names.none { it is PresentedName.Dns || it is PresentedName.Ip },
                ) { "a CN-ID beside a SAN DNS or IP" }
            }
        }

        private fun budgeted(
            constraints: NameConstraints,
            names: List<PresentedName>?,
        ) {
            var used = 0
            val limited = constraints.check(names) { if (used >= BUDGET) false else true.also { used++ } }
            val unlimited = constraints.check(names) { true }
            check(used <= BUDGET) { "the budget was overspent" }
            check(unlimited != NameConstraints.Result.EXHAUSTED) { "an unlimited budget ran out" }
            if (limited == NameConstraints.Result.EXHAUSTED) {
                check(used == BUDGET) { "EXHAUSTED with budget left" }
            } else {
                check(limited == unlimited) { "the budget changed the answer" }
            }
            if (names ==
                null
            ) {
                check(unlimited == NameConstraints.Result.VIOLATION) { "an unreadable name list conforms" }
            }
        }

        private fun halves(rest: ByteArray) {
            val half = rest.size / 2
            val a = rest.copyOfRange(0, half)
            val b = rest.copyOfRange(half, rest.size)
            for (excluded in listOf(false, true)) {
                DnsNameConstraint.matches(a, b, excluded)
                Rfc822NameConstraint.matches(a, b, excluded)
            }
            val unlimited = ComparisonBudget { true }
            var used = 0
            val limited =
                DirectoryNameConstraint.permits(a, b) {
                    if (used >=
                        SMALL_BUDGET
                    ) {
                        false
                    } else {
                        true.also { used++ }
                    }
                }
            val full = DirectoryNameConstraint.permits(a, b, unlimited)
            check(full != NameMatch.EXHAUSTED) { "an unlimited Name comparison ran out" }
            check(limited == full || (limited == NameMatch.EXHAUSTED && used == SMALL_BUDGET)) {
                "the budget changed a Name answer"
            }
            check(DirectoryNameConstraint.permits(a, a, unlimited) != NameMatch.NO) { "a Name outside itself" }
            check(
                DirectoryNameConstraint.permits(a, TestDer.seq(), unlimited) != NameMatch.NO,
            ) { "outside the empty Name" }
            if (Rfc822NameConstraint.valid(a)) {
                check(a.count { it == '@'.code.toByte() } == 1) { "a valid mailbox without exactly one @" }
                check(Rfc822NameConstraint.matches(a, a, excluded = false) == true) { "a mailbox outside itself" }
            }
            SubjectNames.ipv4(a)?.let { ip ->
                val printed = ip.joinToString(".") { (it.toInt() and 0xff).toString() }.encodeToByteArray()
                check(printed.contentEquals(a)) { "an IPv4 address that does not print back" }
            }
        }
    }
}
