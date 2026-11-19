// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import com.code_intelligence.jazzer.junit.FuzzTest
import dev.revokt.RevoktLimits
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer

/**
 * Spec §9.1 target for #237's name-constraint readers, which read server bytes: the first octet splits the rest into
 * a nameConstraints `extnValue` content and a subjectAltName one. [NameConstraints.read] and [PresentedName.of]
 * return or fail closed, never throw; a check never makes more comparisons than its budget allows, says
 * `EXHAUSTED` only when the budget ran out and otherwise answers as with no budget; an unreadable subjectAltName is a
 * violation; and [DnsNameConstraint] never throws on any pair of names cut from the input. With `JAZZER_FUZZ` unset JUnit replays
 * `NameConstraintsFuzzTestInputs/`; the nightly job runs it with `-max_len=65537`.
 */
class NameConstraintsFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun match(data: ByteArray) {
        fuzzerTestOneInput(data)
    }

    companion object {
        private const val BUDGET = 4_096

        /** The static entry point ClusterFuzzLite drives (CONTRIBUTING §6). */
        @JvmStatic
        fun fuzzerTestOneInput(data: ByteArray) {
            if (data.isEmpty()) return
            val split = (data[0].toInt() and 0xff).coerceAtMost(data.size - 1)
            val ncValue = data.copyOfRange(1, 1 + split)
            val sanValue = data.copyOfRange(1 + split, data.size)
            val nc = NameConstraints.read(ncValue, Span(0, ncValue.size))
            val der = TestCert(extensions = listOf(TestDer.extension("2.5.29.17", sanValue))).der
            val parsed = CertificateParser.parse(der) as? CertificateParse.Parsed
            if (parsed == null) {
                check(der.size > RevoktLimits.MAX_CERT_BYTES) { "the wrapping certificate does not parse" }
                return
            }
            val names = PresentedName.of(parsed.certificate)
            names?.let { check(it.last() == PresentedName.Directory) { "the subject is the last name" } }
            for (constraints in listOfNotNull(nc, NameConstraints.UNREADABLE)) {
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
                if (names == null) check(unlimited == NameConstraints.Result.VIOLATION) { "an unreadable SAN conforms" }
            }
            val half = sanValue.size / 2
            for (excluded in listOf(false, true)) {
                DnsNameConstraint.matches(
                    sanValue.copyOfRange(0, half),
                    sanValue.copyOfRange(half, sanValue.size),
                    excluded,
                )
            }
        }
    }
}
