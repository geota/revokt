// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.producer.ProducerCorpus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The replay against oracle 1, the test JDK's `SUN` factory: run it on every matrix JDK with `-Prevokt.testJdk`. It adds
 * what only oracle 1 has: the read fallback of spec §9.2 revision 39, and the SPKI re-encoding rule's own cases.
 */
class JdkReplayTest : PlatformReplayTest(PlatformReplay.jdk, floor = 300, tbsDivergence = null) {
    private val accepted get() = PlatformReplay.jdk.accepted

    /**
     * The read fallback (spec §9.2 revision 39) is pinned: the nine indefinite-TBS inputs on every matrix JDK are read
     * through the platform canon and parse, each platform canon is its own `canon` as the reference view locates it, and
     * no platform-canon read reports an `AlgorithmIdMismatch` (their TBS AlgorithmIdentifiers are minimal DER).
     */
    @Test
    fun `the read fallback parses the nine indefinite-TBS inputs through their platform canon`() {
        val fallback = accepted.filter { it.platformCanon }
        assertEquals(FALLBACK_PARSED, fallback.filter { it.certificate != null }.map { it.name }.toSet())
        for (a in fallback) {
            val read = a.readInput
            read.referenceParts?.canon()?.let { located ->
                assertEquals(Oracle3a.hex(read.der), Oracle3a.hex(located), "${a.name}: canon of its canon")
            }
            a.certificate?.let {
                assertEquals(
                    false,
                    it.envelope.algorithmIdMismatch,
                    "${a.name}: AlgorithmIdMismatch",
                )
            }
        }
        assertTrue(fallback.count { it.readInput.referenceParts != null } >= FALLBACK_PARSED.size, "canon checked")
    }

    @Test
    fun `the SPKI re-encoding rule allows only a minimal re-encoding of the same key`() {
        val keys =
            listOf("letsencrypt.org-1", "www.mozilla.org-1").map {
                val c =
                    (
                        CertificateParser.parse(
                            ProducerCorpus.resource("certs/$it.der"),
                        ) as CertificateParse.Parsed
                    ).certificate
                c.rawSpki()
            }
        assertTrue(PlatformReplay.reencodesSpki(keys[0], keys[0]), "the same minimal SPKI")
        assertEquals(false, PlatformReplay.reencodesSpki(keys[0], keys[1]), "another key")
        assertEquals(false, PlatformReplay.reencodesSpki(keys[1], keys[0]), "another key, RSA against EC")
    }

    private companion object {
        /** The inputs read through the platform canon that parse, on every matrix JDK (spec §9.2 revision 39). */
        val FALLBACK_PARSED: Set<String> =
            ProducerCorpus.envelopeLeaves
                .flatMap { (leaf, _) ->
                    listOf("serial-81", "serial-84", "spki-83").map { "envelope/$leaf/tbs-indefinite-$it" }
                }.toSet()
    }
}
