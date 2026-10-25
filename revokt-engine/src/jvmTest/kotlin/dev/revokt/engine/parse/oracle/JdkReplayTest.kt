// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.oracle

import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.TestDer.ascii
import dev.revokt.engine.parse.TestDer.bytes
import dev.revokt.engine.parse.TestDer.oid
import dev.revokt.engine.parse.TestDer.seq
import dev.revokt.engine.parse.TestDer.tlv
import dev.revokt.engine.parse.producer.ProducerCorpus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The replay against oracle 1, the test JDK's `SUN` factory: run it on every matrix JDK with `-Prevokt.testJdk`. It adds
 * what only oracle 1 has: the read fallback of spec §9.2 revision 39, and the SPKI re-encoding rule's own cases.
 */
class JdkReplayTest : PlatformReplayTest(PlatformReplay.jdk, d1Floor = 300, d2Floor = 1000, d6Floor = 1000) {
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

    @Test
    fun `the second re-encoding rule allows only NULL parameters added to an AlgorithmIdentifier that has none`() {
        fun spki(
            alg: ByteArray,
            bits: ByteArray,
        ) = seq(alg, tlv(0x03, bytes(0), bits))
        val mlDsa = oid("2.16.840.1.101.3.4.3.17")
        val raw = spki(seq(mlDsa), bytes(1, 2, 3))
        assertTrue(PlatformReplay.addsNullParameters(raw, spki(seq(mlDsa, tlv(0x05)), bytes(1, 2, 3))), "NULL added")
        assertEquals(false, PlatformReplay.addsNullParameters(raw, raw), "the same bytes are no re-encoding")
        assertEquals(
            false,
            PlatformReplay.addsNullParameters(raw, spki(seq(oid("1.3.101.112"), tlv(0x05)), bytes(1, 2, 3))),
            "another OID",
        )
        assertEquals(
            false,
            PlatformReplay.addsNullParameters(raw, spki(seq(mlDsa, tlv(0x05)), bytes(1, 2, 4))),
            "other key bits",
        )
        assertEquals(
            false,
            PlatformReplay.addsNullParameters(raw, spki(seq(mlDsa, tlv(0x06, bytes(1))), bytes(1, 2, 3))),
            "parameters other than NULL",
        )
        val withParams = spki(seq(mlDsa, tlv(0x05)), bytes(1, 2, 3))
        assertEquals(false, PlatformReplay.addsNullParameters(withParams, withParams), "parameters already present")
        // The bytes JDK 17.0.20.1 returns for x509-limbo's rfc9881::ml-dsa-44 leaf (spec Appendix A, revision 41 probes).
        val real = ProducerCorpus.resource("oracle/ml-dsa-44-spki.der")
        val jdk17020 = ProducerCorpus.resource("oracle/ml-dsa-44-spki-jdk-17.0.20.1.der")
        assertTrue(PlatformReplay.addsNullParameters(real, jdk17020), "JDK 17.0.20.1's generic key")
        assertEquals(false, PlatformReplay.reencodesSpki(real, jdk17020), "not the first rule's minimal re-encoding")
    }

    @Test
    fun `a time divergence is only a dropped UTCTime differential where revokt equals the JDK`() {
        val hour = 3_600_000L
        val utc = { s: String -> tlv(0x17, ascii(s)) }
        val revokt = 1_792_673_130_000 // 2026-10-22T12:45:30Z, 261022134530+0100 as the JDK reads it
        assertTrue(PlatformReplay.droppedDifferential(utc("261022134530+0100"), revokt, revokt + hour, revokt))
        // 2610221345-0130: local 13:45 is 15:15Z as the JDK reads it, 13:45Z with the differential dropped.
        val negative = 1_792_682_100_000
        assertTrue(
            PlatformReplay.droppedDifferential(utc("2610221345-0130"), negative, negative - 90 * 60_000L, negative),
        )
        assertEquals(
            false,
            PlatformReplay.droppedDifferential(utc("261022134530+0100"), revokt, revokt + 2 * hour, revokt),
        )
        assertEquals(
            false,
            PlatformReplay.droppedDifferential(
                utc("261022134530+0100"),
                revokt,
                revokt + hour,
                revokt + 1,
            ),
        )
        assertEquals(false, PlatformReplay.droppedDifferential(utc("261022134530Z"), revokt, revokt + hour, revokt))
        assertEquals(
            false,
            PlatformReplay.droppedDifferential(tlv(0x18, ascii("20261022134530+0100")), revokt, revokt + hour, revokt),
            "a GeneralizedTime",
        )
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
