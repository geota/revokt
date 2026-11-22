// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.FakeX509Certificate
import dev.revokt.ParseReason
import dev.revokt.PkixPki
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.engine.parse.oracle.Oracle1
import dev.revokt.engine.parse.producer.ProducerCorpus
import dev.revokt.engine.walker.CandidateIndex
import dev.revokt.testing.SplitMix64
import okio.ByteString.Companion.toByteString
import java.security.cert.CertificateEncodingException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Spec §9.2 "The read fallback" and §5.3 on [PlatformRead]: `getEncoded()` unless revokt's parse of it is
 * `ParseFailed(STRUCTURE)`, then the platform canon; `getEncoded()` where the canon cannot be built or a getter throws;
 * and the canon equal to oracle 1's independent `platformCanon` on every input.
 */
@OptIn(RevoktInternalApi::class)
class PlatformReadTest {
    /** A JDK-accepted input revokt's parser rejects: the TBS in indefinite form, with an 81-form serial length. */
    private val indefinite: ByteArray by lazy {
        ProducerCorpus.inputs.first { it.name == "envelope/letsencrypt.org-1/tbs-indefinite-serial-81" }.der
    }

    @Test
    fun `read a certificate revokt parses is read as getEncoded`() {
        val x509 = PkixPki.root("Read Root").x509
        val read = checkNotNull(PlatformRead.of(x509))
        assertSame(read.encoded, read.read)
        assertFalse(read.platformCanon)
        assertContentEquals(x509.encoded, read.read)
    }

    @Test
    fun `read a STRUCTURE getEncoded is read through the platform canon, which parses`() {
        val x509 = PkixPki.x509(indefinite)
        val encoded = x509.encoded
        val structure = assertIs<CertificateParse.Failed>(CertificateParser.parse(encoded))
        assertEquals(ParseReason.STRUCTURE, structure.reason)
        val read = checkNotNull(PlatformRead.of(x509))
        assertTrue(read.platformCanon)
        assertContentEquals(encoded, read.encoded)
        val expected = checkNotNull(Oracle1.platformCanon(x509.tbsCertificate, x509.signature)).canon()
        assertContentEquals(expected, read.read)
        val parsed = assertIs<CertificateParse.Parsed>(CertificateParser.parse(read.read))
        assertFalse(parsed.certificate.envelope.algorithmIdMismatch, "no AlgorithmIdMismatch on a minimal TBS AlgId")
    }

    @Test
    fun `read the identity keys stay over getEncoded, the engine's bytes are the bytes read`() {
        // §5.3: bytesHash is over the bytes read; the chain hash (0.3's cache key) is over getEncoded().
        val read = checkNotNull(PlatformRead.of(PkixPki.x509(indefinite)))
        val cert = CandidateIndex(emptyList()).cert(WalkerCertsForRead.parse(read.read))
        assertEquals(read.read.toByteString().sha256(), cert.bytesHash)
        assertFalse(read.encoded.contentEquals(read.read))
    }

    @Test
    fun `read getEncoded throwing or null has no bytes at all`() {
        assertNull(PlatformRead.of(FakeX509Certificate(encoded = { throw CertificateEncodingException("x") })))
        assertNull(PlatformRead.of(FakeX509Certificate(encoded = { null })))
    }

    @Test
    fun `read an interrupt from a getter keeps the flag`() {
        try {
            assertNull(PlatformRead.of(FakeX509Certificate(encoded = { throw InterruptedException() })))
            assertTrue(Thread.interrupted())
            val structure = byteArrayOf(0x30, 0x00)
            val tbsInterrupted = FakeX509Certificate(encoded = { structure }, tbs = { throw InterruptedException() })
            assertSame(structure, checkNotNull(PlatformRead.of(tbsInterrupted)).read)
            assertTrue(Thread.interrupted())
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `read a canon that cannot be built leaves getEncoded`() {
        val structure = byteArrayOf(0x30, 0x00)
        val throwing = FakeX509Certificate(encoded = { structure }, tbs = { throw CertificateEncodingException("x") })
        assertSame(structure, checkNotNull(PlatformRead.of(throwing)).read)
        val sigThrows =
            FakeX509Certificate(encoded = { structure }, tbs = { tbs() }, sig = { throw IllegalStateException() })
        assertSame(structure, checkNotNull(PlatformRead.of(sigThrows)).read)
        val nulls = FakeX509Certificate(encoded = { structure }, tbs = { null }, sig = { byteArrayOf(1) })
        assertSame(structure, checkNotNull(PlatformRead.of(nulls)).read)
        val nullSig = FakeX509Certificate(encoded = { structure }, tbs = { tbs() }, sig = { null })
        assertSame(structure, checkNotNull(PlatformRead.of(nullSig)).read)
        val unlocated =
            FakeX509Certificate(encoded = { structure }, tbs = { TestDer.bytes(0x30, 0x80) }, sig = { byteArrayOf(1) })
        assertSame(structure, checkNotNull(PlatformRead.of(unlocated)).read)
    }

    @Test
    fun `read only STRUCTURE takes the canon, and an oversize getEncoded is never re-read`() {
        var calls = 0
        val oversize = ByteArray(RevoktLimits.MAX_CERT_BYTES + 1)
        val big =
            FakeX509Certificate(encoded = { oversize }, tbs = {
                calls++
                tbs()
            }, sig = { byteArrayOf(1) })
        assertSame(oversize, checkNotNull(PlatformRead.of(big)).read)
        val atCap = ByteArray(RevoktLimits.MAX_CERT_BYTES)
        val capped =
            FakeX509Certificate(encoded = { atCap }, tbs = {
                calls++
                tbs()
            }, sig = { byteArrayOf(1) })
        assertTrue(checkNotNull(PlatformRead.of(capped)).platformCanon, "at the cap, a STRUCTURE read takes the canon")
        assertEquals(1, calls, "the oversize certificate's getters were not called")
    }

    @Test
    fun `read the canon is oracle 1's platform canon on generated and mutated TBS bytes`() {
        val rng = SplitMix64(127)
        val base = PkixPki.x509(indefinite).tbsCertificate
        val inputs =
            buildList {
                add(base)
                add(tbs())
                add(ByteArray(0))
                add(byteArrayOf(0x30))
                repeat(4000) {
                    val b =
                        if (rng.nextBoolean()) {
                            base.copyOf()
                        } else {
                            ByteArray(
                                rng.nextInt(64),
                            ) { rng.nextInt().toByte() }
                        }
                    repeat(1 + rng.nextInt(4)) {
                        if (b.isNotEmpty()) b[rng.nextInt(b.size)] = interesting(rng)
                    }
                    add(if (rng.nextInt(8) == 0 && b.size > 2) b.copyOf(rng.nextInt(b.size)) else b)
                }
            }
        var located = 0
        for (tbs in inputs) {
            val sig = byteArrayOf(1, 2, 3)
            val ours = PlatformRead.canon(tbs, sig)
            val oracle = Oracle1.platformCanon(tbs, sig)?.canon()
            assertEquals(oracle?.toByteString(), ours?.toByteString(), tbs.toByteString().hex())
            if (ours != null) located++
        }
        assertTrue(located > 100, "$located located")
    }

    private fun interesting(rng: SplitMix64): Byte =
        listOf(0x30, 0xa0, 0x80, 0x81, 0x84, 0x85, 0xff, 0x00, 0x02, 0x7f)[rng.nextInt(10)].toByte()

    /** A minimal TBS: `[0] { 2 }`, a serial, the AlgorithmIdentifier, and nothing else. */
    private fun tbs(): ByteArray =
        TestDer.seq(
            TestDer.tlv(0xa0, TestDer.tlv(0x02, TestDer.bytes(2))),
            TestDer.tlv(0x02, TestDer.bytes(1)),
            TestDer.seq(TestDer.oid("1.2.840.10045.4.3.2")),
        )

    private object WalkerCertsForRead {
        fun parse(der: ByteArray): ParsedCertificate =
            (CertificateParser.parse(der) as CertificateParse.Parsed).certificate
    }
}
