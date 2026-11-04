// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.testing

import dev.revokt.VerifyResult
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.TestDer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The §9.1 `SymVerifier`: exactly the links in `ok`, and `UNSUPPORTED` wherever the probe's OIDs appear. */
class SymVerifierTest {
    private fun parsed(der: ByteArray): ParsedCertificate =
        (CertificateParser.parse(der) as CertificateParse.Parsed).certificate

    private fun ParsedCertificate.sigAlg(): ByteArray = tbs.signature.bytes(tbsBytes)

    private fun oids(
        c: ParsedCertificate,
        spki: ByteArray,
    ): List<String> = listOfNotNull(SymVerifier.algorithmOid(c.sigAlg())?.first) + SymVerifier.spkiOids(spki)

    @Test
    fun `verifies exactly the links in ok`() {
        val mutations = listOf(Recover(0, 0), Loop(1), SameKeyDecoy(0), Stuff(5, related = true))
        val world = ChainGenerator.generate(7, mutations, depth = 3, anchors = 12)
        val verifier = world.verifier()
        val certs = world.certificates.map(::parsed)
        val keys = certs.map { it.rawSpki() }.distinctBy { KeyId.of(it) }
        var verified = 0
        // Every certificate the world issued under every key it holds: each link of ok, and every other pair.
        for (c in certs) {
            for (k in keys) {
                val expected =
                    when {
                        oids(c, k).any { it in world.unsupported } -> VerifyResult.UNSUPPORTED
                        CertId.of(c.tbsBytes) to KeyId.of(k) in world.ok -> VerifyResult.VERIFIED
                        else -> VerifyResult.INVALID
                    }
                val actual = verifier.verify(c.sigAlg(), k, c.tbsBytes, c.envelope.signature)
                assertEquals(expected, actual, "serial ${c.rawSerial().toList()}")
                if (actual == VerifyResult.VERIFIED) verified++
            }
        }
        assertTrue(verified > world.presented.size, "$verified links verified")
    }

    @Test
    fun `reports UNSUPPORTED for the signature, key and curve OIDs, before ok`() {
        val model = WorldModel(seed = 1, keyIdentifiers = false)
        val name = SymName("CA")
        val keys =
            mapOf(
                SymOids.KEY to model.freshKey(),
                SymOids.UNSUPPORTED_KEY to model.freshKey(keyOid = SymOids.UNSUPPORTED_KEY),
                SymOids.UNSUPPORTED_CURVE to model.freshKey(curveOid = SymOids.UNSUPPORTED_CURVE),
            )
        val links =
            keys.flatMap { (keyOid, key) ->
                listOf(SymOids.SIGNATURE, SymOids.UNSUPPORTED_SIGNATURE).map { sigOid ->
                    Triple(keyOid, sigOid, model.issue(name, name, key, key, sigOid))
                }
            }
        for ((keyOid, sigOid, cert) in links) {
            val p = parsed(cert.der)
            for (unsupported in listOf(emptySet(), setOf(keyOid), setOf(sigOid), SymOids.UNSUPPORTED)) {
                val v = SymVerifier(setOf(cert.id to cert.key.id), unsupported)
                val probed = keyOid in unsupported || sigOid in unsupported
                val expected = if (probed) VerifyResult.UNSUPPORTED else VerifyResult.VERIFIED
                val actual = v.verify(p.sigAlg(), p.rawSpki(), p.tbsBytes, p.envelope.signature)
                assertEquals(expected, actual, "$keyOid $sigOid $unsupported")
                assertEquals(unsupported, v.unsupportedOids())
            }
        }
        // A link outside ok under supported OIDs is INVALID.
        val other = parsed(model.issue(name, name, keys.getValue(SymOids.KEY), null).der)
        val v = SymVerifier(emptySet(), SymOids.UNSUPPORTED)
        assertEquals(VerifyResult.INVALID, v.verify(other.sigAlg(), other.rawSpki(), other.tbsBytes, ByteArray(0)))
    }

    @Test
    fun `inputs that are not an AlgorithmIdentifier or an SPKI carry no OID and never throw`() {
        val key = TestDer.seq(TestDer.oid(SymOids.UNSUPPORTED_KEY))
        val message = TestDer.bytes(1, 2, 3)
        val v = SymVerifier(setOf(CertId.of(message) to KeyId.of(key)), SymOids.UNSUPPORTED)
        assertEquals(VerifyResult.VERIFIED, v.verify(ByteArray(0), key, message, ByteArray(0)))
        assertEquals(
            VerifyResult.INVALID,
            v.verify(TestDer.bytes(0x30, 0x05), TestDer.bytes(0xff), message, ByteArray(0)),
        )
        val unsupportedSig = TestDer.seq(TestDer.oid(SymOids.UNSUPPORTED_SIGNATURE))
        assertEquals(VerifyResult.UNSUPPORTED, v.verify(unsupportedSig, key, message, ByteArray(0)))
    }
}
