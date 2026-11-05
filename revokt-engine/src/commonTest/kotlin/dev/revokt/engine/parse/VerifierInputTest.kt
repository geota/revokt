// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Spec §3 "Verifier contract" and §9.1 target "`AlgorithmIdentifier`/PSS parameters": the verifier's readers. */
class VerifierInputTest {
    private val sha256 = "2.16.840.1.101.3.4.2.1"
    private val sha384 = "2.16.840.1.101.3.4.2.2"
    private val nul = TestDer.bytes(0x05, 0x00)

    private fun alg(
        oid: String,
        vararg parameters: ByteArray,
    ): ByteArray = TestDer.seq(TestDer.oid(oid), *parameters)

    private fun int(vararg content: Int): ByteArray = TestDer.tlv(0x02, TestDer.bytes(*content))

    private fun field(
        index: Int,
        content: ByteArray,
    ): ByteArray = TestDer.tlv(0xa0 + index, content)

    private fun mgf1(hash: ByteArray): ByteArray = alg(VerifierInput.MGF1, hash)

    private fun pss(vararg fields: ByteArray): PssParameters? = VerifierInput.pss(TestDer.seq(*fields))

    @Test
    fun `verifier algorithm identifier with and without parameters`() {
        val bare = assertNotNull(VerifierInput.algorithm(alg("1.2.840.10045.4.3.2")))
        assertEquals("1.2.840.10045.4.3.2", bare.oid)
        assertNull(bare.parameters)
        assertNull(bare.parametersOid)
        assertTrue(bare.noParameters)
        val withNull = assertNotNull(VerifierInput.algorithm(alg("1.2.840.113549.1.1.11", nul)))
        assertContentEquals(nul, withNull.parameters)
        assertTrue(withNull.noParameters)
        val curve = assertNotNull(VerifierInput.algorithm(alg("1.2.840.10045.2.1", TestDer.oid("1.3.132.0.34"))))
        assertEquals("1.3.132.0.34", curve.parametersOid)
        assertEquals(false, curve.noParameters)
        val integer = assertNotNull(VerifierInput.algorithm(alg("1.2.3", int(0))))
        assertNull(integer.parametersOid)
        assertEquals(false, integer.noParameters)
        val badCurve = assertNotNull(VerifierInput.algorithm(alg("1.2.3", TestDer.tlv(0x06, TestDer.bytes(0x81)))))
        assertNull(badCurve.parametersOid, "an undecodable parameters OID")
    }

    @Test
    fun `verifier algorithm identifier malformed`() {
        val bad =
            listOf(
                ByteArray(0),
                TestDer.bytes(0x30, 0x00),
                TestDer.seq(nul),
                TestDer.seq(TestDer.tlv(0x06)),
                TestDer.seq(TestDer.tlv(0x06, TestDer.bytes(0x2a, 0x81))),
                alg("1.2.3", nul, nul),
                alg("1.2.3") + TestDer.bytes(0x00),
                TestDer.tlv(0x31, TestDer.oid("1.2.3")),
                TestDer.bytes(0x30, 0x05, 0x06, 0x01),
            )
        for (b in bad) {
            assertNull(
                VerifierInput.algorithm(b),
                b.joinToString(" ") { (it.toInt() and 0xff).toString(16) },
            )
        }
    }

    @Test
    fun `verifier SPKI algorithm`() {
        val key =
            TestDer.seq(
                alg("1.2.840.10045.2.1", TestDer.oid("1.2.840.10045.3.1.7")),
                TestDer.tlv(0x03, TestDer.bytes(0, 4)),
            )
        val read = assertNotNull(VerifierInput.spkiAlgorithm(key))
        assertEquals("1.2.840.10045.2.1", read.oid)
        assertEquals("1.2.840.10045.3.1.7", read.parametersOid)
        val bad =
            listOf(
                ByteArray(0),
                key + TestDer.bytes(0x00),
                TestDer.seq(alg("1.2.3")),
                TestDer.seq(alg("1.2.3"), TestDer.tlv(0x04, TestDer.bytes(0))),
                TestDer.seq(alg("1.2.3"), TestDer.tlv(0x03, TestDer.bytes(0)), nul),
                TestDer.seq(TestDer.seq(TestDer.tlv(0x06)), TestDer.tlv(0x03, TestDer.bytes(0))),
            )
        for (b in bad) assertNull(VerifierInput.spkiAlgorithm(b))
    }

    @Test
    fun `verifier PSS parameters defaults`() {
        val p = assertNotNull(pss())
        assertEquals(VerifierInput.SHA1, p.hashOid)
        assertEquals(VerifierInput.SHA1, p.mgfHashOid)
        assertEquals(20, p.saltLength)
        assertEquals(1, p.trailerField)
        val hashOnly = assertNotNull(pss(field(0, alg(sha256))))
        assertEquals(sha256, hashOnly.hashOid)
        assertEquals(VerifierInput.SHA1, hashOnly.mgfHashOid)
        assertEquals(20, hashOnly.saltLength)
    }

    @Test
    fun `verifier PSS parameters explicit`() {
        val p =
            assertNotNull(
                pss(field(0, alg(sha256, nul)), field(1, mgf1(alg(sha384))), field(2, int(0x20)), field(3, int(1))),
            )
        assertEquals(sha256, p.hashOid)
        assertEquals(sha384, p.mgfHashOid)
        assertEquals(32, p.saltLength)
        assertEquals(1, p.trailerField)
        assertEquals(0, assertNotNull(pss(field(2, int(0)))).saltLength)
        assertEquals(Int.MAX_VALUE, assertNotNull(pss(field(2, int(0x7f, 0xff, 0xff, 0xff)))).saltLength)
        assertEquals(0x80, assertNotNull(pss(field(2, int(0x00, 0x80)))).saltLength)
        assertEquals(2, assertNotNull(pss(field(3, int(2)))).trailerField)
    }

    @Test
    fun `verifier PSS parameters malformed`() {
        assertNull(VerifierInput.pss(null), "absent: RFC 4055 requires them in a signature AlgorithmIdentifier")
        assertNull(VerifierInput.pss(nul))
        assertNull(VerifierInput.pss(TestDer.seq() + TestDer.bytes(0x00)), "trailing bytes")
        val bad =
            listOf(
                listOf(field(1, mgf1(alg(sha256))), field(0, alg(sha256))),
                listOf(field(0, alg(sha256)), field(0, alg(sha256))),
                listOf(field(4, int(1))),
                listOf(TestDer.tlv(0x80, TestDer.bytes(1))),
                listOf(int(1)),
                listOf(field(0, alg(sha256, TestDer.oid("1.2.3")))),
                listOf(field(0, alg(sha256) + nul)),
                listOf(field(0, TestDer.seq(TestDer.tlv(0x06)))),
                listOf(field(1, alg("1.2.840.113549.1.1.9", alg(sha256)))),
                listOf(field(1, alg(VerifierInput.MGF1))),
                listOf(field(1, alg(VerifierInput.MGF1, nul))),
                listOf(field(1, alg(VerifierInput.MGF1, alg(sha256, int(0))))),
                listOf(field(1, alg(VerifierInput.MGF1, alg(sha256) + nul))),
                listOf(field(1, TestDer.seq(TestDer.tlv(0x06)))),
                listOf(field(2, int(0xff))),
                listOf(field(2, int(0x00, 0x01))),
                listOf(field(2, TestDer.tlv(0x02))),
                listOf(field(2, int(0x00, 0x80, 0x00, 0x00, 0x00))),
                listOf(field(2, nul)),
                listOf(field(2, int(1) + int(1))),
                listOf(field(3, int(0x80))),
            )
        for (fields in bad) assertNull(pss(*fields.toTypedArray()), fields.joinToString { it.size.toString() })
    }
}
