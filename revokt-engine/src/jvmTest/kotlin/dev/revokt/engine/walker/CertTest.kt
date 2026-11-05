// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.KeyabilityClause
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParseContext
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.testing.SymName
import dev.revokt.testing.SymVerifier
import okio.ByteString.Companion.toByteString
import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Spec §5.1 `Cert` and §5.5: every field from the one parse of `Cert.tbs`, against the parser and the JDK. */
class CertTest {
    private val certs = "/dev/revokt/engine/parse/certs"

    private val corpus: List<Pair<String, ByteArray>> =
        listOf(
            "github.com-1",
            "github.com-2",
            "github.com-3",
            "letsencrypt.org-1",
            "letsencrypt.org-2",
            "letsencrypt.org-3",
            "letsencrypt.org-4",
            "www.google.com-1",
            "www.google.com-2",
            "www.google.com-3",
            "www.mozilla.org-1",
            "www.mozilla.org-2",
            "www.mozilla.org-3",
            "mozilla-content-signing-c0",
            "mozilla-content-signing-c1",
            "mozilla-content-signing-c2",
        ).map { name -> name to resource("$certs/$name.der") }

    private fun resource(path: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream(path)) { "missing fixture $path" }.use { it.readBytes() }

    @Test
    fun `cert fields equal the parser's view on the committed corpus chains`() {
        val variants =
            File(checkNotNull(javaClass.getResource("$certs/variants")).toURI())
                .listFiles { f -> f.extension == "der" }
                .orEmpty()
                .sortedBy { it.name }
                .map { it.name to it.readBytes() }
        assertTrue(variants.isNotEmpty())
        for ((name, der) in corpus + variants) {
            val p = (CertificateParser.parse(der) as? CertificateParse.Parsed)?.certificate ?: continue
            val c = Cert.of(p, ::canonicalSubject)
            assertSame(der, c.der, name)
            assertEquals(der.toByteString().sha256(), c.bytesHash, name)
            assertContentEquals(p.tbsBytes, c.tbs, name)
            assertContentEquals(p.envelope.signature, c.sig, name)
            assertContentEquals(p.tbs.signature.bytes(p.tbsBytes), c.tbsSigAlg, name)
            assertEquals(SymVerifier.algorithmOid(c.tbsSigAlg)?.first.orEmpty(), c.tbsSigOid, name)
            assertContentEquals(p.rawSpki(), c.spki, name)
            assertEquals(p.rawSpki().toByteString().sha256(), c.spkiHash, name)
            val spkiOids = SymVerifier.spkiOids(c.spki)
            assertEquals(spkiOids.firstOrNull().orEmpty(), c.keyOid, name)
            assertEquals(spkiOids.getOrNull(1), c.curveOid, name)
            assertEquals(KeyFamily.ofKey(c.keyOid), c.keyFamily, name)
            assertContentEquals(p.rawSubject(), c.subjectRaw, name)
            assertContentEquals(p.rawIssuer(), c.issuerRaw, name)
            assertEquals(canonical(p.rawSubject()), c.canonicalSubject, name)
            assertEquals(canonical(p.rawIssuer()), c.canonicalIssuer, name)
            assertContentEquals(p.fields.ski?.bytes(p.tbsBytes), c.ski, name)
            assertContentEquals(p.fields.akiKeyId?.bytes(p.tbsBytes), c.akiKeyId, name)
            assertContentEquals(p.rawSerial(), c.serial, name)
            assertEquals(
                p.fields.scts.map { it.logId to it.timestamp },
                c.scts.map { it.logId.toByteString() to it.timestampMillis },
                name,
            )
            assertEquals(p.tbs.validity.notBeforeMillis, c.notBefore, name)
            assertEquals(p.tbs.validity.notAfterMillis, c.notAfter, name)
            assertEquals(Keyability.firstFailing(p), c.keyabilityClause, name)
            assertEquals(c.keyabilityClause == null, c.producerKeyable, name)
            assertEquals(p.envelope.algorithmIdMismatch, c.algorithmIdMismatch, name)
        }
    }

    @Test
    fun `cert fields equal the JDK's on the committed corpus chains`() {
        val factory = CertificateFactory.getInstance("X.509")
        var scts = 0
        for ((name, der) in corpus) {
            val jdk = factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            val c = WalkerCerts.cert(der)
            assertContentEquals(jdk.tbsCertificate, c.tbs, name)
            assertContentEquals(jdk.signature, c.sig, name)
            assertEquals(jdk.sigAlgOID, c.tbsSigOid, name)
            assertContentEquals(jdk.publicKey.encoded, c.spki, name)
            val family = mapOf("RSA" to KeyFamily.RSA, "EC" to KeyFamily.EC).getValue(jdk.publicKey.algorithm)
            assertEquals(family, c.keyFamily, name)
            val curve =
                (jdk.publicKey as? ECPublicKey)?.let {
                    AlgorithmParameters
                        .getInstance("EC")
                        .apply { init(it.params) }
                        .getParameterSpec(ECGenParameterSpec::class.java)
                        .name
                }
            assertEquals(curve, c.curveOid, name)
            assertContentEquals(jdk.subjectX500Principal.encoded, c.subjectRaw, name)
            assertContentEquals(jdk.issuerX500Principal.encoded, c.issuerRaw, name)
            assertEquals(jdk.subjectX500Principal.getName(X500Principal.CANONICAL), c.canonicalSubject, name)
            assertEquals(jdk.issuerX500Principal.getName(X500Principal.CANONICAL), c.canonicalIssuer, name)
            assertContentEquals(
                jdk.getExtensionValue(Oid.SUBJECT_KEY_IDENTIFIER)?.let { octets(octets(it)) },
                c.ski,
                name,
            )
            assertContentEquals(
                jdk.getExtensionValue(Oid.AUTHORITY_KEY_IDENTIFIER)?.let { akiKeyId(octets(it)) },
                c.akiKeyId,
                name,
            )
            assertEquals(jdk.serialNumber, BigInteger(c.serial), name)
            assertEquals(jdk.notBefore.time, c.notBefore, name)
            assertEquals(jdk.notAfter.time, c.notAfter, name)
            assertEquals(false, c.algorithmIdMismatch, name)
            scts += c.scts.size
        }
        assertTrue(scts > 0, "the corpus leaves carry SCTs")
    }

    @Test
    fun `cert computes canonicalSubject once and canonicalIssuer at most once`() {
        val calls = ArrayList<String?>()
        val counting: (ByteArray) -> String? = { canonicalSubject(it).also { s -> calls += s } }
        val der = WalkerCerts.der(SymName("Leaf"), SymName("Issuer"))
        val c = WalkerCerts.cert(der, counting)
        assertEquals(listOf<String?>("cn=leaf"), calls)
        repeat(3) { assertEquals("cn=issuer", c.canonicalIssuer) }
        assertEquals(listOf<String?>("cn=leaf", "cn=issuer"), calls)
        val selfIssued = WalkerCerts.cert(WalkerCerts.der(SymName("Root"), SymName("Root")), counting)
        assertEquals("cn=root", selfIssued.canonicalIssuer)
        assertEquals(
            listOf<String?>("cn=leaf", "cn=issuer", "cn=root"),
            calls,
            "a self-issued name is canonicalised once",
        )
    }

    @Test
    fun `cert turns a throwing or null canonicaliser into no canonical form and passes it a copy`() {
        val der = WalkerCerts.der(SymName("Leaf"), SymName("Issuer"))
        val throwing = WalkerCerts.cert(der) { throw IllegalArgumentException("custom delegate") }
        assertNull(throwing.canonicalSubject)
        assertNull(throwing.canonicalIssuer)
        val nulls = WalkerCerts.cert(der) { null }
        assertNull(nulls.canonicalSubject)
        val mutating =
            WalkerCerts.cert(der) {
                it.fill(0)
                "x"
            }
        assertContentEquals(SymName("Leaf").der(), mutating.subjectRaw)
        assertContentEquals(SymName("Issuer").der(), mutating.issuerRaw)
        assertEquals("x", mutating.canonicalIssuer)
    }

    @Test
    fun `cert treats a canonicaliser Error or StackOverflowError as no canonical form and caches it`() {
        val leaf = SymName("Leaf")
        val der = WalkerCerts.der(leaf, SymName("Issuer"))
        val throwers =
            listOf<Pair<String, () -> Nothing>>(
                "NotImplementedError" to { TODO("custom delegate") },
                "StackOverflowError" to { throw StackOverflowError("crafted name") },
                "AssertionError" to { throw AssertionError("custom delegate") },
            )
        for ((name, thrower) in throwers) {
            // Only the issuer throws, so the throw happens on the lazy read: it must give null, every time.
            var calls = 0
            val c =
                WalkerCerts.cert(der) {
                    calls++
                    if (it.contentEquals(leaf.der())) "cn=leaf" else thrower()
                }
            repeat(3) { assertNull(c.canonicalIssuer, name) }
            assertEquals(2, calls, "$name: the issuer's failure is cached")
            assertEquals("cn=leaf", c.canonicalSubject, name)
            val index = CandidateIndex(listOf(WalkerCerts.der(SymName("Issuer"), SymName("Issuer")))) { thrower() }
            val child = index.cert(WalkerCerts.parse(der))
            assertEquals(
                1,
                index.related(listOf(child), child, setOf(child.bytesHash), belowLeaf = false).count(),
                name,
            )
        }
    }

    @Test
    fun `cert rethrows a fatal VirtualMachineError from the canonicaliser`() {
        val leaf = SymName("Leaf")
        val der = WalkerCerts.der(leaf, SymName("Issuer"))
        assertFailsWith<OutOfMemoryError> { WalkerCerts.cert(der) { throw OutOfMemoryError("probe") } }
        val issuerOnly =
            WalkerCerts.cert(
                der,
            ) { if (it.contentEquals(leaf.der())) "cn=leaf" else throw InternalError("probe") }
        assertFailsWith<InternalError> { issuerOnly.canonicalIssuer }
    }

    @Test
    fun `cert isFatal follows the section 5_5 catch rule`() {
        assertTrue(isFatal(OutOfMemoryError()))
        assertTrue(isFatal(InternalError()))
        assertFalse(isFatal(StackOverflowError()))
        assertFalse(isFatal(NotImplementedError()))
        assertFalse(isFatal(AssertionError()))
        assertFalse(isFatal(IllegalStateException()))
        assertFalse(isFatal(LinkageError()))
    }

    @Test
    fun `cert reads an empty OID for an AlgorithmIdentifier it cannot decode`() {
        val badAlgorithm = TestDer.seq(TestDer.tlv(0x02, TestDer.bytes(1)))
        val noOid =
            TestCert(
                tbsSignature = badAlgorithm,
                outerAlgorithm = badAlgorithm,
                spki = TestDer.seq(badAlgorithm, TestDer.tlv(0x03, TestDer.bytes(0, 1))),
            )
        val c = WalkerCerts.cert(noOid.der)
        assertEquals("", c.tbsSigOid)
        assertEquals("", c.keyOid)
        assertNull(c.curveOid)
        assertEquals(KeyFamily.UNKNOWN, c.keyFamily)
        val truncatedOid = TestDer.seq(TestDer.tlv(0x06, TestDer.bytes(0x2a, 0x86)))
        val unterminated = WalkerCerts.cert(TestCert(tbsSignature = truncatedOid, outerAlgorithm = truncatedOid).der)
        assertEquals("", unterminated.tbsSigOid)
        assertEquals(WalkerCerts.EC_KEY, unterminated.keyOid)
        assertEquals(WalkerCerts.P256, unterminated.curveOid)
        assertEquals(KeyFamily.EC, unterminated.keyFamily)
        // Parameters that are not an OID (RSASSA-PSS's SEQUENCE) carry no curve.
        val pssAlgorithm =
            TestDer.seq(
                TestDer.oid("1.2.840.113549.1.1.10"),
                TestDer.seq(TestDer.tlv(0x02, TestDer.bytes(1))),
            )
        val pss =
            WalkerCerts.cert(
                TestCert(spki = TestDer.seq(pssAlgorithm, TestDer.tlv(0x03, TestDer.bytes(0, 1)))).der,
            )
        assertEquals("1.2.840.113549.1.1.10", pss.keyOid)
        assertNull(pss.curveOid)
        assertEquals(KeyFamily.RSA, pss.keyFamily)
    }

    @Test
    fun `cert carries the AlgorithmIdMismatch flag and keyability of the parse`() {
        val nullParameters = TestDer.seq(TestDer.oid(WalkerCerts.ECDSA_SHA256), TestDer.bytes(0x05, 0x00))
        // NULL against absent parameters is no mismatch after normalisation (spec §5.1 "Findings").
        assertEquals(false, WalkerCerts.cert(TestCert(outerAlgorithm = nullParameters).der).algorithmIdMismatch)
        val other = TestDer.seq(TestDer.oid(WalkerCerts.SHA256_RSA))
        assertTrue(WalkerCerts.cert(TestCert(outerAlgorithm = other).der).algorithmIdMismatch)
        val same = WalkerCerts.cert(TestCert().der)
        assertEquals(false, same.algorithmIdMismatch)
        // TestCert's SPKI is not a point on P-256: outside the keyability profile (K7).
        assertEquals(KeyabilityClause.KEY, same.keyabilityClause)
        assertEquals(false, same.producerKeyable)
    }

    private fun canonical(name: ByteArray): String? =
        try {
            X500Principal(name).getName(X500Principal.CANONICAL)
        } catch (_: IllegalArgumentException) {
            null
        }

    private fun octets(der: ByteArray): ByteArray {
        val r = DerReader(der, 0, der.size, ParseContext())
        return r.read(0x04, HeaderSite.EXTENSION_VALUE).content.bytes(der)
    }

    private fun akiKeyId(value: ByteArray): ByteArray? {
        val r = DerReader(value, 0, value.size, ParseContext())
        val seq = r.child(r.read(0x30, HeaderSite.AKI))
        return if (seq.peekTag() == 0x80) seq.readAny(HeaderSite.AKI_KEY_ID).content.bytes(value) else null
    }
}
