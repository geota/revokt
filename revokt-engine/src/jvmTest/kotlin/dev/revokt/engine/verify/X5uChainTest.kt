// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.parse.X5uPem
import dev.revokt.engine.parse.X5uPemRead
import dev.revokt.engine.verify.X5uChainFailure.ALGORITHM
import dev.revokt.engine.verify.X5uChainFailure.EKU
import dev.revokt.engine.verify.X5uChainFailure.EXTENSION
import dev.revokt.engine.verify.X5uChainFailure.KEY_USAGE
import dev.revokt.engine.verify.X5uChainFailure.NAME
import dev.revokt.engine.verify.X5uChainFailure.NOT_CA
import dev.revokt.engine.verify.X5uChainFailure.NOT_PINNED
import dev.revokt.engine.verify.X5uChainFailure.PARSE
import dev.revokt.engine.verify.X5uChainFailure.PATH_LEN
import dev.revokt.engine.verify.X5uChainFailure.SAN
import dev.revokt.engine.verify.X5uChainFailure.SIGNATURE
import dev.revokt.verify.JcaFixtures
import dev.revokt.verify.JcaFixtures.ECDSA_SHA1
import dev.revokt.verify.JcaFixtures.ECDSA_SHA256
import dev.revokt.verify.JcaFixtures.ECDSA_SHA384
import dev.revokt.verify.JcaFixtures.EC_KEY
import dev.revokt.verify.JcaFixtures.ED25519
import dev.revokt.verify.JcaFixtures.NULL
import dev.revokt.verify.JcaFixtures.P224
import dev.revokt.verify.JcaFixtures.PSS
import dev.revokt.verify.JcaFixtures.RSA_KEY
import dev.revokt.verify.JcaFixtures.SHA1
import dev.revokt.verify.JcaFixtures.SHA1_RSA
import dev.revokt.verify.JcaFixtures.SHA256
import dev.revokt.verify.JcaFixtures.SHA256_RSA
import dev.revokt.verify.JcaFixtures.algId
import dev.revokt.verify.JcaFixtures.generate
import dev.revokt.verify.JcaFixtures.pssParams
import dev.revokt.verify.JcaFixtures.pssSpec
import dev.revokt.verify.JcaSignatureVerifier
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import java.math.BigInteger
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §7.1 "x5u chain" and §9 data-path fixture (d) (all but the URL-host and size items, which are #129's), on chains
 * built here: a test root (RSA-2048) pinned by SPKI SHA-256 → a P-384 intermediate → a P-384 leaf, shaped like
 * Mozilla's, every signature made by the test JDK. Plus Mozilla's own committed chain against the real pin.
 */
class X5uChainTest {
    private val verifier = JcaSignatureVerifier()

    private val rootKey = JcaFixtures.rsa("x5u-root")
    private val intermediateKey = ecPair("x5u-intermediate")
    private val leafKey = ecPair("x5u-leaf")
    private val pinned = setOf(hash(rootKey))

    // The chains

    /** A signature algorithm: the `AlgorithmIdentifier` written into the certificate and the JCA name that signs. */
    private class Alg(
        val id: ByteArray,
        val jca: String,
        val params: AlgorithmParameterSpec? = null,
    )

    /** A certificate for [spki] named [subject], issued by [issuer] and signed by [signer] under [alg]. */
    private fun issue(
        subject: ByteArray,
        spki: ByteArray,
        issuer: ByteArray,
        signer: PrivateKey,
        extensions: List<ByteArray>,
        validity: ByteArray = WIDE,
        alg: Alg = if (signer.algorithm == "RSA") RSA_SHA384 else EC_SHA384,
        outer: ByteArray = alg.id,
    ): ByteArray {
        fun cert(signature: ByteArray) =
            TestCert(
                tbsSignature = alg.id,
                issuer = issuer,
                validity = validity,
                subject = subject,
                spki = spki,
                extensions = extensions,
                outerAlgorithm = outer,
                signature = TestDer.tlv(0x03, TestDer.bytes(0x00), signature),
            )
        return cert(JcaFixtures.sign(alg.jca, signer, cert(ByteArray(0)).tbs, alg.params)).der
    }

    private fun root(
        validity: ByteArray = WIDE,
        extensions: List<ByteArray> = caExtensions(),
    ): ByteArray = issue(ROOT, rootKey.public.encoded, ROOT, rootKey.private, extensions, validity)

    private fun intermediate(
        extensions: List<ByteArray> = caExtensions(),
        subject: ByteArray = INTERMEDIATE,
        validity: ByteArray = WIDE,
        key: KeyPair = intermediateKey,
        spki: ByteArray = key.public.encoded,
        signer: KeyPair = rootKey,
        alg: Alg = RSA_SHA384,
    ): ByteArray = issue(subject, spki, ROOT, signer.private, extensions, validity, alg)

    private fun leaf(
        extensions: List<ByteArray> = LEAF_EXTENSIONS,
        issuer: ByteArray = INTERMEDIATE,
        validity: ByteArray = WIDE,
        spki: ByteArray = leafKey.public.encoded,
        signer: KeyPair = intermediateKey,
        alg: Alg = if (signer.private.algorithm == "RSA") RSA_SHA384 else EC_SHA384,
        outer: ByteArray = alg.id,
    ): ByteArray = issue(LEAF, spki, issuer, signer.private, extensions, validity, alg, outer)

    private fun chain(
        leaf: ByteArray = leaf(),
        intermediate: ByteArray = intermediate(),
        root: ByteArray = root(),
    ): List<ByteArray> = listOf(leaf, intermediate, root)

    private fun validate(
        chain: List<ByteArray>,
        pins: Set<ByteString> = pinned,
        with: SignatureVerifier = verifier,
    ): X5uChainResult = validateX5uChain(chain, pins, with)

    private fun assertLoads(
        chain: List<ByteArray>,
        pins: Set<ByteString> = pinned,
        links: Int = 2,
        leafSpki: ByteArray = leafKey.public.encoded,
    ): X5uPath {
        val result = validate(chain, pins)
        assertIs<X5uChainResult.Valid>(result, "$result")
        assertEquals(links, result.path.links.size)
        assertContentEquals(leafSpki, result.path.leafSpki)
        return result.path
    }

    private fun assertFails(
        failure: X5uChainFailure,
        certIndex: Int,
        chain: List<ByteArray>,
        pins: Set<ByteString> = pinned,
        with: SignatureVerifier = verifier,
    ): X5uChainResult.Failed {
        val result = validate(chain, pins, with)
        assertIs<X5uChainResult.Failed>(result, "expected $failure")
        assertEquals(failure to certIndex, result.failure to result.certIndex, result.detail)
        return result
    }

    private fun live(path: X5uPath): X5uValidity = checkValidity(path, NOW)

    // Fixture (d): the valid chain and every mutation

    @Test
    fun `data-path (d) a chain shaped like Mozilla's loads, and its leaf SPKI is the content-signature key`() {
        assertEquals(X5uValidity.Valid, live(assertLoads(chain())))
    }

    @Test
    fun `data-path (d) wrong leaf SAN is FAILED`() {
        for (san in listOf(
            san(dns("other.content-signature.mozilla.org")),
            san(dns(X5U_LEAF_NAME.uppercase())),
            san(dns("*.content-signature.mozilla.org")),
            san(dns("$X5U_LEAF_NAME.")),
            san(dns(X5U_LEAF_NAME), dns("other.example")),
            san(dns("other.example"), dns(X5U_LEAF_NAME)),
            san(dns(X5U_LEAF_NAME), TestDer.tlv(0x86, TestDer.ascii("https://$X5U_LEAF_NAME/"))),
            san(TestDer.tlv(0x86, TestDer.ascii(X5U_LEAF_NAME))),
            san(TestDer.tlv(0x81, TestDer.ascii(X5U_LEAF_NAME))),
        )) {
            assertFails(SAN, 0, chain(leaf = leaf(listOf(ku(DIGITAL_SIGNATURE), eku(CODE_SIGNING), san))))
        }
        assertFails(SAN, 0, chain(leaf = leaf(listOf(ku(DIGITAL_SIGNATURE), eku(CODE_SIGNING)))))
    }

    @Test
    fun `data-path (d) missing codeSigning EKU is FAILED`() {
        val sanOnly = listOf(ku(DIGITAL_SIGNATURE), san(dns(X5U_LEAF_NAME)))
        assertFails(EKU, 0, chain(leaf = leaf(sanOnly)))
        assertFails(EKU, 0, chain(leaf = leaf(sanOnly + eku(SERVER_AUTH))))
        assertFails(EKU, 0, chain(leaf = leaf(sanOnly + eku(SERVER_AUTH, "1.3.6.1.5.5.7.3.33"))))
        // A purpose among others is enough, as in mozilla::pkix and webpki.
        assertLoads(chain(leaf = leaf(sanOnly + eku(SERVER_AUTH, CODE_SIGNING))))
    }

    @Test
    fun `data-path (d) root not pinned is FAILED`() {
        val chain = chain()
        assertFails(NOT_PINNED, 2, chain, pins = emptySet())
        assertFails(NOT_PINNED, 2, chain, pins = setOf(hash(JcaFixtures.rsa("x5u-other"))))
        // The leaf is never the terminal: a pinned leaf SPKI alone pins nothing.
        assertFails(NOT_PINNED, 2, chain, pins = setOf(hash(leafKey)))
        assertFails(NOT_PINNED, 0, chain.take(1), pins = setOf(hash(leafKey)))
        assertLoads(chain, pins = setOf(hash(leafKey), hash(rootKey)))
        // The SPKI is hashed as its DER TLV, not the certificate.
        assertFails(NOT_PINNED, 2, chain, pins = setOf(chain[2].toByteString().sha256()))
    }

    @Test
    fun `data-path (d) a non-CA certificate as intermediate is FAILED`() {
        val rest = listOf(ku(KEY_CERT_SIGN, CRL_SIGN), eku(CODE_SIGNING))
        assertFails(NOT_CA, 1, chain(intermediate = intermediate(rest)))
        assertFails(NOT_CA, 1, chain(intermediate = intermediate(rest + bc(ca = false))))
        assertFails(NOT_CA, 1, chain(intermediate = intermediate(rest + bc(ca = null, pathLen = 0))))
        assertFails(NOT_CA, 1, chain(intermediate = intermediate(rest + bc(ca = false, pathLen = 3))))
    }

    @Test
    fun `data-path (d) a name-chaining break is FAILED`() {
        assertFails(NAME, 1, chain(leaf = leaf(issuer = TestCert.name("Content Signing Intermediate 2"))))
        assertFails(NAME, 1, chain(intermediate = intermediate(subject = TestCert.name("Other Intermediate"))))
        // A subject the platform cannot read has no canonical form, so only the raw bytes could match.
        val unreadable = TestDer.seq(TestDer.bytes(0x01, 0x02))
        assertNull(canonicalSubject(unreadable))
        assertFails(NAME, 1, chain(intermediate = intermediate(subject = unreadable)))
        val otherUnreadable = TestDer.seq(TestDer.bytes(0x01, 0x03))
        assertFails(
            NAME,
            1,
            chain(leaf = leaf(issuer = otherUnreadable), intermediate = intermediate(subject = unreadable)),
        )
        assertLoads(chain(leaf = leaf(issuer = unreadable), intermediate = intermediate(subject = unreadable)))
    }

    @Test
    fun `data-path (d) a pathLenConstraint violation is FAILED`() {
        val subKey = ecPair("x5u-sub")
        val sub = TestCert.name("Sub Intermediate")

        fun fourLinks(
            intermediatePathLen: Int?,
            subPathLen: Int? = null,
            rootPathLen: Int? = null,
        ): List<ByteArray> =
            listOf(
                issue(LEAF, leafKey.public.encoded, sub, subKey.private, LEAF_EXTENSIONS),
                issue(sub, subKey.public.encoded, INTERMEDIATE, intermediateKey.private, caExtensions(subPathLen)),
                intermediate(caExtensions(intermediatePathLen)),
                root(extensions = caExtensions(rootPathLen)),
            )
        assertFails(PATH_LEN, 2, fourLinks(intermediatePathLen = 0))
        assertLoads(fourLinks(intermediatePathLen = 1), links = 3)
        assertLoads(fourLinks(intermediatePathLen = null, subPathLen = 0), links = 3)
        // The terminal's own constraint is never read (trust-anchor semantics).
        assertLoads(fourLinks(intermediatePathLen = 1, rootPathLen = 0), links = 3)
        assertLoads(chain(intermediate = intermediate(caExtensions(pathLen = 0))))
    }

    @Test
    fun `data-path (d) keyUsage without keyCertSign is FAILED`() {
        val ca = listOf(bc(ca = true), eku(CODE_SIGNING))
        assertFails(KEY_USAGE, 1, chain(intermediate = intermediate(ca + ku(DIGITAL_SIGNATURE, CRL_SIGN))))
        assertFails(KEY_USAGE, 1, chain(intermediate = intermediate(ca + ku(CRL_SIGN))))
        // keyCertSign is checked only when keyUsage is present.
        assertLoads(chain(intermediate = intermediate(ca)))
        assertLoads(chain(intermediate = intermediate(ca + ku(KEY_CERT_SIGN))))
    }

    @Test
    fun `data-path (d) an expired intermediate or leaf at a live fetch is CLOCK_SKEW`() {
        val expired = window("20250101000000Z", "20260101000000Z")
        val future = window("20270101000000Z", "20300101000000Z")
        for ((chain, index) in listOf(
            chain(intermediate = intermediate(validity = expired)) to 1,
            chain(leaf = leaf(validity = expired)) to 0,
            chain(leaf = leaf(validity = future)) to 0,
        )) {
            val path = assertLoads(chain)
            val skew = assertIs<X5uValidity.ClockSkew>(live(path))
            assertEquals(index, skew.certIndex, skew.detail)
        }
    }

    @Test
    fun `data-path (d) an expired leaf in a seed loads, through the split`() {
        val leafWindow = window("20260906180425Z", "20261025180425Z")
        val path = assertLoads(chain(leaf = leaf(validity = leafWindow)))
        assertIs<X5uValidity.ClockSkew>(live(path))
        assertEquals(X5uValidity.Valid, checkValidity(path, millis("2026-10-21T12:00:00Z")))
    }

    @Test
    fun `data-path (d) a pinned SPKI as a non-terminal link loads with the path truncated there`() {
        val pins = setOf(hash(intermediateKey), hash(rootKey))
        assertLoads(chain(), pins = pins, links = 1)
        // Nothing after the terminal is parsed or checked.
        val garbage = TestDer.bytes(0x30, 0x03, 0x01)
        val path = assertLoads(chain(root = garbage), pins = pins, links = 1)
        assertLoads(chain().take(2), pins = setOf(hash(intermediateKey)), links = 1)
        assertLoads(chain().take(2) + listOf(garbage, garbage), pins = setOf(hash(intermediateKey)), links = 1)
        // An empty CERTIFICATE block (X5uPem returns empty DER for one, as rustls-pki-types does) after the terminal.
        assertLoads(chain() + listOf(ByteArray(0)))
        assertEquals(X5uValidity.Valid, live(path))
    }

    @Test
    fun `data-path (d) the pinned terminal expired, or wrapped self-signed under another subject, loads`() {
        val expiredRoot = root(validity = window("19900101000000Z", "20000101000000Z"))
        assertEquals(X5uValidity.Valid, live(assertLoads(chain(root = expiredRoot))))
        val other = TestCert.name("Some Other Root")
        val wrapped =
            issue(
                other,
                rootKey.public.encoded,
                other,
                rootKey.private,
                listOf(ku(DIGITAL_SIGNATURE), bc(ca = false), dup(), dup()),
                window("19900101000000Z", "20000101000000Z"),
                Alg(algId(SHA1_RSA, NULL), "SHA1withRSA"),
            )
        assertEquals(X5uValidity.Valid, live(assertLoads(chain(root = wrapped))))
        // Its own signature is never read either: a flipped byte still loads.
        assertLoads(chain(root = JcaFixtures.flip(wrapped)))
    }

    @Test
    fun `data-path (d) an RSA-1024 or SHA-1 link is FAILED by the floor`() {
        val rsa1024 = generate("RSA", size = 1024)
        assertFails(ALGORITHM, 1, chain(intermediate = intermediate(key = rsa1024)))
        assertFails(ALGORITHM, 1, chain(leaf = leaf(signer = rsa1024), intermediate = intermediate(key = rsa1024)))
        assertFails(ALGORITHM, 0, chain(leaf = leaf(alg = Alg(algId(ECDSA_SHA1), "SHA1withECDSA"))))
        assertFails(ALGORITHM, 1, chain(intermediate = intermediate(alg = Alg(algId(SHA1_RSA, NULL), "SHA1withRSA"))))
    }

    @Test
    fun `the floor bounds every link's signature algorithm`() {
        assertLoads(chain(leaf = leaf(alg = Alg(algId(ECDSA_SHA256), "SHA256withECDSA"))))
        assertLoads(chain(leaf = leaf(alg = Alg(algId(ECDSA_SHA512), "SHA512withECDSA"))))
        assertLoads(chain(intermediate = intermediate(alg = Alg(algId(SHA256_RSA, NULL), "SHA256withRSA"))))
        assertLoads(chain(intermediate = intermediate(alg = Alg(algId(SHA512_RSA, NULL), "SHA512withRSA"))))
        val pss = pssParams(hash = SHA256, mgfHash = SHA256, salt = 32)
        val pssAlg = Alg(algId(PSS, pss), "RSASSA-PSS", pssSpec("SHA-256", "SHA-256", 32))
        assertLoads(chain(intermediate = intermediate(alg = pssAlg)))
        for (id in listOf(
            algId(ECDSA_SHA224),
            algId(SHA224_RSA, NULL),
            algId(SHA3_256_ECDSA),
            algId(PSS),
            algId(PSS, pssParams(hash = SHA256)),
            algId(PSS, pssParams(mgfHash = SHA256)),
            algId(PSS, pssParams(hash = SHA1, mgfHash = SHA1)),
            algId(PSS, pssParams(hash = SHA224, mgfHash = SHA224)),
            algId(PSS, pssParams(hash = SHA256, mgfHash = SHA224)),
            algId(ED25519),
            // `ecdsa-with-SHA256` with a padded arc: not the real OID (VerifierInput's minimal-OID rule).
            TestDer.seq(TestDer.tlv(0x06, TestDer.bytes(0x2a, 0x80, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02))),
        )) {
            // The floor runs before any signature, so the certificate need not be really signed under these.
            assertFails(ALGORITHM, 0, chain(leaf = leaf(alg = Alg(id, "SHA384withECDSA"))))
        }
    }

    @Test
    fun `the floor bounds every link's own key, the leaf's included`() {
        // Any EC curve the floor allows may sign the content (maintainer decision on #163: Firefox parity).
        for (curve in listOf("secp256r1", "secp521r1")) {
            val key = ecPair("x5u-leaf-$curve", curve).public.encoded
            assertLoads(chain(leaf = leaf(spki = key)), leafSpki = key)
        }
        val rsaLeaf = JcaFixtures.rsa("x5u-rsa-leaf").public.encoded
        assertLoads(chain(leaf = leaf(spki = rsaLeaf)), leafSpki = rsaLeaf)
        val rsaIntermediate = JcaFixtures.rsa("x5u-rsa-intermediate")
        assertLoads(chain(leaf = leaf(signer = rsaIntermediate), intermediate = intermediate(key = rsaIntermediate)))
    }

    @Test
    fun `keys below the floor are FAILED before any signature`() {
        val never = stub { _, _, _, _ -> error("called") }
        for (spki in listOf(
            rsaSpki(2047),
            rsaSpki(1024),
            rsaSpki(2047, PSS),
            ecSpki(P224),
            ecSpki(BRAINPOOL_P256),
            ecSpki(null),
            JcaFixtures.spki(algId(ED25519), TestDer.bytes(*IntArray(32))),
            // Malformed RSA keys: an empty BIT STRING, unused bits, a modulus negative, empty, zero or all zero octets,
            // no RSAPublicKey SEQUENCE.
            rsaBits(TestDer.bytes(0x00)),
            rsaBits(TestDer.bytes(0x01) + rsaPublicKey(2048)),
            rsaBits(TestDer.bytes(0x00) + modulus(TestDer.bytes(0x80, 0x01))),
            rsaBits(TestDer.bytes(0x00) + modulus(TestDer.bytes())),
            rsaBits(TestDer.bytes(0x00) + modulus(TestDer.bytes(0))),
            rsaBits(TestDer.bytes(0x00) + modulus(ByteArray(300))),
            rsaBits(TestDer.bytes(0x00, 0x05, 0x00)),
            // Not an SPKI the verifier reads: an element after the BIT STRING.
            TestDer.seq(algId(RSA_KEY, NULL), TestDer.tlv(0x03, TestDer.bytes(0x00), rsaPublicKey(2048)), NULL),
        )) {
            assertFails(ALGORITHM, 0, chain(leaf = leaf(spki = spki)), with = never)
            assertFails(ALGORITHM, 1, chain(intermediate = intermediate(spki = spki)), with = never)
        }
        assertTrue(X5uFloor.key(rsaSpki(2048)))
        assertTrue(X5uFloor.key(rsaSpki(2048, PSS)))
        assertTrue(X5uFloor.key(rsaSpki(4096, leadingZeros = 3)))
    }

    @Test
    fun `data-path (d) a canonical-only name match loads`() {
        val printable = name(0x13, "Content Signing Intermediate")
        val utf8 = name(0x0c, "content  signing INTERMEDIATE ")
        assertNotEquals(printable.toByteString(), utf8.toByteString())
        assertEquals(canonicalSubject(printable), canonicalSubject(utf8))
        assertLoads(chain(leaf = leaf(issuer = utf8), intermediate = intermediate(subject = printable)))
    }

    @Test
    fun `validateX5uChain never reads a validity field`() {
        val past = window("19900101000000Z", "20000101000000Z")
        val path = assertLoads(chain(leaf(validity = past), intermediate(validity = past), root(validity = past)))
        assertEquals(0, assertIs<X5uValidity.ClockSkew>(live(path)).certIndex)
        // Windows that do not decode, or end before they start, pass it too; checkValidity then fails closed.
        val utcMonth13 = TestDer.tlv(0x17, TestDer.ascii("991399999999Z"))
        for (window in listOf(
            TestDer.seq(utcMonth13, TestDer.tlv(0x18, TestDer.ascii("20500101000000Z"))),
            TestDer.seq(TestDer.tlv(0x18, TestDer.ascii("20200101000000Z")), utcMonth13),
            window("20300101000000Z", "20200101000000Z"),
        )) {
            val odd = assertLoads(chain(leaf = leaf(validity = window)))
            assertEquals(0, assertIs<X5uValidity.Failed>(live(odd)).certIndex)
        }
        val oddIntermediate =
            assertLoads(chain(intermediate = intermediate(validity = window("20300101000000Z", "20200101000000Z"))))
        assertEquals(1, assertIs<X5uValidity.Failed>(live(oddIntermediate)).certIndex)
    }

    // Further rules

    @Test
    fun `a validity window includes both of its ends`() {
        val path = assertLoads(chain(leaf = leaf(validity = window("20261001000000Z", "20261101000000Z"))))
        val notBefore = millis("2026-10-01T00:00:00Z")
        val notAfter = millis("2026-11-01T00:00:00Z")
        assertEquals(X5uValidity.Valid, checkValidity(path, notBefore))
        assertEquals(X5uValidity.Valid, checkValidity(path, notAfter))
        assertIs<X5uValidity.ClockSkew>(checkValidity(path, notBefore - 1))
        assertIs<X5uValidity.ClockSkew>(checkValidity(path, notAfter + 1))
    }

    @Test
    fun `a duplicate of any extension OID is FAILED`() {
        assertFails(EXTENSION, 0, chain(leaf = leaf(LEAF_EXTENSIONS + dup() + dup())))
        assertFails(EXTENSION, 0, chain(leaf = leaf(LEAF_EXTENSIONS + san(dns(X5U_LEAF_NAME)))))
        // Two identical good copies included (the JDK rejects them too).
        assertFails(EXTENSION, 1, chain(intermediate = intermediate(caExtensions() + ku(KEY_CERT_SIGN, CRL_SIGN))))
        assertFails(EXTENSION, 1, chain(intermediate = intermediate(caExtensions() + dup() + dup())))
        assertFails(EXTENSION, 1, chain(intermediate = intermediate(caExtensions() + bc(ca = true))))
    }

    @Test
    fun `a malformed extension the chain reads is FAILED`() {
        val badBoolean = TestDer.extension("2.5.29.19", TestDer.seq(TestDer.tlv(0x01, TestDer.bytes(0x01))))
        val emptyKu = TestDer.extension("2.5.29.15", TestDer.tlv(0x03, TestDer.bytes()))
        val emptyEku = TestDer.extension("2.5.29.37", TestDer.seq())
        val emptySan = TestDer.extension("2.5.29.17", TestDer.seq())
        val ca = listOf(bc(ca = true), ku(KEY_CERT_SIGN))
        assertFails(EXTENSION, 1, chain(intermediate = intermediate(listOf(badBoolean, ku(KEY_CERT_SIGN)))))
        assertFails(EXTENSION, 1, chain(intermediate = intermediate(listOf(bc(ca = true), emptyKu))))
        assertFails(EXTENSION, 0, chain(leaf = leaf(listOf(emptyEku, san(dns(X5U_LEAF_NAME))))))
        assertFails(EXTENSION, 0, chain(leaf = leaf(listOf(eku(CODE_SIGNING), emptySan))))
        // The leaf's basicConstraints and keyUsage are not read (no spec rule), so a bad one there is not checked.
        assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS.drop(1) + badBoolean), intermediate = intermediate(ca)))
    }

    @Test
    fun `every link's signature must verify under the next certificate's SPKI`() {
        assertFails(SIGNATURE, 0, chain(leaf = JcaFixtures.flip(leaf())))
        assertFails(SIGNATURE, 0, chain(leaf = leaf(signer = ecPair("x5u-other-intermediate"))))
        assertFails(SIGNATURE, 1, chain(intermediate = intermediate(signer = JcaFixtures.rsa("x5u-other"))))
        // x5u order is the path: Firefox's path building would find the intermediate, revokt does not reorder.
        assertFails(SIGNATURE, 0, listOf(leaf(), root(), intermediate()))
    }

    @Test
    fun `links are verified with the signed TBS algorithm, never the unsigned outer one`() {
        val outer = algId(ECDSA_SHA512)
        assertLoads(chain(leaf = leaf(outer = outer)))
        val calls = ArrayList<List<ByteArray>>()
        val recording =
            stub { sigAlg, spki, message, signature ->
                calls += listOf(sigAlg, spki, message, signature)
                verifier.verify(sigAlg, spki, message, signature)
            }
        val chain = chain(leaf = leaf(outer = outer))
        assertIs<X5uChainResult.Valid>(validate(chain, with = recording))
        assertEquals(2, calls.size)
        assertContentEquals(algId(ECDSA_SHA384), calls[0][0])
        assertContentEquals(intermediateKey.public.encoded, calls[0][1])
        assertContentEquals(rootKey.public.encoded, calls[1][1])
    }

    @Test
    fun `UNSUPPORTED, INVALID and a verifier throw are each FAILED, and a fatal error is rethrown`() {
        val chain = chain()
        assertFails(SIGNATURE, 0, chain, with = stub { _, _, _, _ -> VerifyResult.UNSUPPORTED })
        assertFails(SIGNATURE, 0, chain, with = stub { _, _, _, _ -> VerifyResult.INVALID })
        val threw = assertFails(SIGNATURE, 0, chain, with = stub { _, _, _, _ -> throw IllegalStateException("boom") })
        assertEquals("boom", threw.verifierError)
        // The intermediate's link is reached only once the leaf's verified.
        var calls = 0
        val leafOnly = stub { _, _, _, _ -> if (calls++ == 0) VerifyResult.VERIFIED else VerifyResult.INVALID }
        assertFails(SIGNATURE, 1, chain, with = leafOnly)
        assertFailsWith<OutOfMemoryError> { validate(chain, with = stub { _, _, _, _ -> throw OutOfMemoryError() }) }
    }

    @Test
    fun `a certificate up to the terminal that does not parse is FAILED`() {
        val garbage = TestDer.bytes(0x30, 0x03, 0x01)
        assertFails(PARSE, 0, chain(leaf = garbage))
        assertFails(PARSE, 1, chain(intermediate = garbage))
        assertFails(PARSE, 2, chain(root = garbage))
        assertFails(PARSE, 1, chain(intermediate = ByteArray(0)))
        assertFailsWith<IllegalArgumentException> { validate(emptyList()) }
    }

    // Mozilla's chain

    @Test
    fun `Mozilla's committed x5u chain validates to the pinned production root`() {
        val ders = (0..2).map { resource("/dev/revokt/engine/parse/certs/mozilla-content-signing-c$it.der") }
        val pem = X5uPem.read(resource("/dev/revokt/engine/parse/X5uPemFuzzTestInputs/mozilla-chain"))
        assertEquals(
            ders.map { it.toByteString() },
            assertIs<X5uPemRead.Certificates>(pem).ders.map { it.toByteString() },
        )
        val path = assertLoads(ders, pins = setOf(MOZILLA_ROOT_SPKI_SHA256), leafSpki = spkiOf(ders[0]))
        // The leaf is valid 2026-09-06 to 2026-11-25, the intermediate 2015-03-17 to 2101-05-19.
        assertEquals(X5uValidity.Valid, checkValidity(path, millis("2026-10-21T00:00:00Z")))
        assertEquals(0, assertIs<X5uValidity.ClockSkew>(checkValidity(path, millis("2026-12-01T00:00:00Z"))).certIndex)
        assertEquals(0, assertIs<X5uValidity.ClockSkew>(checkValidity(path, millis("2015-01-01T00:00:00Z"))).certIndex)
        assertFails(NOT_PINNED, 2, ders, pins = pinned)
        assertFails(
            SIGNATURE,
            0,
            listOf(JcaFixtures.flip(ders[0])) + ders.drop(1),
            pins = setOf(MOZILLA_ROOT_SPKI_SHA256),
        )
    }

    // Helpers

    private fun resource(path: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream(path)) { "missing $path" }.use { it.readBytes() }

    private fun stub(answer: (ByteArray, ByteArray, ByteArray, ByteArray) -> VerifyResult): SignatureVerifier =
        object : SignatureVerifier {
            override fun verify(
                sigAlg: ByteArray,
                spki: ByteArray,
                message: ByteArray,
                signature: ByteArray,
            ): VerifyResult = answer(sigAlg, spki, message, signature)

            override fun unsupportedOids(): Set<String> = emptySet()
        }

    private fun spkiOf(der: ByteArray): ByteArray =
        CertificateFactory
            .getInstance("X.509")
            .generateCertificate(der.inputStream())
            .publicKey.encoded

    private companion object {
        const val CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
        const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
        const val DIGITAL_SIGNATURE = 0
        const val KEY_CERT_SIGN = 5
        const val CRL_SIGN = 6
        const val ECDSA_SHA224 = "1.2.840.10045.4.3.1"
        const val ECDSA_SHA512 = "1.2.840.10045.4.3.4"
        const val SHA3_256_ECDSA = "2.16.840.1.101.3.4.3.10"
        const val SHA224_RSA = "1.2.840.113549.1.1.14"
        const val SHA224 = "2.16.840.1.101.3.4.2.4"
        const val SHA512_RSA = "1.2.840.113549.1.1.13"
        const val BRAINPOOL_P256 = "1.3.36.3.3.2.8.1.1.7"

        /** Spec §7.1 and Appendix A: the SPKI SHA-256 of `root-ca-production-amo`, which `MozillaRemoteSettings.DEFAULT` pins. */
        val MOZILLA_ROOT_SPKI_SHA256 =
            "3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7"
                .lowercase()
                .decodeHex()

        val NOW = millis("2026-11-06T12:00:00Z")
        val WIDE = window("20200101000000Z", "20500101000000Z")
        val ROOT = TestCert.name("root-ca-production-amo")
        val INTERMEDIATE = TestCert.name("Content Signing Intermediate")
        val LEAF = TestCert.name(X5U_LEAF_NAME)

        val RSA_SHA384 = Alg(algId("1.2.840.113549.1.1.12", NULL), "SHA384withRSA")
        val EC_SHA384 = Alg(algId(ECDSA_SHA384), "SHA384withECDSA")

        val LEAF_EXTENSIONS = listOf(ku(DIGITAL_SIGNATURE), eku(CODE_SIGNING), san(dns(X5U_LEAF_NAME)))

        fun caExtensions(pathLen: Int? = null): List<ByteArray> =
            listOf(bc(ca = true, pathLen = pathLen), ku(KEY_CERT_SIGN, CRL_SIGN), eku(CODE_SIGNING))

        fun ecPair(
            label: String,
            curve: String = "secp384r1",
        ): KeyPair = JcaFixtures.pair(label) { generate("EC", ECGenParameterSpec(curve)) }

        fun hash(pair: KeyPair): ByteString =
            pair.public.encoded
                .toByteString()
                .sha256()

        fun millis(instant: String): Long = Instant.parse(instant).toEpochMilli()

        fun window(
            notBefore: String,
            notAfter: String,
        ): ByteArray =
            TestDer.seq(TestDer.tlv(0x18, TestDer.ascii(notBefore)), TestDer.tlv(0x18, TestDer.ascii(notAfter)))

        /** A one-CN name whose value has string tag [tag]. */
        fun name(
            tag: Int,
            cn: String,
        ): ByteArray =
            TestDer.seq(TestDer.tlv(0x31, TestDer.seq(TestDer.oid("2.5.4.3"), TestDer.tlv(tag, TestDer.ascii(cn)))))

        fun bc(
            ca: Boolean?,
            pathLen: Int? = null,
        ): ByteArray =
            TestDer.extension(
                "2.5.29.19",
                TestDer.seq(
                    ca?.let { TestDer.tlv(0x01, TestDer.bytes(if (it) 0xff else 0x00)) } ?: ByteArray(0),
                    pathLen?.let { JcaFixtures.integer(it) } ?: ByteArray(0),
                ),
                critical = true,
            )

        /** keyUsage with the named [bits] (0 = digitalSignature) set, in one octet, trailing zero bits trimmed. */
        fun ku(vararg bits: Int): ByteArray {
            val octet = bits.fold(0) { acc, bit -> acc or (0x80 ushr bit) }
            return TestDer.extension(
                "2.5.29.15",
                TestDer.tlv(0x03, TestDer.bytes(7 - bits.max(), octet)),
                critical = true,
            )
        }

        fun eku(vararg purposes: String): ByteArray =
            TestDer.extension("2.5.29.37", TestDer.seq(*purposes.map { TestDer.oid(it) }.toTypedArray()))

        fun san(vararg names: ByteArray): ByteArray = TestDer.extension("2.5.29.17", TestDer.seq(*names))

        fun dns(name: String): ByteArray = TestDer.tlv(0x82, TestDer.ascii(name))

        /** An extension of an unassigned OID, which a second copy makes a duplicate. */
        fun dup(): ByteArray = TestDer.extension("1.3.6.1.4.1.99999.1", TestDer.tlv(0x05, ByteArray(0)))

        /** `RSAPublicKey` whose modulus has exactly [bits] significant bits, behind [leadingZeros] zero octets. */
        fun rsaPublicKey(
            bits: Int,
            leadingZeros: Int = 0,
        ): ByteArray {
            val n =
                BigInteger.ONE
                    .shiftLeft(bits - 1)
                    .or(BigInteger.ONE)
                    .toByteArray()
            return TestDer.seq(TestDer.tlv(0x02, ByteArray(leadingZeros), n), JcaFixtures.integer(65537))
        }

        fun rsaSpki(
            bits: Int,
            oid: String = RSA_KEY,
            leadingZeros: Int = 0,
        ): ByteArray =
            TestDer.seq(
                if (oid == RSA_KEY) algId(oid, NULL) else algId(oid),
                TestDer.tlv(0x03, TestDer.bytes(0x00), rsaPublicKey(bits, leadingZeros)),
            )

        /** An `rsaEncryption` SPKI whose BIT STRING content is [content]. */
        fun rsaBits(content: ByteArray): ByteArray = TestDer.seq(algId(RSA_KEY, NULL), TestDer.tlv(0x03, content))

        /** `RSAPublicKey` with the modulus content [n] as given. */
        fun modulus(n: ByteArray): ByteArray = TestDer.seq(TestDer.tlv(0x02, n), JcaFixtures.integer(3))

        /** An `id-ecPublicKey` SPKI on [curve] (no parameters when null) with a placeholder point. */
        fun ecSpki(curve: String?): ByteArray =
            JcaFixtures.spki(
                TestDer.seq(TestDer.oid(EC_KEY), curve?.let { TestDer.oid(it) } ?: ByteArray(0)),
                TestDer.bytes(0x04, *IntArray(64) { 1 }),
            )
    }
}
