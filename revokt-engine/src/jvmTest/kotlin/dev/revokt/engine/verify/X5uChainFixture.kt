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
import dev.revokt.engine.verify.X5uChainFailure.LEAF_CA
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
import dev.revokt.verify.JcaFixtures.P256
import dev.revokt.verify.JcaFixtures.P384
import dev.revokt.verify.JcaFixtures.P521
import dev.revokt.verify.JcaFixtures.PSS
import dev.revokt.verify.JcaFixtures.RSA_KEY
import dev.revokt.verify.JcaFixtures.SHA1
import dev.revokt.verify.JcaFixtures.SHA1_RSA
import dev.revokt.verify.JcaFixtures.SHA256
import dev.revokt.verify.JcaFixtures.SHA256_RSA
import dev.revokt.verify.JcaFixtures.SHA384
import dev.revokt.verify.JcaFixtures.SHA512
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The chains of the x5u tests (spec §7.1 "x5u chain", §9 data-path fixture (d)): a test root (RSA-2048) pinned by SPKI
 * SHA-256 → a P-384 intermediate → a P-384 leaf, shaped like Mozilla's, every signature made by the test JDK.
 */
internal open class X5uChainFixture {
    protected val verifier = JcaSignatureVerifier()

    protected val rootKey = JcaFixtures.rsa("x5u-root")
    protected val intermediateKey = ecPair("x5u-intermediate")
    protected val leafKey = ecPair("x5u-leaf")
    protected val pinned = setOf(hash(rootKey))

    // The chains

    /**
     * A signature algorithm: the signed TBS `AlgorithmIdentifier`, the JCA name that signs, and the unsigned outer
     * `signatureAlgorithm` ([id] unless a test changes it).
     */
    class Alg(
        val id: ByteArray,
        val jca: String,
        val params: AlgorithmParameterSpec? = null,
        val outer: ByteArray = id,
    )

    /** A certificate for [spki] named [subject], issued by [issuer] and signed by [signer] under [alg]. */
    protected fun issue(
        subject: ByteArray,
        spki: ByteArray,
        issuer: ByteArray,
        signer: PrivateKey,
        extensions: List<ByteArray>,
        validity: ByteArray = WIDE,
        alg: Alg = if (signer.algorithm == "RSA") RSA_SHA384 else EC_SHA384,
    ): ByteArray {
        fun cert(signature: ByteArray) =
            TestCert(
                tbsSignature = alg.id,
                issuer = issuer,
                validity = validity,
                subject = subject,
                spki = spki,
                extensions = extensions,
                outerAlgorithm = alg.outer,
                signature = TestDer.tlv(0x03, TestDer.bytes(0x00), signature),
            )
        return cert(JcaFixtures.sign(alg.jca, signer, cert(ByteArray(0)).tbs, alg.params)).der
    }

    protected fun root(
        validity: ByteArray = WIDE,
        extensions: List<ByteArray> = caExtensions(),
    ): ByteArray = issue(ROOT, rootKey.public.encoded, ROOT, rootKey.private, extensions, validity)

    protected fun intermediate(
        extensions: List<ByteArray> = caExtensions(),
        subject: ByteArray = INTERMEDIATE,
        validity: ByteArray = WIDE,
        key: KeyPair = intermediateKey,
        spki: ByteArray = key.public.encoded,
        signer: KeyPair = rootKey,
        alg: Alg = RSA_SHA384,
    ): ByteArray = issue(subject, spki, ROOT, signer.private, extensions, validity, alg)

    protected fun leaf(
        extensions: List<ByteArray> = LEAF_EXTENSIONS,
        issuer: ByteArray = INTERMEDIATE,
        validity: ByteArray = WIDE,
        spki: ByteArray = leafKey.public.encoded,
        signer: KeyPair = intermediateKey,
        alg: Alg = if (signer.private.algorithm == "RSA") RSA_SHA384 else EC_SHA384,
    ): ByteArray = issue(LEAF, spki, issuer, signer.private, extensions, validity, alg)

    protected fun chain(
        leaf: ByteArray = leaf(),
        intermediate: ByteArray = intermediate(),
        root: ByteArray = root(),
    ): List<ByteArray> = listOf(leaf, intermediate, root)

    protected fun validate(
        chain: List<ByteArray>,
        pins: Set<ByteString> = pinned,
        with: SignatureVerifier = verifier,
    ): X5uChainResult = validateX5uChain(chain, pins, with)

    protected fun assertLoads(
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

    protected fun assertFails(
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

    protected fun live(path: X5uPath): X5uValidity = checkValidity(path, NOW)

    /** A leaf signed by the intermediate with the given encoding parts, for the DER rules. */
    protected fun leafParts(
        version: ByteArray = version(TestDer.bytes(2)),
        serial: ByteArray = TestDer.bytes(0x00, 0x8f, 0x12, 0x34),
        extensions: List<ByteArray> = LEAF_EXTENSIONS,
        wrapper: (List<ByteArray>) -> ByteArray = { TestDer.tlv(0xa3, TestDer.seq(*it.toTypedArray())) },
        tbsTrailing: ByteArray = ByteArray(0),
        signatureValue: (ByteArray) -> ByteArray = { TestDer.tlv(0x03, TestDer.bytes(0x00), it) },
        issuer: ByteArray = INTERMEDIATE,
    ): TestCert {
        fun cert(signature: ByteArray) =
            TestCert(
                version = version,
                serial = TestDer.tlv(0x02, serial),
                tbsSignature = EC_SHA384.id,
                issuer = issuer,
                validity = WIDE,
                subject = LEAF,
                spki = leafKey.public.encoded,
                extensions = extensions,
                extensionsWrapper = wrapper,
                tbsTrailing = tbsTrailing,
                outerAlgorithm = EC_SHA384.id,
                signature = signatureValue(signature),
            )
        return cert(JcaFixtures.sign(EC_SHA384.jca, intermediateKey.private, cert(ByteArray(0)).tbs))
    }

    // Helpers

    protected fun resource(path: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream(path)) { "missing $path" }.use { it.readBytes() }

    protected fun stub(answer: (ByteArray, ByteArray, ByteArray, ByteArray) -> VerifyResult): SignatureVerifier =
        object : SignatureVerifier {
            override fun verify(
                sigAlg: ByteArray,
                spki: ByteArray,
                message: ByteArray,
                signature: ByteArray,
            ): VerifyResult = answer(sigAlg, spki, message, signature)

            override fun unsupportedOids(): Set<String> = emptySet()
        }

    protected fun spkiOf(der: ByteArray): ByteArray =
        CertificateFactory
            .getInstance("X.509")
            .generateCertificate(der.inputStream())
            .publicKey.encoded

    companion object {
        const val CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
        const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
        const val OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
        const val OTHER_OID = "1.3.6.1.4.1.99999.2"
        const val NAME_CONSTRAINTS_OID = "2.5.29.30"
        const val TLS_FEATURE = "1.3.6.1.5.5.7.1.24"
        const val SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"
        const val OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5"
        const val NETSCAPE_CERT_TYPE = "2.16.840.1.113730.1.1"
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

        fun utc(text: String): ByteArray = TestDer.tlv(0x17, TestDer.ascii(text))

        fun generalized(text: String): ByteArray = TestDer.tlv(0x18, TestDer.ascii(text))

        /** The `[0] EXPLICIT Version` with INTEGER content [content]. */
        fun version(content: ByteArray): ByteArray = TestDer.tlv(0xa0, TestDer.tlv(0x02, content))

        /** [extension] with a critical BOOLEAN of `01` inserted after its OID. */
        fun criticalOne(extension: ByteArray): ByteArray {
            val oid = TestDer.oid(OTHER_OID)
            val rest = extension.copyOfRange(2 + oid.size, extension.size)
            return TestDer.seq(oid, TestDer.tlv(0x01, TestDer.bytes(0x01)), rest)
        }

        /** [cert] with its TBS re-written under an indefinite length (`30 80 … 00 00`). */
        fun indefinite(cert: TestCert): ByteArray {
            val tbs = cert.tbs
            val header = if (tbs[1].toInt() and 0x80 == 0) 2 else 2 + (tbs[1].toInt() and 0x7f)
            val body = TestDer.bytes(0x30, 0x80) + tbs.copyOfRange(header, tbs.size) + TestDer.bytes(0x00, 0x00)
            return TestDer.seq(body, cert.outerAlgorithm, cert.signature)
        }

        /** [cert] under a `Certificate` header whose length takes one octet more than it needs. */
        fun longCertificateHeader(cert: TestCert): ByteArray {
            val content = TestDer.concat(cert.tbs, cert.outerAlgorithm, cert.signature)
            val n = content.size
            return TestDer.tlvWithLength(0x30, TestDer.bytes(0x83, n shr 16, (n shr 8) and 0xff, n and 0xff), content)
        }

        /** An extension of an unassigned OID, which a second copy makes a duplicate. */
        fun dup(): ByteArray = TestDer.extension("1.3.6.1.4.1.99999.1", TestDer.tlv(0x05, ByteArray(0)))

        /** `RSAPublicKey` whose modulus has exactly [bits] significant bits, behind [leadingZeros] zero octets. */
        fun rsaPublicKey(
            bits: Int,
            leadingZeros: Int = 0,
            exponent: ByteArray = TestDer.bytes(0x01, 0x00, 0x01),
        ): ByteArray {
            val n =
                BigInteger.ONE
                    .shiftLeft(bits - 1)
                    .or(BigInteger.ONE)
                    .toByteArray()
            return TestDer.seq(TestDer.tlv(0x02, ByteArray(leadingZeros), n), TestDer.tlv(0x02, exponent))
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

        /** rustls-pki-types 1.15.1 `data/alg-rsa-pss-sha256.der` under its SEQUENCE header. */
        const val RSA_PSS_SHA256_HEX =
            "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c" +
                "301a06092a864886f70d010108300d06096086480165030402010500a203020120"

        /**
         * `id-RSASSA-PSS` with [hash] (NULL parameters), MGF1 on [mgfHash], salt [salt], and an explicit trailer 1 when
         * [trailer]: the exact encodings when [mgfHash] is [hash], [salt] its length and [trailer] false.
         */
        fun exactPss(
            hash: String,
            salt: Int,
            mgfHash: String = hash,
            trailer: Boolean = false,
        ): ByteArray =
            algId(
                PSS,
                TestDer.seq(
                    TestDer.tlv(0xa0, algId(hash, NULL)),
                    TestDer.tlv(0xa1, algId(JcaFixtures.MGF1, algId(mgfHash, NULL))),
                    TestDer.tlv(0xa2, JcaFixtures.integer(salt)),
                    if (trailer) TestDer.tlv(0xa3, JcaFixtures.integer(1)) else ByteArray(0),
                ),
            )

        /** A `GeneralSubtree` whose base is the dNSName [name]. */
        fun dnsTree(name: String): ByteArray = TestDer.seq(dns(name))

        /** `NameConstraints` with each subtree list written when not null. */
        fun constraints(
            permitted: List<ByteArray>?,
            excluded: List<ByteArray>? = null,
        ): ByteArray =
            TestDer.seq(
                permitted?.let { TestDer.tlv(0xa0, *it.toTypedArray()) } ?: ByteArray(0),
                excluded?.let { TestDer.tlv(0xa1, *it.toTypedArray()) } ?: ByteArray(0),
            )

        fun nameConstraints(
            value: ByteArray,
            critical: Boolean = false,
        ): ByteArray = TestDer.extension(NAME_CONSTRAINTS_OID, value, critical.takeIf { it })

        /** An `rsaEncryption` SPKI whose BIT STRING content is [content]. */
        fun rsaBits(content: ByteArray): ByteArray = TestDer.seq(algId(RSA_KEY, NULL), TestDer.tlv(0x03, content))

        /** `RSAPublicKey` with the modulus content [n] as given. */
        fun modulus(n: ByteArray): ByteArray = TestDer.seq(TestDer.tlv(0x02, n), JcaFixtures.integer(3))

        /** An `id-ecPublicKey` SPKI on [curve] (no parameters when null) with a placeholder point. */
        fun ecSpki(
            curve: String?,
            point: ByteArray = TestDer.bytes(0x04, *IntArray(64) { 1 }),
        ): ByteArray =
            JcaFixtures.spki(
                TestDer.seq(TestDer.oid(EC_KEY), curve?.let { TestDer.oid(it) } ?: ByteArray(0)),
                point,
            )
    }
}
