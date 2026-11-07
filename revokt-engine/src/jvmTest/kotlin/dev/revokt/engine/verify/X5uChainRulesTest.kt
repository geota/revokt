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
 * The x5u chain's encoding and extension rules beyond fixture (d): mozilla::pkix's DER and time rules, validity
 * windows, duplicate, malformed and critical extensions, a CA leaf and a CA's extKeyUsage (review round 1 of #170 and
 * the maintainer decision of 2026-11-06, pending in the next spec revision).
 */
internal class X5uChainRulesTest : X5uChainFixture() {
    @Test
    fun `validateX5uChain never checks a validity period`() {
        val past = window("19900101000000Z", "20000101000000Z")
        val path = assertLoads(chain(leaf(validity = past), intermediate(validity = past), root(validity = past)))
        assertEquals(0, assertIs<X5uValidity.ClockSkew>(live(path)).certIndex)
        // A window that is not two DER times in order is not DER (mozilla::pkix's ERROR_INVALID_DER_TIME): FAILED.
        assertFails(PARSE, 0, chain(leaf = leaf(validity = window("20300101000000Z", "20200101000000Z"))))
        assertFails(
            PARSE,
            1,
            chain(intermediate = intermediate(validity = window("20300101000000Z", "20200101000000Z"))),
        )
        assertLoads(chain(leaf = leaf(validity = window("20300101000000Z", "20300101000000Z"))))
    }

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
        // The leaf's basicConstraints and keyUsage are read too (maintainer decision 2026-11-06), and the CA's EKU.
        assertFails(EXTENSION, 0, chain(leaf = leaf(LEAF_EXTENSIONS + badBoolean)))
        assertFails(EXTENSION, 0, chain(leaf = leaf(LEAF_EXTENSIONS.drop(1) + emptyKu)))
        assertFails(EXTENSION, 1, chain(intermediate = intermediate(ca + emptyEku)))
    }

    @Test
    fun `a leaf with cA TRUE is FAILED`() {
        assertFails(LEAF_CA, 0, chain(leaf = leaf(LEAF_EXTENSIONS + bc(ca = true))))
        assertFails(LEAF_CA, 0, chain(leaf = leaf(LEAF_EXTENSIONS + bc(ca = true, pathLen = 0))))
        assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + bc(ca = false))))
        assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + bc(ca = null, pathLen = 3))))
    }

    @Test
    fun `a CA whose extKeyUsage lacks codeSigning is FAILED, the terminal's never read`() {
        val ca = listOf(bc(ca = true), ku(KEY_CERT_SIGN, CRL_SIGN))
        assertFails(EKU, 1, chain(intermediate = intermediate(ca + eku(SERVER_AUTH))))
        assertLoads(chain(intermediate = intermediate(ca)))
        assertLoads(chain(intermediate = intermediate(ca + eku(SERVER_AUTH, CODE_SIGNING))))
        // An OCSPSigning CA is fine, as in mozilla::pkix.
        assertLoads(chain(intermediate = intermediate(ca + eku(CODE_SIGNING, OCSP_SIGNING))))
        assertLoads(chain(root = root(extensions = ca + eku(SERVER_AUTH))))
    }

    @Test
    fun `a critical extension mozilla pkix does not understand, or enforces, is FAILED`() {
        val value = TestDer.seq()
        for (oid in listOf(OTHER_OID, "2.5.29.14", "2.5.29.35", "2.5.29.31")) {
            val critical = TestDer.extension(oid, value, critical = true)
            assertFails(EXTENSION, 0, chain(leaf = leaf(LEAF_EXTENSIONS + critical)))
            assertFails(EXTENSION, 1, chain(intermediate = intermediate(caExtensions() + critical)))
            // Non-critical, each is ignored; and the terminal is never read.
            assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + TestDer.extension(oid, value))))
            assertLoads(chain(root = root(extensions = caExtensions() + critical)))
        }
        // Understood ones load critical: certificatePolicies, policyConstraints, inhibitAnyPolicy, AIA, qcStatements,
        // the SCT list, and ocsp-nocheck (also empty).
        for (oid in listOf(
            "2.5.29.32",
            "2.5.29.36",
            "2.5.29.54",
            "1.3.6.1.5.5.7.1.1",
            "1.3.6.1.5.5.7.1.3",
            SCT_LIST,
            TLS_FEATURE,
        )) {
            val ext =
                TestDer.extension(
                    oid,
                    if (oid ==
                        SCT_LIST
                    ) {
                        TestDer.tlv(0x04, TestDer.bytes(0x00, 0x00))
                    } else {
                        value
                    },
                    true,
                )
            assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + ext)))
        }
        for (v in listOf(NULL, ByteArray(0))) {
            assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + TestDer.extension(OCSP_NOCHECK, v, critical = true))))
        }
        // An understood extension may not be empty.
        assertFails(
            EXTENSION,
            0,
            chain(
                leaf =
                    leaf(LEAF_EXTENSIONS + TestDer.extension("1.3.6.1.5.5.7.1.1", ByteArray(0))),
            ),
        )
        assertFails(
            EXTENSION,
            0,
            chain(leaf = leaf(LEAF_EXTENSIONS + TestDer.extension(NAME_CONSTRAINTS, ByteArray(0)))),
        )
        // A critical Netscape certificate type only beside basicConstraints and extKeyUsage (BackCert::Init).
        val netscape =
            TestDer.extension(
                NETSCAPE_CERT_TYPE,
                TestDer.tlv(0x03, TestDer.bytes(0x07, 0x80)),
                critical = true,
            )
        assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + bc(ca = false) + netscape)))
        assertFails(EXTENSION, 0, chain(leaf = leaf(LEAF_EXTENSIONS + netscape)))
        assertFails(EXTENSION, 0, chain(leaf = leaf(listOf(bc(ca = false), san(dns(X5U_LEAF_NAME)), netscape))))
    }

    @Test
    fun `a CA's TLS feature must be carried by its child, as CheckTLSFeatures requires`() {
        val statusRequest = TestDer.extension(TLS_FEATURE, TestDer.seq(JcaFixtures.integer(5)))
        val other = TestDer.extension(TLS_FEATURE, TestDer.seq(JcaFixtures.integer(17)))
        assertFails(EXTENSION, 1, chain(intermediate = intermediate(caExtensions() + statusRequest)))
        assertFails(
            EXTENSION,
            1,
            chain(
                leaf = leaf(LEAF_EXTENSIONS + other),
                intermediate =
                    intermediate(caExtensions() + statusRequest),
            ),
        )
        assertLoads(
            chain(
                leaf = leaf(LEAF_EXTENSIONS + statusRequest),
                intermediate =
                    intermediate(caExtensions() + statusRequest),
            ),
        )
        // Only a CA's feature binds; the leaf's alone, and the terminal's, are not checked.
        assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + statusRequest)))
        assertLoads(chain(root = root(extensions = caExtensions() + statusRequest)))
    }

    @Test
    fun `nameConstraints are enforced on every CA below the terminal, critical or not`() {
        val mozilla =
            constraints(
                permitted = listOf(dnsTree(".content-signature.mozilla.org"), dnsTree("content-signature.mozilla.org")),
            )
        for (critical in listOf(false, true)) {
            assertLoads(chain(intermediate = intermediate(caExtensions() + nameConstraints(mozilla, critical))))
        }
        for (permitted in listOf(
            "onecrl.content-signature.mozilla.org",
            "ONECRL.Content-Signature.Mozilla.ORG",
            "mozilla.org",
            "",
        )) {
            assertLoads(
                chain(
                    intermediate =
                        intermediate(caExtensions() + nameConstraints(constraints(listOf(dnsTree(permitted))))),
                ),
            )
        }
        // Outside: another name, a leading-dot subtree of the name itself, a suffix that is not a label boundary.
        for (permitted in listOf("other.example", ".onecrl.content-signature.mozilla.org", "signature.mozilla.org")) {
            assertFails(
                NAME,
                1,
                chain(
                    intermediate =
                        intermediate(caExtensions() + nameConstraints(constraints(listOf(dnsTree(permitted))))),
                ),
            )
        }
        for (excluded in listOf("content-signature.mozilla.org", ".mozilla.org", "")) {
            val tree = constraints(permitted = null, excluded = listOf(dnsTree(excluded)))
            assertFails(NAME, 1, chain(intermediate = intermediate(caExtensions() + nameConstraints(tree))))
        }
        assertLoads(
            chain(
                intermediate =
                    intermediate(caExtensions() + nameConstraints(constraints(null, listOf(dnsTree("other.example"))))),
            ),
        )
        // Any form revokt does not evaluate fails closed.
        val email = TestDer.seq(TestDer.tlv(0x81, TestDer.ascii("a@content-signature.mozilla.org")))
        val directory = TestDer.seq(TestDer.tlv(0xa4, TestCert.name("x")))
        val withMinimum = TestDer.seq(dns("content-signature.mozilla.org"), TestDer.tlv(0x80, TestDer.bytes(0)))
        for (value in listOf(
            constraints(listOf(email)),
            constraints(listOf(dnsTree("content-signature.mozilla.org")), listOf(directory)),
            constraints(listOf(withMinimum)),
            constraints(listOf(dnsTree("*.mozilla.org"))),
            constraints(listOf()),
            TestDer.seq(),
            TestDer.seq(TestDer.tlv(0xa0, TestDer.seq(dns("content-signature.mozilla.org"))), NULL),
            TestDer.seq(
                TestDer.tlvWithLength(0xa0, TestDer.bytes(0x81, 0x21), dnsTree("content-signature.mozilla.org")),
            ),
        )) {
            assertFails(EXTENSION, 1, chain(intermediate = intermediate(caExtensions() + nameConstraints(value))))
        }
        // An upper CA's constraints bind the leaf too; the leaf's own and the terminal's are never read.
        val subKey = ecPair("x5u-sub")
        val sub = TestCert.name("Sub Intermediate")
        val outside = nameConstraints(constraints(listOf(dnsTree("other.example"))))
        assertFails(
            NAME,
            2,
            listOf(
                issue(LEAF, leafKey.public.encoded, sub, subKey.private, LEAF_EXTENSIONS),
                issue(sub, subKey.public.encoded, INTERMEDIATE, intermediateKey.private, caExtensions()),
                intermediate(caExtensions() + outside),
                root(),
            ),
        )
        assertLoads(chain(leaf = leaf(LEAF_EXTENSIONS + outside)))
        assertLoads(chain(root = root(extensions = caExtensions() + outside)))
    }

    @Test
    fun `a link that is not DER as mozilla pkix reads it is FAILED`() {
        val nonMinimalValue =
            TestDer.seq(TestDer.oid(OTHER_OID), TestDer.tlvWithLength(0x04, TestDer.bytes(0x81, 0x02), NULL))
        val trailingInExtension = TestDer.seq(TestDer.oid(OTHER_OID), TestDer.tlv(0x04, NULL), NULL)
        for (der in listOf(
            leafParts(extensions = LEAF_EXTENSIONS + listOf(nonMinimalValue)).der,
            leafParts(extensions = LEAF_EXTENSIONS + listOf(trailingInExtension)).der,
            leafParts(wrapper = { TestDer.tlv(0xa3, TestDer.seq(*it.toTypedArray()), NULL) }).der,
            leafParts(wrapper = { NULL + TestDer.tlv(0xa3, TestDer.seq(*it.toTypedArray())) }).der,
            leafParts(tbsTrailing = NULL).der,
            leafParts(signatureValue = { TestDer.tlv(0x03, TestDer.bytes(0x01), it) }).der,
            leafParts(signatureValue = { TestDer.tlv(0x03) }).der,
            leafParts(version = version(TestDer.bytes(4))).der,
            leafParts(version = version(TestDer.bytes(0xff))).der,
            leafParts(version = version(TestDer.bytes(0x00, 0x02))).der,
            leafParts(extensions = LEAF_EXTENSIONS + TestDer.extension(OTHER_OID, NULL).let(::criticalOne)).der,
            indefinite(leafParts()),
            longCertificateHeader(leafParts()),
        )) {
            assertFails(PARSE, 0, chain(leaf = der))
        }
        // What mozilla::pkix accepts: v1 (absent, or explicit as bug 1031093 allows), v2 and v4 read like v3, and an
        // explicit critical FALSE.
        for (v in listOf(ByteArray(0), version(TestDer.bytes(0)), version(TestDer.bytes(1)), version(TestDer.bytes(3)))) {
            assertLoads(chain(leaf = leafParts(version = v).der))
        }
        assertLoads(
            chain(leaf = leafParts(extensions = LEAF_EXTENSIONS + TestDer.extension(OTHER_OID, NULL, false)).der),
        )
    }

    @Test
    fun `validity times must be in DER form`() {
        val good = TestDer.tlv(0x18, TestDer.ascii("20500101000000Z"))
        for (text in listOf(
            "2610221345Z",
            "261022134530",
            "261022134530+0000",
            "691231235959Z",
            "500101000000Z",
        )) {
            assertFails(PARSE, 0, chain(leaf = leaf(validity = TestDer.seq(utc(text), good))))
        }
        for (text in listOf(
            "20261022134530.5Z",
            "20261022134530+0100",
            "19691231235959Z",
            "20251301000000Z",
            "20250001000000Z",
            "20250100000000Z",
            "20250132000000Z",
            "20250229000000Z",
            "21000229000000Z",
            "20250431000000Z",
            "20250101240000Z",
            "20250101006000Z",
            "20250101000060Z",
            "2025010100000aZ",
            "202501010000a0Z",
            "202501010000/0Z",
            "2025010100000/Z",
            "20250101000000z",
        )) {
            assertFails(PARSE, 0, chain(leaf = leaf(validity = TestDer.seq(generalized(text), good))))
            assertFails(PARSE, 0, chain(leaf = leaf(validity = TestDer.seq(utc("700101000000Z"), generalized(text)))))
        }
        // The decoded millisecond, against java.time, at the edges of the ranges.
        for ((time, instant) in listOf(
            utc("700101000000Z") to "1970-01-01T00:00:00Z",
            utc("491231235959Z") to "2049-12-31T23:59:59Z",
            utc("990228120000Z") to "1999-02-28T12:00:00Z",
            generalized("20000229120000Z") to "2000-02-29T12:00:00Z",
            generalized("20240229000000Z") to "2024-02-29T00:00:00Z",
            generalized("20250430235959Z") to "2025-04-30T23:59:59Z",
            generalized("20251231235959Z") to "2025-12-31T23:59:59Z",
            generalized("99991231235959Z") to "9999-12-31T23:59:59Z",
        )) {
            val path = assertLoads(chain(leaf = leaf(validity = TestDer.seq(utc("700101000000Z"), time))))
            assertEquals(0L..millis(instant), path.windows[0])
        }
    }

    @Test
    fun `an empty issuer name is FAILED`() {
        assertFails(NAME, 0, chain(leaf = leafParts(issuer = TestDer.seq()).der))
    }

    @Test
    fun `a leaf that may also sign OCSP responses is FAILED`() {
        val extensions = listOf(ku(DIGITAL_SIGNATURE), eku(CODE_SIGNING, OCSP_SIGNING), san(dns(X5U_LEAF_NAME)))
        assertFails(EKU, 0, chain(leaf = leaf(extensions)))
    }
}
