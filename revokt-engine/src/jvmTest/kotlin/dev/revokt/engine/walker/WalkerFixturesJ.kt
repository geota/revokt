// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class, RevoktTestingApi::class)

package dev.revokt.engine.walker

import dev.revokt.FallbackReason
import dev.revokt.Finding
import dev.revokt.Layer
import dev.revokt.NoIssuerReason
import dev.revokt.PathBuilderFallback
import dev.revokt.PathReason
import dev.revokt.PathStatus
import dev.revokt.PkixPathBuilderFallback
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import dev.revokt.SignatureVerifier
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.TestCert
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.Want.Companion.noIssuer
import dev.revokt.verify.JcaFixtures
import dev.revokt.verify.JcaSignatureVerifier
import dev.revokt.verify.JdkFacts
import okio.ByteString
import java.security.Security
import kotlin.test.assertTrue

/**
 * Walker fixtures (j) and (j2) (spec §9 "Walker fixtures"; #140): real certificates under #108's [JcaSignatureVerifier]
 * and, on the enabled path, #127's real [PkixPathBuilderFallback] on the same JDK, since a reference builder
 * ([SymPathBuilder]) would find the ML-DSA path a real PKIX builder on a JDK without ML-DSA cannot.
 *
 * - **(j)** leaf → I → R, R an ML-DSA-44 anchor that signed I, I a P-256 CA that signed the leaf. The walk runs a
 *   provider-limited `JcaSignatureVerifier(SunEC)`: no SunEC on any matrix JDK has ML-DSA, so the row runs on every JDK
 *   rather than being skipped on those that ship it (Appendix A: 24+, 17.0.21, 21.0.13). I's own ML-DSA OID is then
 *   probe-listed and recorded, the I/R link is `UNSUPPORTED`, and the walk is `NotFound(UNANCHORED)`:
 *   `NO_ISSUER(UNSUPPORTED_ALGORITHM)`. [PkixPathBuilderFallback] runs over the installed providers and takes no
 *   provider, so it is the JDK's own. The case a JDK without ML-DSA meets is written with an ML-DSA signature no
 *   builder verifies, so it runs on every JDK: the fallback fails and the decision is the same on both paths. On a JDK
 *   with ML-DSA a second case makes that signature a real one: the builder verifies it, and the enabled path is the
 *   fallback's `Found`.
 * - **(j2)** a leaf signed by a brainpoolP256r1 anchor, under the default verifier: SunEC has no brainpool on any
 *   matrix JDK (Appendix A), so the curve OID makes the link `UNSUPPORTED` before any parse. The curve OID is the
 *   candidate's, never recorded, so the walk is `NotFound(ALL_CANDIDATES_INVALID)` with no `UnsupportedAlgorithm`. No
 *   JDK provider can sign under that key, so the leaf's signature is a placeholder, and the PKIX fallback fails too.
 */
internal object WalkerFixturesJ {
    /** Valid at [WalkerHarness.NOW], which the PKIX builder checks; `UTCTime` with seconds, inside §9.2's K6. */
    private val validity: ByteArray =
        TestDer.seq(
            TestDer.tlv(0x17, TestDer.ascii("250101000000Z")),
            TestDer.tlv(0x18, TestDer.ascii("20500101000000Z")),
        )

    private const val ML_DSA_44_SPKI = "oracle/ml-dsa-44-spki.der"

    /** FIPS 204's ML-DSA-44 signature length. */
    private const val ML_DSA_44_SIGNATURE = 2420

    /**
     * (j): the case a JDK without ML-DSA meets, whose PKIX builder cannot verify R's signature on I, on every JDK; and,
     * on a JDK that ships ML-DSA, the same chain with that signature a real one, which its builder verifies.
     */
    fun j(): List<DecisionRow> =
        listOfNotNull(j(realSignature = false), if (JdkFacts.shipsMlDsa()) j(realSignature = true) else null)

    private fun j(realSignature: Boolean): DecisionRow {
        val mlDsaAlg = JcaFixtures.algId(JcaFixtures.ML_DSA_44)
        val rootPair = if (realSignature) JcaFixtures.generate("ML-DSA-44") else null
        val rootSpki = rootPair?.public?.encoded ?: resource(ML_DSA_44_SPKI)
        // Without a real one, an ML-DSA-44-sized signature that no provider verifies.
        val signByRoot = { tbs: ByteArray ->
            rootPair?.let { JcaFixtures.sign("ML-DSA-44", it.private, tbs) } ?: ByteArray(ML_DSA_44_SIGNATURE) { 0x5a }
        }
        val i = JcaFixtures.ec("secp256r1")
        val labels = Labels()
        val root = labels.issue("R", "PQ Root", rootSpki, "PQ Root", mlDsaAlg, signByRoot, ca = true)
        val intermediate =
            labels.issue("I", "Intermediate", i.public.encoded, "PQ Root", mlDsaAlg, signByRoot, ca = true)
        val leaf =
            labels.issue(
                "L",
                "leaf.example",
                JcaFixtures.generate("Ed25519").public.encoded,
                "Intermediate",
                JcaFixtures.algId(JcaFixtures.ECDSA_SHA256),
                { JcaFixtures.sign("SHA256withECDSA", i.private, it) },
                ca = false,
            )
        val sunEc = JcaSignatureVerifier(Security.getProvider("SunEC"))
        assertTrue(JcaFixtures.ML_DSA_44 in sunEc.unsupportedOids(), "SunEC has no ML-DSA")
        val variant = if (realSignature) "the JDK's builder verifies ML-DSA" else "no builder verifies the ML-DSA link"
        // L/I verified, I/R unsupported.
        val f = labels.fixture("j", variant, listOf(leaf, intermediate), root, explorations = 2)
        val disabled =
            Want(
                PathStatus.NO_ISSUER,
                Verdicts.NO_ISSUER,
                PathReason.UNSUPPORTED_ALGORITHM,
                NoIssuerReason.UNANCHORED,
                notUsed = FallbackReason.DISABLED,
                findings = listOf(mlDsaUnsupported(depended = true)),
            )
        val enabled =
            if (realSignature) {
                Want(
                    PathStatus.FOUND,
                    Verdicts.HONEST,
                    walkerReason = NoIssuerReason.UNANCHORED,
                    usedFallback = true,
                    path = listOf("L", "I", "R"),
                    findings = listOf(mlDsaUnsupported(depended = false)),
                )
            } else {
                disabled.copy(notUsed = FallbackReason.FAILED)
            }
        return row(f, sunEc, enabled, disabled)
    }

    /** (j2): the brainpool anchor on SunEC. */
    fun j2(): List<DecisionRow> {
        val verifier = JcaSignatureVerifier()
        assertTrue(JcaFixtures.BRAINPOOL_P256 in verifier.unsupportedOids(), "SunEC has no brainpool")
        val ecdsa = JcaFixtures.algId(JcaFixtures.ECDSA_SHA256)
        val brainpool =
            TestDer.seq(
                TestDer.seq(TestDer.oid(JcaFixtures.EC_KEY), TestDer.oid(JcaFixtures.BRAINPOOL_P256)),
                TestDer.tlv(0x03, TestDer.bytes(0x00, 0x04), ByteArray(64) { 0x11 }),
            )
        // No provider here signs under a brainpool key: the signatures are placeholders the link never reads.
        val placeholder = { _: ByteArray ->
            TestDer.seq(TestDer.tlv(0x02, TestDer.bytes(1)), TestDer.tlv(0x02, TestDer.bytes(1)))
        }
        val labels = Labels()
        val root = labels.issue("R", "Brainpool Root", brainpool, "Brainpool Root", ecdsa, placeholder, ca = true)
        val leaf =
            labels.issue(
                "L",
                "leaf.example",
                JcaFixtures.generate("Ed25519").public.encoded,
                "Brainpool Root",
                ecdsa,
                placeholder,
                ca = false,
            )
        // L/R unsupported: one verifier call, one exploration.
        val f = labels.fixture("j2", "", listOf(leaf), root, 1)
        return listOf(row(f, verifier, noIssuer(NoIssuerReason.ALL_CANDIDATES_INVALID), honest = "R"))
    }

    private fun row(
        f: WalkerFixture,
        verifier: SignatureVerifier,
        enabled: Want,
        disabled: Want = enabled.onDisabledPath(),
        honest: String = "I",
    ): DecisionRow =
        DecisionRow(
            f,
            enabled,
            disabled,
            honest = honest,
            fallback = { PkixPathBuilderFallback() },
            decide = { fallback -> decide(f, verifier, fallback) },
        )

    /** Decision steps 1 to 6 in the walker-only harness, with [verifier] and its own startup probe. */
    private fun decide(
        f: WalkerFixture,
        verifier: SignatureVerifier,
        fallback: PathBuilderFallback?,
    ): PathDecision {
        val context =
            DecideContext(
                verifier,
                verifier.unsupportedOids(),
                lruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
                fallback,
                WalkerHarness.NOW,
                platformOnly = false,
            )
        return decideWalkerHarness(f.presented, CandidateIndex(f.snapshot), WalkerHarness.snapshot(f.snapshot), context)
    }

    private fun mlDsaUnsupported(depended: Boolean): Finding =
        Finding.UnsupportedAlgorithm
            .Builder()
            .oid(JcaFixtures.ML_DSA_44)
            .where(Layer.PATH)
            .outcomeDepended(depended)
            .build()

    private fun resource(name: String): ByteArray =
        checkNotNull(CertificateParser::class.java.getResourceAsStream(name)) { "missing $name" }.use { it.readBytes() }

    /** The certificates of one row and their labels. */
    private class Labels {
        private val byHash = HashMap<ByteString, String>()
        private var serial = 0

        /** A v3 certificate for [spki] named [subject], issued by [issuer] under [sigAlg], its signature [sign]'s. */
        fun issue(
            label: String,
            subject: String,
            spki: ByteArray,
            issuer: String,
            sigAlg: ByteArray,
            sign: (ByteArray) -> ByteArray,
            ca: Boolean,
        ): ByteArray {
            val n = ++serial
            val cert = { signature: ByteArray ->
                TestCert(
                    serial = TestDer.tlv(0x02, TestDer.bytes(0x01, n)),
                    tbsSignature = sigAlg,
                    issuer = TestCert.name(issuer),
                    validity = validity,
                    subject = TestCert.name(subject),
                    spki = spki,
                    extensions = if (ca) listOf(TestDer.basicConstraints(ca = true)) else emptyList(),
                    outerAlgorithm = sigAlg,
                    signature = signature,
                )
            }
            val tbs = cert(TestDer.tlv(0x03, TestDer.bytes(0x00))).tbs
            val der = cert(TestDer.tlv(0x03, TestDer.bytes(0x00), sign(tbs))).der
            byHash[WalkerHarness.hash(der)] = label
            return der
        }

        /** The row's fixture; its Walk column is the counts alone, the decision columns assert the rest. */
        fun fixture(
            id: String,
            variant: String,
            presented: List<ByteArray>,
            anchor: ByteArray,
            explorations: Int,
        ): WalkerFixture =
            WalkerFixture(
                id,
                variant,
                presented,
                listOf(anchor),
                emptySet(),
                ExpectedWalk(
                    ExpectedWalk.Kind.NOT_FOUND,
                    verifications = explorations,
                    candidatesExplored = explorations,
                ),
                label = { byHash[it] ?: it.hex().take(8) },
            )
    }
}
