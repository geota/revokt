// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.NoIssuerReason
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.testing.SymOids

/**
 * Row (aq), proposed in #225: an issuer that is not an anchor must be a CA (basicConstraints `cA = TRUE`), as webpki
 * (`verify_cert.rs` `check_basic_constraints`, `EndEntityUsedAsCa`) and mozilla::pkix (`pkixcheck.cpp`
 * `CheckBasicConstraints`, `ERROR_CA_CERT_INVALID`) require. A non-CA candidate is a dead end before its link is
 * verified: it is explored, never verified, and its own signature OID still counts. A non-CA certificate here carries
 * a [FixtureWorld.leafKey], so [FixtureWorld.cert] writes no basicConstraints but the ones a case lists.
 */
internal object WalkerFixturesAq {
    /** basicConstraints values that do not make a CA, each with what it shows. */
    private val notCa: List<Pair<String, List<ByteArray>>> =
        listOf(
            "intermediate without basicConstraints" to emptyList(),
            "cA omitted (its DEFAULT FALSE)" to listOf(TestDer.basicConstraints(ca = false)),
            "cA explicitly FALSE" to listOf(bc(TestDer.tlv(0x01, TestDer.bytes(0x00)))),
            "cA 01, not DER: fails closed" to listOf(bc(TestDer.tlv(0x01, TestDer.bytes(0x01)))),
            "two basicConstraints with cA TRUE: fails closed" to
                List(2) { TestDer.basicConstraints(ca = true) },
        )

    private fun bc(content: ByteArray): ByteArray =
        TestDer.extension("2.5.29.19", TestDer.seq(content), critical = true)

    fun aq(): List<WalkerFixture> =
        intermediates() + signedByEndEntity() + attacker() + belowLeaf() + anchorWithoutBasicConstraints()

    /** leaf → I → R with I not a CA: `ALL_CANDIDATES_INVALID`, no verification. */
    private fun intermediates(): List<WalkerFixture> =
        notCa.map { (variant, extensions) ->
            val w = FixtureWorld()
            val root = w.root("R", "Root")
            val i =
                w.cert(
                    "I",
                    w.name("Intermediate"),
                    root.subject,
                    key = w.leafKey(),
                    signer = root.key,
                    extensions = extensions,
                )
            val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
            w.fixture(
                "aq",
                variant,
                listOf(leaf, i),
                listOf(root),
                notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 0, candidatesExplored = 1),
            )
        }

    /**
     * The attack the CA check closes: the attacker signs C, a CA certificate for a recovered key, with the key of its
     * own end-entity certificate F under the real root. C verifies the leaf; F is a dead end below it, and no candidate
     * of the leaf. C2 is C with an issuer name F's subject does not match, so F is no candidate at all.
     */
    private fun signedByEndEntity(): List<WalkerFixture> {
        val honest = Honest()
        val w = honest.w
        val f = w.cert("F", w.name("attacker.example"), honest.root.subject, w.leafKey(), signer = honest.root.key)
        val c =
            w.cert("C", honest.intermediate.subject, f.subject, signer = f.key).also { w.verifies(honest.leaf, it.key) }
        val c2 =
            w
                .cert("C2", honest.intermediate.subject, w.name("Elsewhere"), signer = f.key)
                .also { w.verifies(honest.leaf, it.key) }
        return listOf(
            "recovered key in a CA certificate signed by an end entity under the real root" to c,
            "the same with F not related to C2" to c2,
        ).map { (variant, ca) ->
            honest.fixture(
                "aq",
                variant,
                presented = listOf(honest.leaf, ca, f),
                // L/C, then C/F refused by the CA check; C2 has no candidate.
                walk =
                    notFound(NoIssuerReason.UNANCHORED).copy(
                        verifications = 1,
                        candidatesExplored = if (ca === c) 2 else 1,
                    ),
            )
        }
    }

    /**
     * The soundness case: E is an end-entity certificate the real root issued, named like the leaf's issuer, whose key
     * verifies the leaf (a recovered key, or any key the attacker holds a certificate for). Anyone can obtain such a
     * certificate, so E's key never becomes a leaf-issuer key: with the honest intermediate presented after it the
     * walk is `Found` through I alone; without it, `ALL_CANDIDATES_INVALID`. A probe-listed own signature OID on E is
     * still recorded (pkix checks the signature algorithm before basicConstraints).
     */
    private fun attacker(): List<WalkerFixture> {
        val honest = Honest()
        val e = honest.endEntity("E")
        val unsupported = honest.endEntity("E2", SymOids.UNSUPPORTED_SIGNATURE)
        return listOf(
            honest.fixture(
                "aq",
                "end-entity certificate under the real root, honest intermediate after it",
                presented = listOf(honest.leaf, e, honest.intermediate),
                walk =
                    found(honest.path).copy(verifications = 2, candidatesExplored = 3),
            ),
            honest.fixture(
                "aq",
                "end-entity certificate under the real root, intermediate omitted",
                presented = listOf(honest.leaf, e),
                walk =
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 0, candidatesExplored = 1),
            ),
            honest.fixture(
                "aq",
                "end-entity certificate with a probe-listed own signature OID",
                presented = listOf(honest.leaf, unsupported),
                walk =
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(
                        unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE),
                        verifications = 0,
                        candidatesExplored = 1,
                    ),
            ),
        )
    }

    /** [label]: an end-entity certificate under the root, named like the intermediate, whose key verifies the leaf. */
    private fun Honest.endEntity(
        label: String,
        sigOid: String = SymOids.SIGNATURE,
    ): FixtureCert =
        w
            .cert(label, intermediate.subject, root.subject, w.leafKey(), signer = root.key, sigOid = sigOid)
            .also { w.verifies(leaf, it.key) }

    /**
     * leaf → I1 → I2 → R with I2 not a CA: I1 verifies the leaf and I2 is a dead end at I1, so the walk is
     * `UNANCHORED` after one verification.
     */
    private fun belowLeaf(): List<WalkerFixture> {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val i2 = w.cert("I2", w.name("Intermediate 2"), root.subject, w.leafKey(), signer = root.key)
        val i1 = w.cert("I1", w.name("Intermediate 1"), i2.subject, signer = i2.key)
        val leaf = w.cert("L", w.name("leaf.example"), i1.subject, signer = i1.key, key = w.leafKey())
        return listOf(
            w.fixture(
                "aq",
                "non-CA certificate below the leaf's issuer",
                listOf(leaf, i1, i2),
                listOf(root),
                notFound(NoIssuerReason.UNANCHORED).copy(verifications = 1, candidatesExplored = 2),
            ),
        )
    }

    /** An anchor is never checked, as webpki's `TrustAnchor` has no extensions: a v3 root without them terminates. */
    private fun anchorWithoutBasicConstraints(): List<WalkerFixture> {
        val w = FixtureWorld()
        val name = w.name("Root")
        val key = w.leafKey()
        val root = w.cert("R", name, name, key, signer = key)
        val i = w.cert("I", w.name("Intermediate"), root.subject, signer = root.key)
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
        return listOf(
            w.fixture(
                "aq",
                "anchor without basicConstraints",
                listOf(leaf, i),
                listOf(root),
                found(listOf(leaf, i, root)).copy(verifications = 2, candidatesExplored = 2),
            ),
        )
    }
}
