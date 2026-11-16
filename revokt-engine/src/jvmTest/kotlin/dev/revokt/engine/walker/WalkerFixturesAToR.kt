// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.NoIssuerReason
import dev.revokt.RevoktLimits
import dev.revokt.WalkEnd
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.budget
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import dev.revokt.engine.walker.FixtureWorld.Companion.PRINTABLE_STRING
import dev.revokt.engine.walker.FixtureWorld.Companion.TELETEX_STRING
import dev.revokt.testing.ChainGenerator
import dev.revokt.testing.CrossCertToNonAnchor
import dev.revokt.testing.SymOids
import dev.revokt.testing.World
import okio.ByteString.Companion.decodeHex

/**
 * The §9 walker fixture table, rows (a) to (r), with their expected Walk column (spec §9 "Walker fixtures", §5.1); rows
 * (s1) to (aj) are [WalkerFixturesS1ToAj]. Each function is one row id; a row with several cases (orders, counts)
 * returns one [WalkerFixture] per case. Counts the spec states are asserted as stated; the other counts are derived by
 * hand from §5.1's pseudocode and written next to the row. (j) and (j2) need the JCA verifier (#140).
 */
internal object WalkerFixturesAToR {
    /** A private-arc signature OID no fixture verifies under: only an outer `signatureAlgorithm` carries it. */
    private const val OTHER_SIGNATURE = "1.3.6.1.4.1.99999.91.3"

    /** (a) A fake issuer under a random key: one `INVALID` exploration, then the honest path. */
    fun a(): List<WalkerFixture> =
        with(Honest()) {
            val fake = w.cert("F", intermediate.subject, w.name("Attacker"))
            listOf(
                fixture(
                    "a",
                    presented = listOf(leaf, fake, intermediate),
                    // L/F invalid, L/I, I/R.
                    walk =
                        found(path).copy(
                            verifications = 3,
                            candidatesExplored = 3,
                            relatedExploredAtLeaf = 2,
                            unrelatedExploredAtLeaf = 0,
                        ),
                ),
            )
        }

    /**
     * (b) An ECDSA-recovered second key: F verifies the leaf but nothing certifies it, so its subtree is a dead end
     * (its only candidate, I, is unrelated to it and `INVALID`).
     */
    fun b(): List<WalkerFixture> =
        with(Honest()) {
            val recovered = w.cert("F", intermediate.subject, w.name("Attacker"))
            w.verifies(leaf, recovered.key)
            listOf(
                fixture(
                    "b",
                    presented = listOf(leaf, recovered, intermediate),
                    // L/F, F/I invalid, L/I, I/R.
                    walk = found(path).copy(verifications = 4, candidatesExplored = 4),
                ),
            )
        }

    /**
     * (c) An RSA duplicate-signature key, modelled as one more `ok` link (spec §9.1), in a certificate claiming the
     * root as its issuer: the root's key does not verify it.
     */
    fun c(): List<WalkerFixture> =
        with(Honest()) {
            val duplicate = w.cert("D", intermediate.subject, root.subject)
            w.verifies(leaf, duplicate.key)
            listOf(
                fixture(
                    "c",
                    presented = listOf(leaf, duplicate, intermediate),
                    // L/D, D/R invalid, D/I invalid (unrelated), L/I, I/R.
                    walk = found(path).copy(verifications = 5, candidatesExplored = 5),
                ),
            )
        }

    /**
     * (d) A recovered-key fake signed by the real anchor under an unsupported signature OID of its own: the link to the
     * anchor is `UNSUPPORTED`, never trusted, and the fake's own OID counts against that related anchor.
     */
    fun d(): List<WalkerFixture> =
        with(Honest()) {
            val fake =
                w.cert(
                    "F",
                    intermediate.subject,
                    root.subject,
                    signer = root.key,
                    sigOid = SymOids.UNSUPPORTED_SIGNATURE,
                )
            w.verifies(leaf, fake.key)
            listOf(
                fixture(
                    "d",
                    presented = listOf(leaf, fake, intermediate),
                    // L/F, F/R unsupported, F/I unsupported (unrelated, not counted), L/I, I/R.
                    walk =
                        found(path).copy(
                            unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE),
                            verifications = 5,
                            candidatesExplored = 5,
                        ),
                ),
            )
        }

    /** (e) 8, 16 and 63 distinct-key related junk ahead of the real intermediate: 63 + 1 is exactly the cap. */
    fun e(): List<WalkerFixture> =
        listOf(8, 16, 63).map { n ->
            with(Honest()) {
                fixture(
                    "e",
                    "$n junk",
                    presented = listOf(leaf) + junk(n) + intermediate,
                    walk =
                        found(path).copy(
                            verifications = n + 2,
                            candidatesExplored = n + 2,
                            relatedExploredAtLeaf = n + 1,
                        ),
                )
            }
        }

    /**
     * (f) A cross-signed chain with both roots in the snapshot: I under R1, and R1 cross-signed by R2. M1 reports the
     * first path only; the cross-certificate sorts after the store anchor at I and is never reached.
     */
    fun f(): List<WalkerFixture> {
        val w = FixtureWorld()
        val r1 = w.root("R1", "Root 1")
        val r2 = w.root("R2", "Root 2")
        val i = w.cert("I", w.name("Intermediate"), r1.subject, signer = r1.key)
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
        val cross = w.cert("X", r1.subject, r2.subject, r1.key, signer = r2.key)
        return listOf(listOf(leaf, i, cross), listOf(leaf, cross, i)).mapIndexed { n, presented ->
            w.fixture(
                "f",
                if (n == 0) "cross-certificate last" else "cross-certificate first",
                presented,
                listOf(r1, r2),
                found(listOf(leaf, i, r1)).copy(verifications = 2, candidatesExplored = 2),
            )
        }
    }

    /** (g) The intermediate omitted: no related candidate at the leaf, with and without the root presented. */
    fun g(): List<WalkerFixture> =
        with(Honest()) {
            listOf(
                fixture(
                    "g",
                    "leaf only",
                    presented = listOf(leaf),
                    walk = notFound(NoIssuerReason.NO_CANDIDATE).copy(verifications = 0, candidatesExplored = 0),
                ),
                fixture(
                    "g",
                    "root presented",
                    presented = listOf(leaf, root),
                    // The root is unrelated to the leaf: the unrelated loop tries it.
                    walk =
                        notFound(NoIssuerReason.NO_CANDIDATE).copy(
                            verifications = 1,
                            candidatesExplored = 1,
                            unrelatedExploredAtLeaf = 1,
                        ),
                ),
            )
        }

    /**
     * (h) A self-signed non-anchor S and an A↔B loop, each entered through a key that verifies the leaf: both are dead
     * ends, and the walk terminates.
     */
    fun h(): List<WalkerFixture> =
        with(Honest()) {
            val self = w.cert("S", intermediate.subject, intermediate.subject).also { w.verifies(it, it.key) }
            w.verifies(leaf, self.key)
            val bName = w.name("Loop B")
            val bKey = w.key()
            val a = w.cert("A", intermediate.subject, bName, signer = bKey)
            val b = w.cert("B", bName, intermediate.subject, bKey, signer = a.key)
            w.verifies(leaf, a.key)
            listOf(
                fixture(
                    "h",
                    presented = listOf(leaf, self, a, b, intermediate),
                    // S: L/S, S/A, S/I, S/B; A: L/A, A/B, B/S, B/I, A/S, A/I; I: L/I, I/R.
                    walk = found(path).copy(verifications = 12, candidatesExplored = 12, relatedExploredAtLeaf = 3),
                ),
            )
        }

    /** (i) 65 related junk at the leaf: the 65th is not explored. */
    fun i(): List<WalkerFixture> =
        with(Honest()) {
            listOf(
                fixture(
                    "i",
                    presented = listOf(leaf) + junk(RevoktLimits.MAX_RELATED_PER_LEVEL + 1) + intermediate,
                    walk =
                        budget(WalkEnd.RELATED_BUDGET, 1).copy(
                            verifications = 64,
                            candidatesExplored = 64,
                            relatedExploredAtLeaf = 64,
                        ),
                ),
            )
        }

    /**
     * (k) A same-key decoy with a garbage signature first, its issuer name the root's: the store anchor and the real
     * intermediate are tried under the decoy's signature before the leaf loop reaches I by a memo hit.
     */
    fun k(): List<WalkerFixture> =
        with(Honest()) {
            val decoy = w.cert("D", intermediate.subject, root.subject, intermediate.key)
            listOf(
                fixture(
                    "k",
                    presented = listOf(leaf, decoy, intermediate),
                    walk = found(path).copy(verifications = 4, candidatesExplored = 5),
                ),
            )
        }

    /**
     * (k2) The same with the decoy carrying an EC key under an RSA-signed leaf: the decoy does not verify the leaf, so
     * L/D, L/I and I/R. The second case adds an EC anchor with the root's name that sorts before the RSA root by
     * bytes hash: the RSA store candidate is still tried first at I (key-family order), so the count is unchanged.
     */
    fun k2(): List<WalkerFixture> =
        listOf(false, true).map { ecAnchor ->
            with(Honest(rsa = true)) {
                val decoy = w.cert("D", intermediate.subject, root.subject, w.key(WalkerCerts.EC_KEY, WalkerCerts.P256))
                val snapshot = if (ecAnchor) listOf(root, ecRootBefore(w, root)) else listOf(root)
                fixture(
                    "k2",
                    if (ecAnchor) "EC anchor with the root's name" else "",
                    presented = listOf(leaf, decoy, intermediate),
                    snapshot = snapshot,
                    walk = found(path).copy(verifications = 3, candidatesExplored = 3),
                )
            }
        }

    /** A self-signed EC root named like [root] whose bytes hash sorts before [root]'s. */
    private fun ecRootBefore(
        w: FixtureWorld,
        root: FixtureCert,
    ): FixtureCert {
        while (true) {
            val key = w.key(WalkerCerts.EC_KEY, WalkerCerts.P256)
            val ec = w.cert("R-EC", root.subject, root.subject, key, signer = key, sigOid = WalkerCerts.ECDSA_SHA256)
            if (ec.bytesHash < root.bytesHash) return ec
        }
    }

    /**
     * (l) A public cross-certificate X of I (I's subject and key) to a retired root T outside the snapshot, presented
     * first with T last: X verifies the leaf, T verifies X, and T's subtree is a dead end; I is then a memo hit.
     */
    fun l(): List<WalkerFixture> =
        with(Honest()) {
            val retired = w.root("T", "Retired root")
            val cross = w.cert("X", intermediate.subject, retired.subject, intermediate.key, signer = retired.key)
            listOf(
                fixture(
                    "l",
                    presented = listOf(leaf, cross, intermediate, retired),
                    // L/X, X/T, T/I invalid, X/I invalid, L/I memo hit, I/R.
                    walk = found(path).copy(verifications = 5, candidatesExplored = 6),
                ),
            )
        }

    /** (m) A sound path, then 62 related junk: the leaf still explores every related candidate (63 in total). */
    fun m(): List<WalkerFixture> =
        with(Honest()) {
            listOf(
                fixture(
                    "m",
                    presented = listOf(leaf, intermediate) + junk(62),
                    walk =
                        found(path).copy(
                            verifications = 64,
                            candidatesExplored = 64,
                            relatedExploredAtLeaf = 63,
                        ),
                ),
            )
        }

    /**
     * (n) An unsupported link on a dead branch, and a supported path found: B verifies the leaf, B's own signature OID
     * is unsupported against its related candidate E, and the walk is `Found` with that OID recorded.
     */
    fun n(): List<WalkerFixture> =
        with(Honest()) {
            val dead = w.name("Dead")
            val branch = w.cert("B", intermediate.subject, dead, sigOid = SymOids.UNSUPPORTED_SIGNATURE)
            w.verifies(leaf, branch.key)
            val e = w.cert("E", dead, dead).also { w.verifies(it, it.key) }
            listOf(
                fixture(
                    "n",
                    presented = listOf(leaf, branch, e, intermediate),
                    // L/B, B/E unsupported (related), B/I unsupported (unrelated), L/I, I/R.
                    walk =
                        found(path).copy(
                            unsupportedOids = setOf(SymOids.UNSUPPORTED_SIGNATURE),
                            verifications = 5,
                            candidatesExplored = 5,
                        ),
                ),
            )
        }

    /** (o) A second certified key that verifies the leaf: both keys are leaf keys. */
    fun o(): List<WalkerFixture> =
        with(Honest()) {
            val sub = subCa()
            listOf(
                fixture(
                    "o",
                    presented = listOf(leaf, sub, intermediate),
                    walk = found(listOf(leaf, sub, root), path).copy(verifications = 4, candidatesExplored = 4),
                ),
            )
        }

    /**
     * (p) PrintableString/UTF8String issuer-name mismatches at both links: the raw names differ, the platform's
     * canonical forms match, so I (presented) and R (the store's canonical group) are related.
     */
    fun p(): List<WalkerFixture> {
        val w = FixtureWorld()
        val h =
            Honest(
                w,
                leafIssuer = w.name("Intermediate", PRINTABLE_STRING),
                intermediateIssuer = w.name("Root", PRINTABLE_STRING),
            )
        return listOf(
            h.fixture(
                "p",
                presented = listOf(h.leaf, h.intermediate),
                walk = found(h.path).copy(verifications = 2, candidatesExplored = 2),
            ),
        )
    }

    /** (q) A depth-9 bridge, the intermediates presented in order and reversed. */
    fun q(): List<WalkerFixture> =
        listOf(false, true).map { reversed ->
            with(Deep(9)) {
                w.fixture(
                    "q",
                    if (reversed) "intermediates reversed" else "intermediates in order",
                    listOf(leaf) + if (reversed) intermediates.reversed() else intermediates,
                    listOf(root),
                    found(path).copy(verifications = 10, candidatesExplored = 10),
                )
            }
        }

    /**
     * (r) A TBS/outer signature OID mismatch on the leaf, and a NULL-vs-absent pair: both walk to `Found`. The
     * `AlgorithmIdMismatch` finding is decide's (#124, from `Cert.algorithmIdMismatch`), so the Walk carries none.
     */
    fun r(): List<WalkerFixture> =
        listOf(
            "OID mismatch" to TestDer.seq(TestDer.oid(OTHER_SIGNATURE)),
            "NULL vs absent" to TestDer.seq(TestDer.oid(SymOids.SIGNATURE), TestDer.bytes(0x05, 0x00)),
        ).map { (variant, outer) ->
            val w = FixtureWorld()
            val root = w.root("R", "Root")
            val i = w.cert("I", w.name("Intermediate"), root.subject, signer = root.key)
            val leaf =
                w.withOuterAlgorithm(
                    w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey()),
                    outer,
                )
            w.fixture(
                "r",
                variant,
                listOf(leaf, i),
                listOf(root),
                found(listOf(leaf, i, root)).copy(verifications = 2, candidatesExplored = 2),
            )
        }
}
