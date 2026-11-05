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
 * The §9 walker fixture table, the rows the walker-only harness runs in 0.2 with their expected Walk column (spec §9
 * "Walker fixtures", §5.1). Each function is one row id; a row with several cases (orders, counts) returns one
 * [WalkerFixture] per case. Counts the spec states are asserted as stated; the other counts are derived by hand from
 * §5.1's pseudocode and written next to the row.
 *
 * (j) and (j2) need the JCA verifier (#140); (x), (ab) and (ag) end before decision step 5; (u) and (y3) are 0.3 and M2.
 */
internal object WalkerFixtures {
    /** A private-arc signature OID no fixture verifies under: only an outer `signatureAlgorithm` carries it. */
    private const val OTHER_SIGNATURE = "1.3.6.1.4.1.99999.91.3"

    /** leaf → I → R with R in the snapshot, the chain most rows start from. */
    class Honest(
        val w: FixtureWorld = FixtureWorld(),
        leafIssuer: ByteArray? = null,
        intermediateIssuer: ByteArray? = null,
        rsa: Boolean = false,
        leafAki: ByteArray? = null,
    ) {
        private val sig = if (rsa) WalkerCerts.SHA256_RSA else SymOids.SIGNATURE
        val root: FixtureCert = w.root("R", "Root", if (rsa) w.key(WalkerCerts.RSA_KEY) else w.key(), sig)
        val intermediate: FixtureCert =
            w.cert(
                "I",
                w.name("Intermediate"),
                intermediateIssuer ?: root.subject,
                if (rsa) w.key(WalkerCerts.RSA_KEY) else w.key(),
                signer = root.key,
                sigOid = sig,
            )
        val leaf: FixtureCert =
            w.cert(
                "L",
                w.name("leaf.example"),
                leafIssuer ?: intermediate.subject,
                signer = intermediate.key,
                sigOid = sig,
                aki = leafAki,
            )

        /** The honest path. */
        val path: List<FixtureCert> get() = listOf(leaf, intermediate, root)

        /** A certificate named like the intermediate under a fresh key no link names: an `INVALID` exploration. */
        fun junk(
            n: Int,
            subject: ByteArray = intermediate.subject,
        ): List<FixtureCert> = List(n) { w.cert("J$it", subject, w.name("Junk issuer $it")) }

        fun fixture(
            id: String,
            variant: String = "",
            presented: List<FixtureCert>,
            walk: ExpectedWalk,
            snapshot: List<FixtureCert> = listOf(root),
            customCanonicaliser: Boolean = false,
        ): WalkerFixture = w.fixture(id, variant, presented, snapshot, walk, customCanonicaliser)
    }

    fun FixtureWorld.fixture(
        id: String,
        variant: String,
        presented: List<FixtureCert>,
        snapshot: List<FixtureCert>,
        walk: ExpectedWalk,
        customCanonicaliser: Boolean = false,
    ): WalkerFixture =
        WalkerFixture(
            id = id,
            variant = variant,
            presented = presented.map { it.der },
            snapshot = snapshot.map { it.der },
            ok = ok,
            walk = walk,
            customCanonicaliser = customCanonicaliser,
            label = ::label,
        )

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
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key)
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

    /** (o)'s attacker sub-CA: a second key that verifies the leaf, certified under the real root. */
    private fun Honest.subCa(): FixtureCert =
        w.cert("S", intermediate.subject, root.subject, signer = root.key).also { w.verifies(leaf, it.key) }

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

    /** A chain of [depth] intermediates under one root: leaf, I1 … I`depth` (I1 issued the leaf), root. */
    class Deep(
        depth: Int,
        val w: FixtureWorld = FixtureWorld(),
    ) {
        val root: FixtureCert = w.root("R", "Root")
        val intermediates: List<FixtureCert>
        val leaf: FixtureCert

        init {
            val chain = ArrayList<FixtureCert>()
            var parent = root
            for (n in depth downTo 1) {
                parent = w.cert("I$n", w.name("Intermediate $n"), parent.subject, signer = parent.key)
                chain.add(0, parent)
            }
            intermediates = chain
            leaf = w.cert("L", w.name("leaf.example"), parent.subject, signer = parent.key)
        }

        val path: List<FixtureCert> get() = listOf(leaf) + intermediates + root
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
            val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, outerAlgorithm = outer)
            w.fixture(
                "r",
                variant,
                listOf(leaf, i),
                listOf(root),
                found(listOf(leaf, i, root)).copy(verifications = 2, candidatesExplored = 2),
            )
        }

    /** (s1) (o) plus 62 related junk ahead of the honest key: 64 related, the cap, and both paths. */
    fun s1(): List<WalkerFixture> =
        with(Honest()) {
            val sub = subCa()
            listOf(
                fixture(
                    "s1",
                    presented = listOf(leaf, sub) + junk(62) + intermediate,
                    walk =
                        found(listOf(leaf, sub, root), path).copy(
                            verifications = 66,
                            candidatesExplored = 66,
                            relatedExploredAtLeaf = 64,
                        ),
                ),
            )
        }

    /** (s2) and (t): (o) plus [junk] related junk: the honest intermediate is past the cap; S's path is partial. */
    private fun overCap(
        id: String,
        junk: Int,
    ): List<WalkerFixture> =
        with(Honest()) {
            val sub = subCa()
            listOf(
                fixture(
                    id,
                    presented = listOf(leaf, sub) + junk(junk) + intermediate,
                    walk =
                        budget(WalkEnd.RELATED_BUDGET, 1, listOf(leaf, sub, root)).copy(
                            verifications = 65,
                            candidatesExplored = 65,
                            relatedExploredAtLeaf = 64,
                        ),
                ),
            )
        }

    fun s2(): List<WalkerFixture> = overCap("s2", 63)

    fun t(): List<WalkerFixture> = overCap("t", 80)

    /** (v) An honest generated chain (depth 2) against a 200-anchor snapshot, over ten seeds: depth + 1 ≤ 4. */
    fun v(): List<WalkerFixture> =
        (1L..10L).map { seed ->
            val world = ChainGenerator.generate(seed, depth = 2, anchors = ChainGenerator.MAX_ANCHORS)
            generated(
                "v",
                "seed $seed",
                world,
                ExpectedWalk(ExpectedWalk.Kind.FOUND).copy(maxVerifications = 4, verifications = 3),
            )
        }

    /** (v2) The same with a cross-certificate of the honest root to a retired root presented. */
    fun v2(): List<WalkerFixture> =
        (1L..10L).map { seed ->
            // honestIssuers is [I1, I2, root] at depth 2: target 2 is the honest root.
            val world =
                ChainGenerator.generate(seed, listOf(CrossCertToNonAnchor(2)), 2, ChainGenerator.MAX_ANCHORS)
            generated(
                "v2",
                "seed $seed",
                world,
                ExpectedWalk(ExpectedWalk.Kind.FOUND).copy(maxVerifications = 4, verifications = 3),
            )
        }

    private fun generated(
        id: String,
        variant: String,
        world: World,
        walk: ExpectedWalk,
    ): WalkerFixture =
        WalkerFixture(
            id = id,
            variant = variant,
            presented = world.presented,
            snapshot = world.anchors,
            ok = world.ok,
            walk = walk.copy(leafKeys = setOf(world.honestKey.decodeHex())),
        )

    /**
     * (w) A dense cross-certified mesh: 6 roots in the snapshot and 12 cross-certificates among them presented ahead of
     * I. None is related to the leaf, and at I the store root comes first: the reported path is leaf → I → anchor.
     */
    fun w(): List<WalkerFixture> {
        val w = FixtureWorld()
        val roots = (1..6).map { w.root("R$it", "Root $it") }
        val pairs = (0 until 6).flatMap { a -> listOf(a to (a + 1) % 6, a to (a + 2) % 6) }
        val crosses =
            pairs.map { (a, b) ->
                w.cert("X$a$b", roots[a].subject, roots[b].subject, roots[a].key, signer = roots[b].key)
            }
        val i = w.cert("I", w.name("Intermediate"), roots[0].subject, signer = roots[0].key)
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key)
        return listOf(
            w.fixture(
                "w",
                "",
                listOf(leaf) + crosses + i,
                roots,
                found(listOf(leaf, i, roots[0])).copy(verifications = 2, candidatesExplored = 2),
            ),
        )
    }

    /** leaf → I1 → I2 → R, with [junk] certificates named [junkName] presented between I1 and I2. */
    private fun twoLevel(
        id: String,
        variant: String,
        junk: Int,
        junkIsRoot: Boolean,
        walk: (Deep) -> ExpectedWalk,
    ): WalkerFixture =
        with(Deep(2)) {
            val (i1, i2) = intermediates
            val name = if (junkIsRoot) root.subject else i2.subject
            val junkCerts = List(junk) { w.cert("J$it", name, w.name("Junk issuer $it")) }
            w.fixture(id, variant, listOf(leaf, i1) + junkCerts + i2, listOf(root), walk(this))
        }

    /**
     * (y) 65 certificates named like I2 whose keys do not verify I1, ahead of I2: the cap trips at I1, below the leaf,
     * and aborts the whole walk at `endDepth = 2`. The second case, 63 of them, is the cap's other side.
     */
    fun y(): List<WalkerFixture> =
        listOf(
            twoLevel("y", "65 junk", 65, junkIsRoot = false) {
                budget(WalkEnd.RELATED_BUDGET, 2).copy(verifications = 65, candidatesExplored = 65)
            },
            twoLevel("y", "63 junk, 64 related at I1", 63, junkIsRoot = false) {
                found(it.path).copy(verifications = 66, candidatesExplored = 66)
            },
        )

    /** (y2) The junk carries the root's name instead: at I2 the store root sorts first, so no junk is explored. */
    fun y2(): List<WalkerFixture> =
        listOf(
            twoLevel("y2", "", 65, junkIsRoot = true) {
                found(it.path).copy(verifications = 3, candidatesExplored = 3)
            },
        )

    /**
     * (z) `NotFound` where only an unrelated presented certificate has an unsupported key OID, and a related candidate
     * verifies but is unanchored: `UNANCHORED`, and no OID recorded.
     */
    fun z(): List<WalkerFixture> =
        with(Honest()) {
            val fake = w.cert("F", intermediate.subject, w.name("Attacker"))
            w.verifies(leaf, fake.key)
            val other = w.name("Other")
            val u = w.cert("U", other, other, w.key(SymOids.UNSUPPORTED_KEY))
            listOf(
                fixture(
                    "z",
                    presented = listOf(leaf, fake, u),
                    // L/F, F/U unsupported (unrelated), L/U unsupported (unrelated).
                    walk =
                        notFound(NoIssuerReason.UNANCHORED).copy(
                            verifications = 3,
                            candidatesExplored = 3,
                            relatedExploredAtLeaf = 1,
                            unrelatedExploredAtLeaf = 1,
                        ),
                ),
            )
        }

    /** (aa) A root-issued leaf with the root's exact bytes also presented: one path, at the presented position. */
    fun aa(): List<WalkerFixture> {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val leaf = w.cert("L", w.name("leaf.example"), root.subject, signer = root.key)
        return listOf(
            w.fixture(
                "aa",
                "",
                listOf(leaf, root),
                listOf(root),
                found(listOf(leaf, root)).copy(verifications = 1, candidatesExplored = 1, relatedExploredAtLeaf = 1),
            ),
        )
    }

    /**
     * The leaf's issuer as a TeletexString: the platform canonicaliser hex-encodes it, so the honest UTF8String-named
     * intermediate is unrelated to the leaf by encoding, and the leaf's AKI (issuer-and-serial form) makes the test
     * name-only. A custom delegate would chain them; revokt's walker reaches I only through the unrelated loop.
     */
    private fun teletex(w: FixtureWorld): Honest {
        val leafIssuer = w.name("Intermediate", TELETEX_STRING)
        return Honest(w, leafIssuer = leafIssuer, leafAki = FixtureWorld.akiIssuerAndSerial(w.name("Intermediate")))
    }

    /**
     * (ac) Custom canonicaliser: the honest issuer unrelated by encoding, four unrelated junk ahead: `Found` through the
     * unrelated loop. The second case adds a related, anchored attacker sub-CA ahead: under a custom canonicaliser the
     * leaf still runs the unrelated loop, so both keys are leaf keys.
     */
    fun ac(): List<WalkerFixture> =
        listOf(false, true).map { decoy ->
            val w = FixtureWorld()
            val h = teletex(w)
            val leaf = h.leaf
            val junk = List(4) { w.cert("J$it", w.name("Junk $it"), w.name("Junk issuer $it")) }
            val sub =
                if (decoy) {
                    w.cert("S", w.name("Intermediate", TELETEX_STRING), h.root.subject, signer = h.root.key).also {
                        w.verifies(leaf, it.key)
                    }
                } else {
                    null
                }
            val presented = listOfNotNull(leaf, sub) + junk + h.intermediate
            val paths = listOfNotNull(sub?.let { listOf(leaf, it, h.root) }, listOf(leaf, h.intermediate, h.root))
            w.fixture(
                "ac",
                if (decoy) "related anchored decoy ahead" else "",
                presented,
                listOf(h.root),
                found(*paths.toTypedArray()).copy(
                    verifications = if (decoy) 8 else 6,
                    candidatesExplored = if (decoy) 8 else 6,
                    relatedExploredAtLeaf = if (decoy) 1 else 0,
                    unrelatedExploredAtLeaf = 5,
                ),
                customCanonicaliser = true,
            )
        }

    /**
     * (ad) The honest issuer unrelated by encoding, and six same-name, mutually cross-signing junk certificates ahead
     * that each verify the leaf: their simple paths exceed `MAX_EXPLORED` long before `MAX_VERIFICATIONS` (the memo
     * holds at most 42 pairs), so the walk ends `EXPLORATION_BUDGET` with exactly 1,024 explorations.
     */
    fun ad(): List<WalkerFixture> {
        val w = FixtureWorld()
        val h = teletex(w)
        val leaf = h.leaf
        val name = w.name("Intermediate", TELETEX_STRING)
        val keys = List(6) { w.key() }
        val junk = keys.mapIndexed { n, k -> w.cert("J$n", name, name, k) }
        for ((n, j) in junk.withIndex()) {
            w.verifies(leaf, j.key)
            keys.forEachIndexed { m, k -> if (m != n) w.verifies(j, k) }
        }
        return listOf(
            w.fixture(
                "ad",
                "",
                listOf(leaf) + junk + h.intermediate,
                listOf(h.root),
                budget(WalkEnd.EXPLORATION_BUDGET, endDepth = null).copy(
                    candidatesExplored = RevoktLimits.MAX_EXPLORED,
                    maxVerifications = 42,
                ),
                customCanonicaliser = true,
            ),
        )
    }

    /** (ae) walker part: a related candidate verifies the leaf but is unanchored. */
    fun ae(): List<WalkerFixture> =
        with(Honest()) {
            val fake = w.cert("F", intermediate.subject, w.name("Attacker"))
            w.verifies(leaf, fake.key)
            listOf(
                fixture(
                    "ae",
                    presented = listOf(leaf, fake),
                    walk = notFound(NoIssuerReason.UNANCHORED).copy(verifications = 1, candidatesExplored = 1),
                ),
            )
        }

    /**
     * (af) walker part: 9 presented certificates and an honest link the walker cannot reproduce (I's signature does not
     * verify under the root's key here, as with a custom delegate's verifier): `UNANCHORED`. Seven unrelated fillers
     * are tried at I and, with no related path, at the leaf.
     */
    fun af(): List<WalkerFixture> {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val i = w.cert("I", w.name("Intermediate"), root.subject) // no link: the walker cannot verify I under R
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key)
        val fillers = List(7) { w.cert("F$it", w.name("Filler $it"), w.name("Filler issuer $it")) }
        return listOf(
            w.fixture(
                "af",
                "",
                listOf(leaf, i) + fillers,
                listOf(root),
                notFound(NoIssuerReason.UNANCHORED).copy(
                    verifications = 16,
                    candidatesExplored = 16,
                    relatedExploredAtLeaf = 1,
                    unrelatedExploredAtLeaf = 7,
                ),
            ),
        )
    }

    /**
     * (ah) 12 distinct duplicate-signature keys D1…D12 that each verify the leaf, each recursing into a 32-certificate
     * subtree whose keys do not verify it (32 related, then 12 unrelated, explorations per D). 5 × 45 verifications,
     * then D6's leaf link and 30 of its subtree: 256; the 257th attempt trips the guard at endDepth 2 and is counted
     * as explored but not as a verification.
     */
    fun ah(): List<WalkerFixture> =
        with(Honest()) {
            val sub = w.name("Sub")
            val ds = List(12) { w.cert("D$it", intermediate.subject, sub).also { d -> w.verifies(leaf, d.key) } }
            val ss = List(32) { w.cert("S$it", sub, w.name("Sub issuer $it")) }
            listOf(
                fixture(
                    "ah",
                    presented = listOf(leaf) + ds + ss + intermediate,
                    walk =
                        budget(WalkEnd.VERIFICATION_BUDGET, 2).copy(
                            verifications = RevoktLimits.MAX_VERIFICATIONS,
                            candidatesExplored = RevoktLimits.MAX_VERIFICATIONS + 1,
                        ),
                ),
            )
        }

    /**
     * (ai) A 17-certificate honest path (16 non-terminal plus the anchor), the longest `MAX_DEPTH` admits: `Found`. An
     * 18-certificate one is a dead end: I16 is never expanded, so the walk is `UNANCHORED`. With no path anywhere every
     * node also runs its unrelated loop: the 16 links L/I1 … I15/I16, then 15 − k candidates at each I_k (105) and 15
     * at the leaf, 136 verifications.
     */
    fun ai(): List<WalkerFixture> =
        listOf(15, 16).map { depth ->
            with(Deep(depth)) {
                w.fixture(
                    "ai",
                    "${depth + 2} certificates",
                    listOf(leaf) + intermediates,
                    listOf(root),
                    if (depth == 15) {
                        found(path).copy(verifications = 16, candidatesExplored = 16)
                    } else {
                        notFound(NoIssuerReason.UNANCHORED).copy(
                            verifications = 136,
                            candidatesExplored = 136,
                            unrelatedExploredAtLeaf = 15,
                        )
                    },
                )
            }
        }

    /**
     * (aj) No related path at the leaf (its issuer neither presented nor in the snapshot): two unrelated presented
     * certificates U1 and U2 whose keys both verify the leaf, each certified by a snapshot anchor, in both orders, with
     * and without a related candidate ahead that verifies the leaf but is unanchored. Every case collects both keys
     * and explores both unrelated certificates at the leaf.
     */
    fun aj(): List<WalkerFixture> =
        listOf(false, true).flatMap { decoy ->
            listOf(false, true).map { swapped ->
                val w = FixtureWorld()
                val r1 = w.root("R1", "Root 1")
                val r2 = w.root("R2", "Root 2")
                val missing = w.name("Missing issuer")
                val leaf = w.cert("L", w.name("leaf.example"), missing, signer = w.key())
                val u1 =
                    w
                        .cert(
                            "U1",
                            w.name("Unrelated 1"),
                            r1.subject,
                            signer = r1.key,
                        ).also { w.verifies(leaf, it.key) }
                val u2 =
                    w
                        .cert(
                            "U2",
                            w.name("Unrelated 2"),
                            r2.subject,
                            signer = r2.key,
                        ).also { w.verifies(leaf, it.key) }
                val d = if (decoy) w.cert("D", missing, w.name("Attacker")).also { w.verifies(leaf, it.key) } else null
                val us = if (swapped) listOf(u2, u1) else listOf(u1, u2)
                val paths = us.map { listOf(leaf, it, if (it === u1) r1 else r2) }
                w.fixture(
                    "aj",
                    listOfNotNull(
                        if (swapped) "U2 first" else "U1 first",
                        "unanchored related decoy ahead".takeIf { decoy },
                    ).joinToString(", "),
                    listOfNotNull(leaf, d) + us,
                    listOf(r1, r2),
                    found(*paths.toTypedArray()).copy(
                        leafKeys = WalkerHarness.keys(u1, u2),
                        // L/U1, U1/R1, L/U2, U2/R2, and with the decoy L/D, D/U1, D/U2.
                        verifications = if (decoy) 7 else 4,
                        relatedExploredAtLeaf = if (decoy) 1 else 0,
                        unrelatedExploredAtLeaf = 2,
                    ),
                )
            }
        }
}
