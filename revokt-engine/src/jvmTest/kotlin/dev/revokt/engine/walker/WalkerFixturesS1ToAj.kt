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
 * The §9 walker fixture table, rows (s1) to (aj) (spec §9 "Walker fixtures", §5.1), as [WalkerFixturesAToR]. (x), (ab)
 * and (ag) end before decision step 5; (u) and (y3) are 0.3 and M2.
 */
internal object WalkerFixturesS1ToAj {
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
                budget(WalkEnd.EXPLORATION_BUDGET, endDepth = 7).copy(
                    candidatesExplored = RevoktLimits.MAX_EXPLORED,
                    // J0's subtree takes 652 explorations; J1's trips the budget at a path through all six junk.
                    relatedExploredAtLeaf = 2,
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
                            // D1 … D5 complete; D6's subtree trips the guard.
                            relatedExploredAtLeaf = 6,
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
