// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.NoIssuerReason
import dev.revokt.RevoktLimits
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
    /**
     * (s1) (o) with 62 related junk ahead of the honest intermediate and the attacker CA S last: the junk, then L/I and
     * I/R, so the first path, through I, is found before S is reached.
     */
    fun s1(): List<WalkerFixture> =
        with(Honest()) {
            val sub = subCa()
            listOf(
                fixture(
                    "s1",
                    presented = listOf(leaf) + junk(62) + intermediate + sub,
                    walk = found(path).copy(verifications = 64, candidatesExplored = 64),
                ),
            )
        }

    /**
     * (s2) and (t): the same with [junk] related junk: L/I is at best the budget's last exploration, so I/R is past it
     * and the walk is `Budget`, with no path.
     */
    private fun overBudget(
        id: String,
        junk: Int,
    ): List<WalkerFixture> =
        with(Honest()) {
            val sub = subCa()
            listOf(
                fixture(
                    id,
                    presented = listOf(leaf) + junk(junk) + intermediate + sub,
                    walk =
                        budget().copy(
                            verifications = RevoktLimits.MAX_EXPLORED,
                            candidatesExplored = RevoktLimits.MAX_EXPLORED,
                        ),
                ),
            )
        }

    fun s2(): List<WalkerFixture> = overBudget("s2", RevoktLimits.MAX_EXPLORED - 1)

    fun t(): List<WalkerFixture> = overBudget("t", 300)

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
            walk = walk.copy(leafKey = world.honestKey.decodeHex()),
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
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
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
     * (y) Certificates named like I2 whose keys do not verify I1, ahead of I2: the budget is one for the whole walk, so
     * junk below the leaf spends it as junk at the leaf does. With `MAX_EXPLORED - 3` of them, L/I1, the junk, I1/I2
     * and I2/R are exactly the budget: `Found`. One more and I2/R is past it: `Budget`, the whole walk aborted.
     */
    fun y(): List<WalkerFixture> {
        val fits = RevoktLimits.MAX_EXPLORED - 3
        return listOf(
            twoLevel("y", "$fits junk", fits, junkIsRoot = false) {
                found(it.path).copy(verifications = fits + 3, candidatesExplored = fits + 3)
            },
            twoLevel("y", "${fits + 1} junk", fits + 1, junkIsRoot = false) {
                budget().copy(verifications = fits + 3, candidatesExplored = RevoktLimits.MAX_EXPLORED)
            },
        )
    }

    /** (y2) The junk carries the root's name instead: at I2 the store root sorts first, so no junk is explored. */
    fun y2(): List<WalkerFixture> =
        listOf(
            twoLevel("y2", "", 65, junkIsRoot = true) {
                found(it.path).copy(verifications = 3, candidatesExplored = 3)
            },
        )

    /**
     * (z) `NotFound` where only an unrelated presented certificate has an unsupported key OID, and a related candidate
     * verifies but is unanchored: `UNANCHORED`, and no OID recorded. The unrelated certificate is no candidate.
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
                    // L/F only.
                    walk = notFound(NoIssuerReason.UNANCHORED).copy(verifications = 1, candidatesExplored = 1),
                ),
            )
        }

    /** (aa) A root-issued leaf with the root's exact bytes also presented: one path, at the presented position. */
    fun aa(): List<WalkerFixture> {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val leaf = w.cert("L", w.name("leaf.example"), root.subject, signer = root.key, key = w.leafKey())
        return listOf(
            w.fixture(
                "aa",
                "",
                listOf(leaf, root),
                listOf(root),
                found(listOf(leaf, root)).copy(verifications = 1, candidatesExplored = 1),
            ),
        )
    }

    /**
     * The leaf's issuer as a TeletexString: the platform canonicaliser hex-encodes it, so the honest UTF8String-named
     * intermediate is unrelated to the leaf by encoding, and the leaf's AKI (issuer-and-serial form) makes the test
     * name-only. A custom delegate would chain them; revokt's walker never offers an unrelated certificate, so only
     * the PKIX fallback (decide) reaches I.
     */
    private fun teletex(w: FixtureWorld): Honest {
        val leafIssuer = w.name("Intermediate", TELETEX_STRING)
        return Honest(w, leafIssuer = leafIssuer, leafAki = FixtureWorld.akiIssuerAndSerial(w.name("Intermediate")))
    }

    /**
     * (ac) The honest issuer unrelated by encoding, four unrelated junk ahead: no candidate, `NO_CANDIDATE`. The second
     * case adds a related, anchored attacker CA ahead: `Found` through it alone (§10 residuals 1 and 15).
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
            w.fixture(
                "ac",
                if (decoy) "related anchored decoy ahead" else "",
                listOfNotNull(leaf, sub) + junk + h.intermediate,
                listOf(h.root),
                if (sub != null) {
                    found(listOf(leaf, sub, h.root)).copy(verifications = 2, candidatesExplored = 2)
                } else {
                    notFound(NoIssuerReason.NO_CANDIDATE).copy(verifications = 0, candidatesExplored = 0)
                },
            )
        }

    /**
     * (ad) The honest issuer unrelated by encoding, and six same-name, mutually cross-signing junk certificates ahead
     * that each verify the leaf: none is a loop of another (their keys differ), and their simple paths take 1,956
     * explorations, so the walk ends `Budget` after exactly `MAX_EXPLORED`, the memo holding at most 42 pairs.
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
                budget().copy(candidatesExplored = RevoktLimits.MAX_EXPLORED, maxVerifications = 42),
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
     * verify under the root's key here, as with a custom delegate's verifier): `UNANCHORED`. The seven unrelated
     * fillers are no candidates.
     */
    fun af(): List<WalkerFixture> {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val i = w.cert("I", w.name("Intermediate"), root.subject) // no link: the walker cannot verify I under R
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
        val fillers = List(7) { w.cert("F$it", w.name("Filler $it"), w.name("Filler issuer $it")) }
        return listOf(
            w.fixture(
                "af",
                "",
                listOf(leaf, i) + fillers,
                listOf(root),
                notFound(NoIssuerReason.UNANCHORED).copy(verifications = 2, candidatesExplored = 2),
            ),
        )
    }

    /**
     * (ah) 12 distinct duplicate-signature keys D1…D12 that each verify the leaf, each recursing into a 32-certificate
     * subtree whose keys do not verify it (33 explorations per D, each one verification): 7 × 33, then D8's leaf link
     * and 24 of its subtree, 256; the next one is not charged and the walk is `Budget`.
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
                        budget().copy(
                            verifications = RevoktLimits.MAX_EXPLORED,
                            candidatesExplored = RevoktLimits.MAX_EXPLORED,
                        ),
                ),
            )
        }

    /**
     * (ai) A 17-certificate honest path (16 non-terminal plus the anchor), the longest `MAX_DEPTH` admits: `Found`. An
     * 18-certificate one is a dead end: I16 is never expanded, so the walk is `UNANCHORED` after the 16 links L/I1 …
     * I15/I16.
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
                        notFound(NoIssuerReason.UNANCHORED).copy(verifications = 16, candidatesExplored = 16)
                    },
                )
            }
        }

    /**
     * (aj) No related path at the leaf (its issuer neither presented nor in the snapshot): two unrelated presented
     * certificates U1 and U2 whose keys both verify the leaf, each certified by a snapshot anchor, in both orders, with
     * and without a related candidate ahead that verifies the leaf but is unanchored. Neither is a candidate, so the
     * walk is `NO_CANDIDATE`, or `UNANCHORED` with the decoy; the PKIX fallback (decide) is what reaches them.
     */
    fun aj(): List<WalkerFixture> =
        listOf(false, true).flatMap { decoy ->
            listOf(false, true).map { swapped ->
                val w = FixtureWorld()
                val r1 = w.root("R1", "Root 1")
                val r2 = w.root("R2", "Root 2")
                val missing = w.name("Missing issuer")
                val leaf = w.cert("L", w.name("leaf.example"), missing, signer = w.key(), key = w.leafKey())
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
                w.fixture(
                    "aj",
                    listOfNotNull(
                        if (swapped) "U2 first" else "U1 first",
                        "unanchored related decoy ahead".takeIf { decoy },
                    ).joinToString(", "),
                    listOfNotNull(leaf, d) + us,
                    listOf(r1, r2),
                    if (decoy) {
                        // L/D only.
                        notFound(NoIssuerReason.UNANCHORED).copy(verifications = 1, candidatesExplored = 1)
                    } else {
                        notFound(NoIssuerReason.NO_CANDIDATE).copy(verifications = 0, candidatesExplored = 0)
                    },
                )
            }
        }
}
