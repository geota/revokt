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

/** leaf → I → R with R in the snapshot, the chain most rows start from. */
internal class Honest(
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
            extensions = listOfNotNull(leafAki?.let { FixtureWorld.aki(it) }),
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

internal fun FixtureWorld.fixture(
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

/** (o)'s attacker sub-CA: a second key that verifies the leaf, certified under the real root. */
internal fun Honest.subCa(): FixtureCert =
    w.cert("S", intermediate.subject, root.subject, signer = root.key).also { w.verifies(leaf, it.key) }

/** A chain of [depth] intermediates under one root: leaf, I1 … I`depth` (I1 issued the leaf), root. */
internal class Deep(
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
