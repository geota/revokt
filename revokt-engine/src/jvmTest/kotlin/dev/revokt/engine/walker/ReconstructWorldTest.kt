// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.VerifyResult
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.FixtureWorld.Companion.PRINTABLE_STRING
import dev.revokt.engine.walker.FixtureWorld.Companion.TELETEX_STRING
import dev.revokt.engine.walker.FixtureWorld.Companion.UTF8_STRING
import dev.revokt.testing.CertId
import dev.revokt.testing.ChainGenerator
import dev.revokt.testing.CrossCertToNonAnchor
import dev.revokt.testing.KeyId
import dev.revokt.testing.Mutation
import dev.revokt.testing.ReferenceWalker
import dev.revokt.testing.SameKeyDecoy
import dev.revokt.testing.SplitMix64
import dev.revokt.testing.Stuff
import dev.revokt.testing.SymKey
import dev.revokt.testing.SymOids
import dev.revokt.testing.SymVerifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * `reconstruct` against the §9.1 reference walker (spec §5.1, §9.1): on generated worlds (honest worlds with world and
 * attacker mutations) and on random mesh worlds (few names in several encodings, shared keys, random links, anchors
 * and cross-signatures), every `Found` has exactly the reference's leaf keys, every `NotFound` a reference with none,
 * and every `Budget` a subset of them; every returned path is sound. Both walkers use the platform canonicaliser. The
 * seed is in every message. The walker fuzzer (#144) is the full gate; this is its fixed-seed smoke.
 */
@OptIn(RevoktInternalApi::class)
class ReconstructWorldTest {
    /** The outcome counts of one differential run. */
    private class Tally {
        var found = 0
        var notFound = 0
        var budget = 0
        var multiKey = 0

        override fun toString(): String = "found $found, notFound $notFound, budget $budget, multi-key $multiKey"
    }

    private fun differential(
        presented: List<ByteArray>,
        anchors: List<ByteArray>,
        ok: Set<Pair<CertId, KeyId>>,
        unsupported: Set<String>,
        at: String,
        tally: Tally,
    ): Walk {
        val verifier = SymVerifier(ok, unsupported)
        val expected = ReferenceWalker(anchors, verifier).walk(presented)
        val index = CandidateIndex(anchors)
        val certs =
            presented.mapNotNull { der ->
                (CertificateParser.parse(der) as? CertificateParse.Parsed)?.let { index.cert(it.certificate) }
            }
        if (certs.size != presented.size) fail("$at: a generated certificate does not parse")
        val walk = reconstruct(certs, index, verifier, unsupported, LruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES))
        val shown = WalkerHarness.describe(walk) { it.hex().take(8) }
        when (walk) {
            is Walk.Found -> {
                tally.found++
                if (walk.leafKeys.size > 1) tally.multiKey++
                assertEquals(expected, WalkerHarness.hex(walk.leafKeys), "$at: Found leaf keys; $shown")
                walk.paths.forEach { assertSound(it, certs[0], index, verifier, "$at; $shown") }
            }

            is Walk.NotFound -> {
                tally.notFound++
                assertEquals(emptySet(), expected, "$at: NotFound but the reference found keys; $shown")
            }

            is Walk.Budget -> {
                tally.budget++
                val partial = WalkerHarness.hex(walk.partialLeafKeys)
                assertTrue(expected.containsAll(partial), "$at: Budget partial keys $partial ⊄ $expected; $shown")
                walk.partialPaths.forEach { assertSound(it, certs[0], index, verifier, "$at; $shown") }
            }
        }
        assertTrue(walk.stats.verifications <= RevoktLimits.MAX_VERIFICATIONS, "$at: $shown")
        assertTrue(walk.stats.candidatesExplored <= RevoktLimits.MAX_EXPLORED, "$at: $shown")
        return walk
    }

    /** The §5.1 invariant: leaf first, every link `VERIFIED` under the next key, an anchor last, within `MAX_DEPTH`. */
    private fun assertSound(
        path: WalkPath,
        leaf: Cert,
        index: CandidateIndex,
        verifier: SymVerifier,
        at: String,
    ) {
        val certs = path.certs
        assertTrue(certs.size in 2..RevoktLimits.MAX_DEPTH + 1, "$at: path size ${certs.size}")
        assertEquals(leaf.bytesHash, certs[0].bytesHash, "$at: path starts at the leaf")
        assertEquals(certs.size, certs.map { it.bytesHash }.toSet().size, "$at: a path repeats a certificate")
        for ((child, issuer) in certs.zipWithNext()) {
            assertEquals(
                VerifyResult.VERIFIED,
                verifier.verify(child.tbsSigAlg, issuer.spki, child.tbs, child.sig),
                "$at: unverified link",
            )
        }
        assertTrue(index.isAnchorBytes(certs.last()), "$at: the terminal is not an anchor")
    }

    @Test
    fun `walker smoke 200 honest generated worlds are Found with the reference keys in depth + 1 verifications`() {
        val tally = Tally()
        var crossSigned = 0
        for (seed in 1L..200L) {
            val world = ChainGenerator.generate(seed)
            val walk = differential(world.presented, world.anchors, world.ok, world.unsupported, "seed $seed", tally)
            if (walk !is Walk.Found) fail("seed $seed: honest world not Found: $walk")
            assertEquals(setOf(world.honestKey), WalkerHarness.hex(walk.leafKeys), "seed $seed")
            // §5.1 "Cost": at most depth + 1, depth counted on the longest path found. That is the generator's depth
            // except for a root-issued leaf with a cross-certificate of its root presented: at the leaf the presented
            // cross-certificate is explored first (L/X, X/R'), and the store root is then a memo hit.
            val depth = walk.paths.maxOf { it.certs.size } - 2
            val v = walk.stats.verifications
            assertTrue(v <= depth + 1, "seed $seed: $v verifications at depth $depth")
            if (v > world.depth + 1) {
                crossSigned++
                assertEquals(listOf(3, 2), walk.paths.map { it.certs.size }, "seed $seed: $walk")
            }
        }
        assertTrue(crossSigned in 1..20, "root-issued leaves with a presented cross-certificate: $crossSigned")
    }

    @Test
    fun `walker reconstruct matches the reference walker on generated worlds with random mutations`() {
        val tally = Tally()
        for (seed in 1L..1500L) {
            val rng = SplitMix64(seed * 104_729)
            val mutations = List(rng.nextInt(0, 7)) { Mutation.random(rng) }
            val world = ChainGenerator.generate(seed, mutations)
            differential(
                world.presented,
                world.anchors,
                world.ok,
                world.unsupported,
                "seed $seed ${world.mutations}",
                tally,
            )
        }
        assertTrue(tally.found > 500 && tally.notFound > 50 && tally.budget > 10 && tally.multiKey > 10, "$tally")
    }

    @Test
    fun `walker reconstruct matches the reference walker around the related cap with decoys and cross-certs`() {
        val tally = Tally()
        for (seed in 1L..120L) {
            val rng = SplitMix64(seed * 7_919)
            val n = RevoktLimits.MAX_RELATED_PER_LEVEL - 2 + rng.nextInt(4) // 62 … 65
            val mutations =
                rng.shuffled(
                    listOf(
                        Stuff(n, related = true, at = rng.nextInt()),
                        SameKeyDecoy(rng.nextInt()),
                        CrossCertToNonAnchor(rng.nextInt()),
                    ),
                )
            val world = ChainGenerator.generate(seed, mutations, depth = rng.nextInt(0, 4))
            differential(world.presented, world.anchors, world.ok, world.unsupported, "seed $seed n $n", tally)
        }
        assertTrue(tally.found > 10 && tally.budget > 10, "$tally")
    }

    /**
     * A random mesh: 1–4 common names, each written as a UTF8String, a PrintableString or (rarely) a TeletexString, so
     * raw, canonical-only and no matches all occur; 1–6 shared keys (a tenth unsupported); 2–13 certificates with random
     * subjects, issuers, keys, signers, SKIs, AKIs and extra recovered links; anchors drawn from them and beside them;
     * the presented order shuffled, with exact-byte duplicates.
     */
    private class Mesh(
        seed: Long,
    ) {
        private val rng = SplitMix64(seed)
        private val w = FixtureWorld()
        private val cns = List(rng.nextInt(1, 5)) { "N$it" }
        private val keys: List<SymKey> =
            List(rng.nextInt(1, 7)) { w.key(if (rng.nextInt(10) == 0) SymOids.UNSUPPORTED_KEY else SymOids.KEY) }
        private val certs = List(rng.nextInt(2, 14)) { cert(it) }
        val ok: Set<Pair<CertId, KeyId>>
        val anchors: List<ByteArray>
        val presented: List<ByteArray>

        init {
            for (c in certs) if (rng.nextInt(3) == 0) w.verifies(c, key())
            val others = certs.drop(1)
            anchors =
                (others.filter { rng.nextInt(3) == 0 } + List(rng.nextInt(3)) { w.root("A$it", cn(), key()) }).map {
                    it.der
                }
            val shown = ArrayList(rng.shuffled(others.filter { rng.nextInt(5) != 0 }))
            repeat(rng.nextInt(3)) {
                if (shown.isNotEmpty()) shown.add(rng.nextInt(shown.size + 1), shown[rng.nextInt(shown.size)])
            }
            presented = (listOf(certs[0]) + shown).map { it.der }
            ok = w.ok
        }

        private fun cn() = cns[rng.nextInt(cns.size)]

        private fun key() = keys[rng.nextInt(keys.size)]

        private fun name(): ByteArray {
            val tag =
                when (rng.nextInt(20)) {
                    0 -> TELETEX_STRING
                    in 1..5 -> PRINTABLE_STRING
                    else -> UTF8_STRING
                }
            return w.name(cn(), tag)
        }

        private fun cert(n: Int): FixtureCert {
            val key = if (n == 0) w.key() else key()
            val signer = if (rng.nextInt(5) == 0) null else key()
            val aki =
                when (rng.nextInt(5)) {
                    0 -> TestDer.seq(TestDer.tlv(0x80, key().keyIdentifier))
                    1 -> FixtureWorld.akiIssuerAndSerial(name())
                    else -> null
                }
            val extensions =
                listOfNotNull(FixtureWorld.ski(key).takeIf { rng.nextInt(3) == 0 }, aki?.let { FixtureWorld.aki(it) })
            val sigOid = if (rng.nextInt(20) == 0) SymOids.UNSUPPORTED_SIGNATURE else SymOids.SIGNATURE
            return w.cert("C$n", name(), name(), key, signer, sigOid, extensions = extensions)
        }
    }

    @Test
    fun `walker reconstruct matches the reference walker on random mesh worlds`() {
        val tally = Tally()
        for (seed in 1L..4000L) {
            val mesh = Mesh(seed)
            differential(mesh.presented, mesh.anchors, mesh.ok, SymOids.UNSUPPORTED, "mesh seed $seed", tally)
        }
        assertTrue(tally.found > 300 && tally.notFound > 300 && tally.multiKey > 20, "$tally")
    }
}
