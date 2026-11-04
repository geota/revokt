// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.testing

import dev.revokt.RevoktLimits
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The §9.1 reference walker over generated worlds: the honest key, and what each mutation does to it. */
class ReferenceWalkerTest {
    private val seeds = 0L until 60

    private fun World.walk(
        canonicalSubject: (ByteArray) -> String? = ReferenceWalker::platformCanonicalSubject,
    ): Set<String> = ReferenceWalker(anchors, verifier(), canonicalSubject).walk(presented)

    private fun WorldModel.walk(): Set<String> = render().walk()

    private fun assertUnchanged(mutation: (Long) -> List<Mutation>) {
        for (seed in seeds) {
            val m = mutation(seed)
            val world = ChainGenerator.generate(seed, m)
            assertEquals(setOf(world.honestKey), world.walk(), "seed $seed, $m (applied ${world.mutations})")
        }
    }

    @Test
    fun `an unmutated world gives the honest leaf-issuer key`() {
        for (seed in 0L until 200) {
            val world = ChainGenerator.generate(seed)
            assertEquals(setOf(world.honestKey), world.walk(), "seed $seed")
        }
    }

    @Test
    fun `DropIntermediate gives the empty set`() {
        for (seed in seeds) {
            val depth = 1 + (seed % 9).toInt()
            val world = ChainGenerator.generate(seed, listOf(DropIntermediate(seed.toInt())), depth = depth)
            assertEquals(1, world.mutations.size)
            assertEquals(emptySet(), world.walk(), "seed $seed")
        }
    }

    @Test
    fun `Recover of the leaf certified by an anchor adds the recovered key`() {
        for (seed in seeds) {
            val anchor = ChainGenerator.honest(seed).honestAnchor
            val world = ChainGenerator.generate(seed, listOf(Recover(0, certifiedBy = anchor)))
            assertEquals(setOf(world.honestKey, world.recoveredKeys.single()), world.walk(), "seed $seed")
        }
    }

    @Test
    fun `Recover without CertifiedBy, or of an intermediate's signature, leaves the result unchanged`() {
        assertUnchanged { listOf(Recover(0)) }
        for (seed in seeds) {
            val honest = ChainGenerator.honest(seed)
            if (honest.depth == 0) continue
            val intermediate = 1 + seed.toInt().mod(honest.depth)
            val world = ChainGenerator.generate(seed, listOf(Recover(intermediate, honest.honestAnchor)))
            assertEquals(setOf(world.honestKey), world.walk(), "seed $seed")
        }
    }

    @Test
    fun `Loop, Duplicate, Permute and DepthPad leave the result unchanged`() {
        assertUnchanged { seed -> listOf(Loop(seed.toInt())) }
        assertUnchanged { seed -> listOf(Duplicate(seed.toInt(), 3 * seed.toInt())) }
        assertUnchanged { seed -> listOf(Permute(seed)) }
        assertUnchanged { seed -> listOf(DepthPad(seed.toInt(), 1 + seed.toInt().mod(DepthPad.MAX))) }
        assertUnchanged { seed -> listOf(Loop(0), DepthPad(1, 20), Duplicate(1, 1), Duplicate(2, 5), Permute(seed)) }
    }

    @Test
    fun `the other attacker mutations and the name and algorithm world mutations leave the result unchanged`() {
        assertUnchanged { seed -> listOf(SameKeyDecoy(seed.toInt())) }
        assertUnchanged { seed -> listOf(CrossCertToNonAnchor(seed.toInt())) }
        assertUnchanged { seed -> listOf(Stuff(Stuff.MAX, related = true, at = seed.toInt())) }
        assertUnchanged { listOf(Stuff(40, related = false)) }
        assertUnchanged { seed -> listOf(SelfSignedNonAnchor(seed.toInt())) }
        assertUnchanged { seed -> listOf(NameEncoding(seed.toInt()), AlgMismatch(seed.toInt() + 1)) }
    }

    @Test
    fun `the attacker branches are reached, so made anchors their recovered keys count`() {
        for (seed in 0L until 20) {
            fun withAnchor(
                m: Mutation,
                at: Int,
            ): Set<String> {
                val w = ChainGenerator.generate(seed, listOf(m))
                return ReferenceWalker(w.anchors + w.presented[at], w.verifier()).walk(w.presented)
            }
            val honest = ChainGenerator.generate(seed)
            val recovered = ChainGenerator.generate(seed, listOf(Loop(0))).recoveredKeys.single()
            assertEquals(setOf(honest.honestKey, recovered), withAnchor(SelfSignedNonAnchor(0), 1), "seed $seed")
            assertEquals(setOf(honest.honestKey, recovered), withAnchor(Loop(0), 2), "seed $seed")
            // The pad's last certificate as the terminal: leaf plus the pad is MAX_DEPTH + 1 certificates at most.
            val longest = RevoktLimits.MAX_DEPTH
            assertEquals(setOf(honest.honestKey, recovered), withAnchor(DepthPad(0, longest), longest), "seed $seed")
            assertEquals(setOf(honest.honestKey), withAnchor(DepthPad(0, longest + 1), longest + 1), "seed $seed")
        }
    }

    @Test
    fun `UnsupportedOwnSig on the honest path gives the empty set`() {
        for (seed in seeds) {
            val world = ChainGenerator.generate(seed, listOf(UnsupportedOwnSig(seed.toInt())))
            assertEquals(emptySet(), world.walk(), "seed $seed")
        }
    }

    @Test
    fun `a path deeper than MAX_DEPTH is a dead end`() {
        // depth intermediates make a path of depth + 2 certificates; MAX_DEPTH + 1 is the most a path holds.
        for (seed in 0L until 5) {
            val longest = ChainGenerator.generate(seed, depth = RevoktLimits.MAX_DEPTH - 1)
            assertEquals(setOf(longest.honestKey), longest.walk(), "seed $seed")
            val deeper = ChainGenerator.generate(seed, depth = RevoktLimits.MAX_DEPTH)
            assertEquals(emptySet(), deeper.walk(), "seed $seed")
        }
        // The same bound on an attacker branch: a recovered key on the leaf, its chain certified by the root.
        for (length in listOf(RevoktLimits.MAX_DEPTH - 1, RevoktLimits.MAX_DEPTH)) {
            val model = ChainGenerator.honest(11, depth = 0)
            val root = model.honestPath.last()
            val keys = List(length) { if (it == 0) model.recover(model.honestPath[0]) else model.freshKey() } + root.key
            val names = List(length) { if (it == 0) root.subject else model.freshName("Branch") } + root.subject
            val branch = List(length) { model.issue(names[it], names[it + 1], keys[it], keys[it + 1]) }
            model.insertAfterLeaf(*branch.toTypedArray())
            // [leaf, branch, root] holds length + 2 certificates.
            val reaches = length + 2 <= RevoktLimits.MAX_DEPTH + 1
            assertEquals(setOfNotNull(root.key.hex, keys[0].hex.takeIf { reaches }), model.walk(), "branch of $length")
        }
    }

    @Test
    fun `a leaf that is an anchor gives its own key`() {
        val world = ChainGenerator.generate(4)
        val anchor = world.anchors[world.honestAnchor]
        val rootKey =
            ChainGenerator
                .honest(4)
                .honestPath
                .last()
                .key.hex
        val keys = ReferenceWalker(world.anchors, world.verifier()).walk(listOf(anchor) + world.presented)
        assertEquals(setOf(rootKey), keys)
    }

    @Test
    fun `an unrelated presented issuer counts only when no related path exists`() {
        for (seed in 0L until 20) {
            val model = ChainGenerator.honest(seed, depth = 1)
            val leaf = model.honestPath[0]
            val intermediate = model.honestPath[1]
            val root = model.honestPath.last()
            val key = model.recover(leaf)
            model.insertAfterLeaf(model.issue(model.freshName("Unrelated"), root.subject, key, root.key))
            assertEquals(setOf(intermediate.key.hex), model.walk(), "seed $seed with the related issuer")
            model.presented.remove(intermediate)
            assertEquals(setOf(key.hex), model.walk(), "seed $seed without it")
        }
    }

    @Test
    fun `a canonical name match is related, and a null or throwing canonicaliser is no match`() {
        // Worlds without key identifiers whose leaf is issued by a root that is not presented: the root is reachable
        // from the store only, so only as a related candidate.
        val worlds =
            (0L until 200)
                .map { it to ChainGenerator.honest(it, depth = 0) }
                .filter { (_, m) -> !m.keyIdentifiers && m.presented.size == 1 }
                .take(10)
        assertTrue(worlds.size == 10)
        for ((seed, _) in worlds) {
            val world = ChainGenerator.generate(seed, listOf(NameEncoding(0)), depth = 0)
            assertEquals(setOf(world.honestKey), world.walk(), "seed $seed")
            assertEquals(emptySet(), world.walk { null }, "seed $seed")
            assertEquals(emptySet(), world.walk { error("canonicaliser failed") }, "seed $seed")
            val honest = ChainGenerator.generate(seed, depth = 0)
            assertEquals(setOf(honest.honestKey), honest.walk { null }, "seed $seed: raw bytes still match")
        }
    }
}
