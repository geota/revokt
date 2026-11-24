// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.walker.WalkerFuzzInput.ThrowKind
import dev.revokt.testing.AlgMismatch
import dev.revokt.testing.CrossCertToNonAnchor
import dev.revokt.testing.DepthPad
import dev.revokt.testing.DropIntermediate
import dev.revokt.testing.Duplicate
import dev.revokt.testing.EndEntityIssuer
import dev.revokt.testing.Loop
import dev.revokt.testing.Mutation
import dev.revokt.testing.NameEncoding
import dev.revokt.testing.Permute
import dev.revokt.testing.Recover
import dev.revokt.testing.SameKeyDecoy
import dev.revokt.testing.SelfSignedNonAnchor
import dev.revokt.testing.Stuff
import dev.revokt.testing.UnsupportedOwnSig
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * The committed `WalkerFuzzTestInputs/` (spec §9.1, #144): each file is the encoding of the input [CORPUS] names, so a
 * change to [WalkerFuzzInput]'s layout cannot silently turn the regression corpus into other worlds. The inputs are
 * one per §9.1 review round (rounds 1–4), one per #134 finding a mutation can reach (F1, F2 and F6; F3 is moot after
 * #226, and F4 and F5 cannot be reached by a mutation), one per #144 spec correction (A1–A3), and the honest, throw
 * and dead-end shapes the properties name.
 */
class WalkerFuzzCorpusTest {
    @Test
    fun `walker fuzz corpus every committed input decodes to the input it is named for`() {
        val dir = checkNotNull(javaClass.getResource("WalkerFuzzTestInputs")) { "no WalkerFuzzTestInputs" }
        val files =
            java.io
                .File(dir.toURI())
                .listFiles()
                .orEmpty()
                .filter { it.isFile }
                .associateBy { it.name }
        assertEquals(CORPUS.keys.sorted(), files.keys.sorted(), "the committed inputs are exactly CORPUS")
        for ((name, input) in CORPUS) {
            val bytes = files.getValue(name).readBytes()
            assertContentEquals(input.encode(), bytes, name)
            assertEquals(input.toString(), WalkerFuzzInput.decode(bytes).toString(), name)
        }
    }

    internal companion object {
        @Suppress("LongParameterList") // one parameter per field of the encoded input
        private fun input(
            seed: Long,
            depth: Int,
            anchors: Int,
            vararg mutations: Mutation,
            revoked: Boolean = true,
            throwKind: ThrowKind = ThrowKind.NONE,
            throwSelector: Int = 0,
            permuteSeed: Long = 0,
        ) = WalkerFuzzInput(revoked, throwKind, seed, depth, anchors, throwSelector, permuteSeed, mutations.toList())

        /** Seed 11's world at depth 2 under 6 anchors lists its top intermediate at index 6 of its specs. */
        private const val TOP_KEY = 6

        /** The same world's leaf issuer, the lower intermediate. */
        private const val LEAF_ISSUER_KEY = 7

        val CORPUS: Map<String, WalkerFuzzInput> =
            linkedMapOf(
                // P6 and P8 on unmutated worlds: the deepest generated chain under the most anchors, and a root-issued leaf.
                "honest-depth9-200-anchors" to input(1, 9, 200),
                "honest-depth0-accepted" to input(2, 0, 5, revoked = false),
                "honest-name-encoding-alg-mismatch" to input(3, 3, 10, NameEncoding(1), AlgMismatch(0)),
                // Rounds 1–2: Recover + P3; round 2's OID case: UnsupportedOwnSig + P1 and P8.
                "round1-recover-leaf" to input(4, 2, 8, Recover(0)),
                "round2-recover-intermediate" to input(5, 3, 8, Recover(2)),
                "round2-unsupported-own-sig" to input(6, 2, 8, UnsupportedOwnSig(1)),
                // Round 3: SameKeyDecoy and CrossCertToNonAnchor under Permute, P4.
                "round3-decoy-crosscert-permute" to
                    input(7, 2, 8, SameKeyDecoy(0), CrossCertToNonAnchor(1), Permute(99), permuteSeed = 12_345),
                // Round 4: Recover(CertifiedBy) on a deeper child (P3 leaves the leaf's to residual 15) and a spent walk.
                "round4-certified-recover-stuff" to input(8, 3, 8, Recover(2, certifiedBy = 1), Stuff(300, true, 0)),
                // #134 F1: a dead branch's candidates change the NO_ISSUER label, never the rule (P3).
                "f1-dropped-plus-candidates" to
                    input(9, 3, 8, DropIntermediate(1), Stuff(5, true, 0), SelfSignedNonAnchor(0), revoked = false),
                // #134 F2: a cross-certified honest root (seed 17 presents one). Unmutated, so P6 sees a presented
                // candidate tried before the store's anchor; permuteSeed gives P4 its second order.
                "f2-cross-cert-root-order" to input(17, 2, 10, permuteSeed = 77),
                // #134 F6 and the P7 throw kinds, on the leaf issuer's key: a NotFound, never an ENGINE_ERROR.
                "f6-interrupted-verifier" to
                    input(11, 2, 6, throwKind = ThrowKind.INTERRUPTED, throwSelector = LEAF_ISSUER_KEY),
                "p7-assertion-error-verifier" to
                    input(11, 2, 6, throwKind = ThrowKind.ASSERTION, throwSelector = LEAF_ISSUER_KEY),
                "p7-stack-overflow-verifier" to
                    input(11, 2, 6, Stuff(3, true, 0), throwKind = ThrowKind.STACK_OVERFLOW, throwSelector = TOP_KEY),
                "p7-io-verifier" to
                    input(11, 2, 6, Recover(0, 2), throwKind = ThrowKind.IO, throwSelector = LEAF_ISSUER_KEY),
                "p7-runtime-verifier" to
                    input(11, 2, 6, SameKeyDecoy(0), throwKind = ThrowKind.RUNTIME, throwSelector = TOP_KEY),
                // A1: an anchor-certified CA bridges the dropped intermediate above intermediate 1 (P3 excluded, P2 kept).
                "a1-certified-bridge" to input(12, 3, 1, DropIntermediate(1), Recover(1, certifiedBy = 0)),
                // A1 the other way: the honest 9-certificate world is Rejected(FALLBACK_LIMIT), the bridged one Accepted.
                "a1-deep-certified-bridge" to
                    input(20, 9, 1, DropIntermediate(5), Recover(2, certifiedBy = 0), revoked = false),
                // A2: above FALLBACK_MAX_PRESENTED a walk without a path is PATH_BUDGET_EXCEEDED(FALLBACK_LIMIT).
                "a2-deep-unsupported-own-sig" to input(13, 9, 4, UnsupportedOwnSig(3)),
                "a2-deep-drop-intermediate" to input(14, 9, 4, DropIntermediate(4)),
                // A3: the reason is the leaf level's.
                "a3-drop-leaf-issuer" to input(15, 2, 4, DropIntermediate(0)),
                "a3-drop-higher-intermediate" to input(16, 4, 4, DropIntermediate(2)),
                // P8 with both: a NotFound walk, never Budget.
                "p8-unsupported-and-dropped" to input(19, 3, 4, UnsupportedOwnSig(2), DropIntermediate(0)),
                // Dead ends: a pad past MAX_DEPTH, a loop, a duplicate and refused end-entity issuers.
                "dead-ends" to
                    input(
                        18,
                        3,
                        12,
                        DepthPad(0, 20),
                        Loop(1),
                        Duplicate(0, 1),
                        EndEntityIssuer(0, 0, false),
                        EndEntityIssuer(1, 0, true),
                    ),
            )
    }
}
