// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.NoIssuerReason
import dev.revokt.WalkEnd
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.budget
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound

/**
 * Row (as), proposed in #237: an issuer's nameConstraints, an anchor's included, bind every certificate below it, as
 * webpki applies them ([NameConstraints]). A violation is a dead end before the link is verified; spending the
 * comparison budget ends the walk `Budget(EXPLORATION_BUDGET)`. The leaf presents the dNSName `leaf.example` unless a
 * case says otherwise.
 */
internal object WalkerFixturesAs {
    fun san(vararg names: ByteArray): ByteArray = TestDer.extension("2.5.29.17", TestDer.seq(*names))

    fun dns(name: String): ByteArray = TestDer.tlv(0x82, TestDer.ascii(name))

    /** A nameConstraints extension with [permitted] and [excluded] bases (GeneralName TLVs). */
    fun nameConstraints(
        permitted: List<ByteArray> = emptyList(),
        excluded: List<ByteArray> = emptyList(),
    ): ByteArray {
        fun subtrees(
            tag: Int,
            bases: List<ByteArray>,
        ): ByteArray =
            if (bases.isEmpty()) {
                ByteArray(
                    0,
                )
            } else {
                TestDer.tlv(tag, bases.map { TestDer.seq(it) }.reduce(ByteArray::plus))
            }
        return TestDer.extension(
            "2.5.29.30",
            TestDer.seq(subtrees(0xa0, permitted), subtrees(0xa1, excluded)),
            critical = true,
        )
    }

    fun `as`(): List<WalkerFixture> =
        onTheIssuer() + listOf(subCa(), anchor(), wildcardInside(), wildcardOutside(), exhausted())

    /** leaf → I → R with nameConstraints on I. */
    private fun onTheIssuer(): List<WalkerFixture> =
        listOf(
            Triple("permitted leaf.example", nameConstraints(permitted = listOf(dns("leaf.example"))), true),
            Triple("permitted .example", nameConstraints(permitted = listOf(dns(".example"))), true),
            Triple("excluded leaf.example", nameConstraints(excluded = listOf(dns("leaf.example"))), false),
            Triple("permitted other.example", nameConstraints(permitted = listOf(dns("other.example"))), false),
            Triple(
                "a directoryName subtree",
                nameConstraints(permitted = listOf(TestDer.tlv(0xa4, TestDer.seq()))),
                false,
            ),
            Triple("unreadable: no subtrees", TestDer.extension("2.5.29.30", TestDer.seq()), false),
        ).map { (variant, nc, passes) ->
            val h = Honest(leafExtensions = listOf(san(dns("leaf.example"))), intermediateExtensions = listOf(nc))
            h.fixture(
                "as",
                variant,
                presented = listOf(h.leaf, h.intermediate),
                walk =
                    if (passes) {
                        found(h.path).copy(verifications = 2, candidatesExplored = 2)
                    } else {
                        notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 0, candidatesExplored = 1)
                    },
            )
        }

    /**
     * #234's review scenario with a name-constrained sub-CA: S, permitted `attacker.example` only, signs C, a CA
     * certificate for a key recovered from the leaf's signature. The real leaf's `leaf.example` violates S's
     * constraint, so `[L, C, S]` is `UNANCHORED`.
     */
    private fun subCa(): WalkerFixture {
        val h = Honest(leafExtensions = listOf(san(dns("leaf.example"))))
        val s =
            h.w.cert(
                "S",
                h.w.name("Constrained sub-CA"),
                h.root.subject,
                signer = h.root.key,
                extensions = listOf(nameConstraints(permitted = listOf(dns("attacker.example")))),
            )
        val c = h.w.cert("C", h.intermediate.subject, s.subject, signer = s.key).also { h.w.verifies(h.leaf, it.key) }
        return h.fixture(
            "as",
            "name-constrained sub-CA certifying a recovered key",
            presented = listOf(h.leaf, c, s),
            walk =
                notFound(NoIssuerReason.UNANCHORED).copy(
                    verifications = 1,
                    candidatesExplored = 3,
                    relatedExploredAtLeaf = 1,
                    unrelatedExploredAtLeaf = 1,
                ),
        )
    }

    /** An anchor's nameConstraints bind too: R permits `other.example` only, so `leaf → I → R` stops at R. */
    private fun anchor(): WalkerFixture {
        val w = FixtureWorld()
        val name = w.name("Root")
        val key = w.key()
        val root =
            w.cert(
                "R",
                name,
                name,
                key,
                signer = key,
                extensions = listOf(nameConstraints(permitted = listOf(dns("other.example")))),
            )
        val i = w.cert("I", w.name("Intermediate"), root.subject, signer = root.key)
        val leaf =
            w.cert(
                "L",
                w.name("leaf.example"),
                i.subject,
                signer = i.key,
                key = w.leafKey(),
                extensions = listOf(san(dns("leaf.example"))),
            )
        return w.fixture(
            "as",
            "an anchor's nameConstraints",
            listOf(leaf, i),
            listOf(root),
            notFound(NoIssuerReason.UNANCHORED).copy(verifications = 1, candidatesExplored = 2),
        )
    }

    /** A wildcard leaf name is inside a permitted subtree that holds every expansion: `*.leaf.example` in `leaf.example`. */
    private fun wildcardInside(): WalkerFixture = wildcard("leaf.example", passes = true)

    /** …and outside one an expansion could leave: `*.leaf.example` against `a.leaf.example`. */
    private fun wildcardOutside(): WalkerFixture = wildcard("a.leaf.example", passes = false)

    private fun wildcard(
        permitted: String,
        passes: Boolean,
    ): WalkerFixture {
        val h =
            Honest(
                leafExtensions = listOf(san(dns("*.leaf.example"))),
                intermediateExtensions = listOf(nameConstraints(permitted = listOf(dns(permitted)))),
            )
        return h.fixture(
            "as",
            "wildcard leaf name, permitted $permitted",
            presented = listOf(h.leaf, h.intermediate),
            walk =
                if (passes) {
                    found(h.path).copy(verifications = 2, candidatesExplored = 2)
                } else {
                    notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 0, candidatesExplored = 1)
                },
        )
    }

    /**
     * 500 leaf names against 501 permitted subtrees, each name inside the last: 250,500 comparisons, past [NameConstraints.MAX_COMPARISONS], so
     * the walk ends `Budget(EXPLORATION_BUDGET)` at the leaf's level with no path.
     */
    private fun exhausted(): WalkerFixture {
        val names = List(500) { dns("n$it.leaf.example") }
        // Every name is inside the last subtree, so each one is compared with all 501 (a permitted match does not stop
        // the loop in webpki either).
        val subtrees = List(500) { dns("s$it.leaf.example") } + dns("leaf.example")
        val h =
            Honest(
                leafExtensions = listOf(san(*names.toTypedArray())),
                intermediateExtensions = listOf(nameConstraints(permitted = subtrees)),
            )
        return h.fixture(
            "as",
            "the comparison budget",
            presented = listOf(h.leaf, h.intermediate),
            walk = budget(WalkEnd.EXPLORATION_BUDGET, 1).copy(verifications = 0, candidatesExplored = 1),
        )
    }
}
