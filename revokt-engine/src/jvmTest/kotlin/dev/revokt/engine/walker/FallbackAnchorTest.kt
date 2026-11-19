// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.FallbackReason
import dev.revokt.Finding
import dev.revokt.NoIssuerReason
import dev.revokt.PathStatus
import dev.revokt.RevoktTestingApi
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * A fallback path's last certificate (#237, #253's reviews): it must be an anchor of the index by exact bytes, which
 * exempts it from [IssuerProfile.mayIssue] but not from its own nameConstraints, as in the walker.
 */
@OptIn(RevoktTestingApi::class)
class FallbackAnchorTest {
    private val h = Honest(leafExtensions = listOf(WalkerFixturesAs.san(WalkerFixturesAs.dns("leaf.example"))))

    /** A self-signed snapshot anchor named [label] with exactly [extensions] (a leaf key adds no basicConstraints). */
    private fun anchor(
        label: String,
        vararg extensions: ByteArray,
    ): FixtureCert {
        val name = h.w.name("Anchor $label")
        val key = h.w.leafKey()
        return h.w.cert(label, name, name, key, signer = key, extensions = extensions.toList())
    }

    /** A CA named like the leaf's issuer, under [issuer]. */
    private fun ca(
        label: String,
        issuer: FixtureCert,
    ): FixtureCert = h.w.cert(label, h.intermediate.subject, issuer.subject, signer = issuer.key)

    private val refusesLeaf =
        anchor(
            "AN",
            TestDer.basicConstraints(ca = true),
            WalkerFixturesAs.nameConstraints(permitted = listOf(WalkerFixturesAs.dns("other.example"))),
        )
    private val pathLenZero = anchor("AP", WalkerFixturesAr.caWithPathLen(0))
    private val noKeyCertSign =
        anchor("AK", TestDer.basicConstraints(ca = true), WalkerFixturesAr.keyUsage(0x07, 0x80))
    private val emailOnly =
        anchor("AE", TestDer.basicConstraints(ca = true), WalkerFixturesAr.eku("1.3.6.1.5.5.7.3.4"))
    private val bare = anchor("AB")

    private val fixture =
        h.fixture(
            "fb-anchor",
            presented = listOf(h.leaf),
            walk = notFound(NoIssuerReason.NO_CANDIDATE),
            snapshot = listOf(h.root, refusesLeaf, pathLenZero, noKeyCertSign, emailOnly, bare),
        )

    private fun decide(vararg path: FixtureCert): PathDecision =
        WalkerHarness.decide(fixture, FakeFallback.finds(*path))

    private fun failed(d: PathDecision): Boolean =
        d.findings
            .filterIsInstance<Finding.FallbackNotUsed>()
            .singleOrNull()
            ?.reason == FallbackReason.FAILED

    @Test
    fun `walker a fallback anchor's own nameConstraints still bind the path`() {
        val d = decide(h.leaf, ca("IN", refusesLeaf), refusesLeaf)
        assertEquals(true, failed(d), "the anchor is in the snapshot, so only its nameConstraints refuse the path")
        assertEquals(PathStatus.NO_ISSUER, d.path.status)
    }

    @Test
    fun `walker a fallback path must end at its anchor, not run past it`() {
        val ee = h.w.cert("EE", h.w.name("past.example"), h.root.subject, h.w.leafKey(), signer = h.root.key)
        assertEquals(true, failed(decide(h.leaf, h.intermediate, h.root, ee)))
        assertEquals(PathStatus.FOUND, decide(h.leaf, h.intermediate, h.root).path.status, "the control")
    }

    @Test
    fun `walker a fallback anchor is exempt from mayIssue`() {
        // pathLen 0 with two CAs under it, no keyCertSign, emailProtection only, no basicConstraints at all.
        val i2 = h.w.cert("AP2", h.w.name("Under AP"), pathLenZero.subject, signer = pathLenZero.key)
        assertEquals(PathStatus.FOUND, decide(h.leaf, ca("AP1", i2), i2, pathLenZero).path.status, "pathLen 0")
        for (top in listOf(noKeyCertSign, emailOnly, bare)) {
            assertEquals(PathStatus.FOUND, decide(h.leaf, ca("${top.label}1", top), top).path.status, top.label)
        }
    }
}
