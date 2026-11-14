// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.evaluate.StubEngine
import dev.revokt.engine.evaluate.snapshot
import dev.revokt.engine.walker.ExpectedWalk
import dev.revokt.engine.walker.FixtureCert
import dev.revokt.engine.walker.FixtureWorld
import dev.revokt.engine.walker.WalkerFixture
import dev.revokt.engine.walker.WalkerHarness
import dev.revokt.engine.walker.fixture
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * `anchorIn` matches the reported path, the first one found (#196 F2, spec §5.1 `related`): the walker tries the
 * candidates in Firefox's order at every depth, the store's anchors, then the presented certificates by index. A leaf
 * issued by "Issuing CA", whose key is certified under the public root Rpub and under the private anchor P, with
 * `exemptAnchors([P])` under `STRICT` and an issuer CRLite does not enroll: the verdict follows the first path in that
 * order, pinned in both presented orders.
 */
@OptIn(RevoktTestingApi::class)
class AnchorOrderTest {
    private val w = FixtureWorld()
    private val rpub = w.root("Rpub", "Public root")
    private val issuerName = w.name("Issuing CA")
    private val issuerKey = w.key()
    private val leaf = w.cert("L", w.name("leaf.example"), issuerName, signer = issuerKey, key = w.leafKey())

    private fun verdict(
        f: WalkerFixture,
        privateAnchor: FixtureCert,
    ): Verdict {
        val policy =
            RevoktPolicy.STRICT
                .newBuilder()
                .exemptAnchors(
                    listOf(privateAnchor.bytesHash.toByteArray()),
                ).build()
        return EvaluatorRig(
            f,
            policy,
            snapshot(),
            StubEngine.always(CrliteQueryResult.NOT_ENROLLED),
        ).presented(f.presented)
    }

    private fun reported(v: Verdict): List<List<Byte>> =
        v.findings
            .filterIsInstance<Finding.Path>()
            .single()
            .reportedPathSha256s
            .map { it.toList() }

    private fun hashes(vararg certs: FixtureCert): List<List<Byte>> = certs.map { it.bytesHash.toByteArray().toList() }

    @Test
    fun `the private anchor that is the issuer is tried before every presented certificate, in both orders`() {
        // P is the issuer itself as a self-signed anchor; X is its cross-certificate under Rpub.
        val p = w.cert("P", issuerName, issuerName, issuerKey, signer = issuerKey)
        val x = w.cert("X", issuerName, rpub.subject, issuerKey, signer = rpub.key)
        for (order in listOf(listOf(leaf, x, p), listOf(leaf, p, x))) {
            val f =
                w.fixture(
                    "anchor order",
                    order.joinToString(),
                    order,
                    listOf(rpub, p),
                    ExpectedWalk.found(listOf(leaf, p), listOf(leaf, x, rpub)),
                )
            WalkerHarness.check(f)
            val v = verdict(f, p)
            assertIs<Verdict.Accepted>(v, "$f")
            assertEquals(hashes(leaf, p), reported(v), "$f")
            assertEquals(listOf(Rule.NOT_ENROLLED), v.findings.filterIsInstance<Finding.Exempted>().map { it.rule })
            val path = v.findings.filterIsInstance<Finding.Path>().single()
            assertContentEquals(p.bytesHash.toByteArray(), path.anchorSha256, "$f")
        }
    }

    @Test
    fun `two cross-signed intermediates follow the presented order, as Firefox does`() {
        // P is a separate private root; I is cross-signed under both roots, so neither anchor issues the leaf.
        val p = w.root("P", "Private root")
        val underPublic = w.cert("Ipub", issuerName, rpub.subject, issuerKey, signer = rpub.key)
        val underPrivate = w.cert("Ip", issuerName, p.subject, issuerKey, signer = p.key)
        val cases =
            listOf(
                listOf(leaf, underPublic, underPrivate) to rpub,
                listOf(leaf, underPrivate, underPublic) to p,
            )
        for ((order, first) in cases) {
            val f = w.fixture("anchor order", order.joinToString(), order, listOf(rpub, p), ExpectedWalk.found())
            val v = verdict(f, p)
            assertEquals(hashes(order[0], order[1], first), reported(v), "$f")
            if (first === p) {
                assertIs<Verdict.Accepted>(v, "$f")
            } else {
                assertEquals(Rule.NOT_ENROLLED, assertIs<Verdict.Rejected>(v, "$f").rule)
            }
        }
    }
}
