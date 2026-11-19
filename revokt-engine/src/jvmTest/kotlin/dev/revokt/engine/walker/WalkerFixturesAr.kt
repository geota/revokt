// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.NoIssuerReason
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import dev.revokt.engine.walker.ExpectedWalk.Companion.notFound

/**
 * Row (ar), proposed in #237: a non-anchor issuer must also be within its `pathLenConstraint`, set `keyCertSign` when
 * it has keyUsage, and list the required purpose (`serverAuth` in the harness) when it has extKeyUsage, as webpki and
 * mozilla::pkix require (`keyCertSign` as pkix and the JDK; webpki ignores keyUsage). Each failing value is a dead end
 * before the link is verified, as #225's CA check is. A certificate with a [FixtureWorld.leafKey] carries only the
 * extensions a case lists; any other gets `cA = TRUE` ahead of them.
 */
internal object WalkerFixturesAr {
    private const val SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
    private const val CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    private const val EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
    private const val ANY_EKU = "2.5.29.37.0"

    /** basicConstraints `cA = TRUE` with `pathLenConstraint` [pathLen]. */
    fun caWithPathLen(pathLen: Int): ByteArray =
        TestDer.extension(
            "2.5.29.19",
            TestDer.seq(TestDer.tlv(0x01, TestDer.bytes(0xff)), TestDer.tlv(0x02, minimal(pathLen))),
            critical = true,
        )

    private fun minimal(v: Int): ByteArray =
        java.math.BigInteger
            .valueOf(v.toLong())
            .toByteArray()

    /** A critical keyUsage whose BIT STRING content (unused-bits octet first) is [content]. */
    fun keyUsage(vararg content: Int): ByteArray =
        TestDer.extension("2.5.29.15", TestDer.tlv(0x03, TestDer.bytes(*content)), critical = true)

    /** An extKeyUsage listing [purposes]. */
    fun eku(vararg purposes: String): ByteArray =
        TestDer.extension("2.5.29.37", TestDer.seq(*purposes.map { TestDer.oid(it) }.toTypedArray()))

    fun ar(): List<WalkerFixture> = pathLen() + keyUsages() + ekus() + constrainedSubCa()

    /**
     * leaf → I1 → I2 → R with `pathLenConstraint` on I2: 0 is a dead end (one CA, I1, under it), 1 and above pass. A
     * `pathLen` 0 on the leaf's own issuer passes (no CA under it). 128 is above pkix's bound, so I2 is not a CA.
     */
    private fun pathLen(): List<WalkerFixture> {
        val deep =
            listOf(0, 1, 128).map { len ->
                val w = FixtureWorld()
                val root = w.root("R", "Root")
                val i2 =
                    w.cert(
                        "I2",
                        w.name("Intermediate 2"),
                        root.subject,
                        w.leafKey(),
                        signer = root.key,
                        extensions = listOf(caWithPathLen(len)),
                    )
                val i1 = w.cert("I1", w.name("Intermediate 1"), i2.subject, signer = i2.key)
                val leaf = w.cert("L", w.name("leaf.example"), i1.subject, signer = i1.key, key = w.leafKey())
                w.fixture(
                    "ar",
                    "pathLenConstraint $len on the second intermediate",
                    listOf(leaf, i1, i2),
                    listOf(root),
                    if (len == 1) {
                        found(listOf(leaf, i1, i2, root)).copy(verifications = 3, candidatesExplored = 3)
                    } else {
                        // I2 is a dead end below I1. At the leaf's unrelated loop, pathLen 0 admits it (no CA under
                        // it there), so its link to the leaf is tried and fails; 128 is not a CA anywhere.
                        notFound(NoIssuerReason.UNANCHORED).copy(
                            verifications = if (len == 0) 2 else 1,
                            candidatesExplored = 3,
                        )
                    },
                )
            }
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val i =
            w.cert(
                "I",
                w.name("Intermediate"),
                root.subject,
                w.leafKey(),
                signer = root.key,
                extensions = listOf(caWithPathLen(0)),
            )
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
        val shallow =
            w.fixture(
                "ar",
                "pathLenConstraint 0 on the leaf's issuer",
                listOf(leaf, i),
                listOf(root),
                found(listOf(leaf, i, root)).copy(verifications = 2, candidatesExplored = 2),
            )
        return deep + shallow
    }

    /**
     * leaf → I → R with keyUsage on I: `keyCertSign` (with digitalSignature and cRLSign, the usual CA value) passes;
     * digitalSignature alone, no bits at all, and a BIT STRING with bad padding are dead ends.
     */
    private fun keyUsages(): List<WalkerFixture> =
        listOf(
            Triple("keyUsage with keyCertSign", intArrayOf(0x01, 0x86), true),
            Triple("keyUsage without keyCertSign", intArrayOf(0x07, 0x80), false),
            Triple("keyUsage with no bits", intArrayOf(0x00), false),
            Triple("keyUsage with 8 unused bits: malformed", intArrayOf(0x08, 0x04), false),
        ).map { (variant, content, passes) -> leafIssuerCase(variant, listOf(keyUsage(*content)), passes) }

    /**
     * leaf → I → R with extKeyUsage on I: listing serverAuth passes, alone or beside clientAuth; emailProtection
     * alone, `anyExtendedKeyUsage` alone (neither reference counts it), and an empty SEQUENCE are dead ends.
     */
    private fun ekus(): List<WalkerFixture> =
        listOf(
            Triple("extKeyUsage serverAuth", eku(SERVER_AUTH), true),
            Triple("extKeyUsage clientAuth and serverAuth", eku(CLIENT_AUTH, SERVER_AUTH), true),
            Triple("extKeyUsage emailProtection", eku(EMAIL_PROTECTION), false),
            Triple("extKeyUsage anyExtendedKeyUsage", eku(ANY_EKU), false),
            Triple("extKeyUsage empty", TestDer.extension("2.5.29.37", TestDer.seq()), false),
        ).map { (variant, ext, passes) -> leafIssuerCase(variant, listOf(ext), passes) }

    /** leaf → I → R, I a CA with [extensions] after its `cA = TRUE`: `Found`, or `ALL_CANDIDATES_INVALID`. */
    private fun leafIssuerCase(
        variant: String,
        extensions: List<ByteArray>,
        passes: Boolean,
    ): WalkerFixture {
        val w = FixtureWorld()
        val root = w.root("R", "Root")
        val i = w.cert("I", w.name("Intermediate"), root.subject, signer = root.key, extensions = extensions)
        val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
        val walk =
            if (passes) {
                found(listOf(leaf, i, root)).copy(verifications = 2, candidatesExplored = 2)
            } else {
                notFound(NoIssuerReason.ALL_CANDIDATES_INVALID).copy(verifications = 0, candidatesExplored = 1)
            }
        return w.fixture("ar", variant, listOf(leaf, i), listOf(root), walk)
    }

    /**
     * #234's review scenario: S is an organisation's constrained sub-CA under the real root, and signs C, a CA
     * certificate named like the leaf's issuer for a key recovered from the leaf's signature. With S limited by
     * `pathLenConstraint` 0, or to emailProtection, `[L, C, S]` is `UNANCHORED`: S is a dead end below C, and again
     * at the leaf's unrelated loop. Without either limit S is an unconstrained CA and `[L, C, S]` is `Found` through
     * C: a CA key holder under a real anchor can certify any key, the §10 residual that remains.
     */
    private fun constrainedSubCa(): List<WalkerFixture> =
        listOf(
            "pathLenConstraint 0" to caWithPathLen(0),
            "extKeyUsage emailProtection" to null,
            "no limit, an unconstrained CA" to TestDer.basicConstraints(ca = true),
        ).map { (variant, bc) ->
            val honest = Honest()
            val w = honest.w
            val sExtensions =
                if (bc == null) listOf(TestDer.basicConstraints(ca = true), eku(EMAIL_PROTECTION)) else listOf(bc)
            val s =
                w.cert(
                    "S",
                    w.name("Constrained sub-CA"),
                    honest.root.subject,
                    w.leafKey(),
                    signer = honest.root.key,
                    extensions = sExtensions,
                )
            val c =
                w
                    .cert("C", honest.intermediate.subject, s.subject, signer = s.key)
                    .also { w.verifies(honest.leaf, it.key) }
            honest.fixture(
                "ar",
                "constrained sub-CA certifying a recovered key, $variant",
                presented = listOf(honest.leaf, c, s),
                walk =
                    if (variant.startsWith("no limit")) {
                        found(listOf(honest.leaf, c, s, honest.root)).copy(verifications = 3, candidatesExplored = 3)
                    } else {
                        // At the leaf's unrelated loop pathLen 0 admits S, so L/S is tried and fails.
                        notFound(NoIssuerReason.UNANCHORED).copy(
                            verifications = if (bc == null) 1 else 2,
                            candidatesExplored = 3,
                            relatedExploredAtLeaf = 1,
                            unrelatedExploredAtLeaf = 1,
                        )
                    },
            )
        }
}
