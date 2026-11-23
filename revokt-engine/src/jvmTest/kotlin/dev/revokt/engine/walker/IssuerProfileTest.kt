// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.walker

import dev.revokt.NoIssuerReason
import dev.revokt.PathReason
import dev.revokt.PathStatus
import dev.revokt.RevoktInternalApi
import dev.revokt.engine.parse.TestDer
import dev.revokt.engine.walker.ExpectedWalk.Companion.found
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** #237's issuer rules ([IssuerProfile]) at their edges, and the request's purpose read through decide. */
class IssuerProfileTest {
    private val w = FixtureWorld()

    /** The profile of a certificate carrying exactly [extensions] (a leaf key, so no basicConstraints is added). */
    private fun profile(vararg extensions: ByteArray): IssuerProfile =
        IssuerProfile.of(
            WalkerCerts.parse(w.cert("X", w.name("X"), w.name("Y"), w.leafKey(), extensions = extensions.toList()).der),
        )

    private val ca = TestDer.basicConstraints(ca = true)

    @Test
    fun `walker pathLenConstraint bounds the CAs under the issuer, and above 127 is not a CA`() {
        val two = profile(WalkerFixturesAr.caWithPathLen(2))
        assertTrue(two.mayIssue(2, RequiredEku.SERVER_AUTH))
        assertFalse(two.mayIssue(3, RequiredEku.SERVER_AUTH))
        assertTrue(profile(WalkerFixturesAr.caWithPathLen(127)).isCa)
        assertFalse(profile(WalkerFixturesAr.caWithPathLen(128)).isCa)
        assertTrue(profile(ca).mayIssue(99, RequiredEku.SERVER_AUTH), "no pathLenConstraint: no bound")
    }

    @Test
    fun `walker keyUsage needs keyCertSign only when present, and a duplicate fails closed`() {
        assertTrue(profile(ca).keyCertSign)
        assertTrue(profile(ca, WalkerFixturesAr.keyUsage(0x02, 0x04)).keyCertSign, "keyCertSign alone")
        assertFalse(profile(ca, WalkerFixturesAr.keyUsage(0x07, 0x80)).keyCertSign)
        val ku = WalkerFixturesAr.keyUsage(0x01, 0x86)
        assertFalse(profile(ca, ku, ku).keyCertSign, "two keyUsage extensions")
    }

    @Test
    fun `walker extKeyUsage allows only the purposes it lists, absent allows every one, and malformed none`() {
        assertTrue(RequiredEku.entries.all { profile(ca).allows(it) })
        val server = profile(ca, WalkerFixturesAr.eku("1.3.6.1.5.5.7.3.1"))
        assertTrue(server.allows(RequiredEku.SERVER_AUTH))
        assertFalse(server.allows(RequiredEku.CLIENT_AUTH))
        val malformed = TestDer.extension("2.5.29.37", TestDer.tlv(0x04, TestDer.bytes(1)))
        assertFalse(RequiredEku.entries.any { profile(ca, malformed).allows(it) })
    }

    @Test
    fun `decide reads the request's purpose, serverAuth by default`() {
        for ((listed, other) in listOf(
            RequiredEku.SERVER_AUTH to RequiredEku.CLIENT_AUTH,
            RequiredEku.CLIENT_AUTH to RequiredEku.SERVER_AUTH,
        )) {
            val oid = if (listed == RequiredEku.SERVER_AUTH) "1.3.6.1.5.5.7.3.1" else "1.3.6.1.5.5.7.3.2"
            val f =
                with(Honest()) {
                    val i =
                        w.cert(
                            "I",
                            w.name("Issuing CA"),
                            root.subject,
                            signer = root.key,
                            extensions = listOf(WalkerFixturesAr.eku(oid)),
                        )
                    val leaf = w.cert("L", w.name("leaf.example"), i.subject, signer = i.key, key = w.leafKey())
                    fixture("eku", presented = listOf(leaf, i), walk = found(listOf(leaf, i, root)))
                }
            assertEquals(PathStatus.FOUND, WalkerHarness.decide(f, null, requiredEku = listed).path.status, "$listed")
            val refused = WalkerHarness.decide(f, null, requiredEku = other).path
            assertEquals(PathStatus.NO_ISSUER, refused.status, "$other")
            assertEquals(PathReason.ALL_CANDIDATES_INVALID, refused.reason, "$other")
            val byDefault = WalkerHarness.decide(f, null).path.status
            assertEquals(if (listed == RequiredEku.SERVER_AUTH) PathStatus.FOUND else PathStatus.NO_ISSUER, byDefault)
        }
    }
}
