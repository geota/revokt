// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The path enums and the walk's findings as spec §4 declares them (#104): value types, invariants and fresh copies. */
@OptIn(RevoktTestingApi::class)
class FindingTest {
    private fun hash(b: Int) = ByteArray(32) { b.toByte() }

    private fun found() =
        Finding.Path
            .Builder()
            .status(PathStatus.FOUND)
            .source(ChainSource.RECONSTRUCTED)
            .issuerSpkiSha256s(listOf(hash(4)))
            .anchorSha256(hash(3))
            .build()

    /** Every field set away from its builder default, so a round trip that drops one shows. */
    private fun everyField(): Finding.Path =
        Finding.Path
            .Builder()
            .status(PathStatus.NO_ISSUER)
            .source(ChainSource.PLATFORM)
            .reason(PathReason.PLATFORM_ONLY)
            .issuerSpkiSha256s(listOf(hash(4), hash(5)))
            .anchorSha256(hash(3))
            .build()

    private fun withReason(reason: PathReason) =
        found()
            .newBuilder()
            .status(reason.status)
            .reason(reason)
            .build()

    private fun assertValueSemantics(
        a: Any,
        same: Any,
    ) {
        assertEquals(a, same)
        assertEquals(a.hashCode(), same.hashCode())
        assertEquals(a.toString(), same.toString())
    }

    @Test
    fun `the enums are the spec's, in its order`() {
        assertEquals(
            listOf("NO_CANDIDATE", "ALL_CANDIDATES_INVALID", "UNANCHORED", "UNSUPPORTED_ALGORITHM", "PLATFORM_ONLY"),
            NoIssuerReason.entries.map { it.name },
        )
        assertEquals(listOf("SKIPPED", "DISABLED", "FAILED"), FallbackReason.entries.map { it.name })
        assertEquals(
            listOf("COMPLETE", "RELATED_BUDGET", "VERIFICATION_BUDGET", "EXPLORATION_BUDGET"),
            WalkEnd.entries.map { it.name },
        )
        assertEquals(listOf("PLATFORM", "RECONSTRUCTED", "PRESENTED"), ChainSource.entries.map { it.name })
        assertEquals(listOf("ANCHOR"), TerminalKind.entries.map { it.name })
        assertEquals(listOf("X509"), CredentialType.entries.map { it.name })
        assertEquals(listOf("BOUNDARY", "ENGINE", "EXEMPTION"), EngineErrorProducer.entries.map { it.name })
        assertEquals(
            listOf(
                "RECORD_LAST_MODIFIED",
                "LAST_VERIFIED_POLL",
                "SEED_SIGNED_TIME",
                "SEQUENCE_TIME",
                "ARTIFACT_DATE",
            ),
            Freshness.entries.map { it.name },
        )
    }

    @Test
    fun `PathReason entries are the spec's, each with its status`() {
        val spec =
            listOf(
                "NO_CANDIDATE" to PathStatus.NO_ISSUER,
                "ALL_CANDIDATES_INVALID" to PathStatus.NO_ISSUER,
                "UNANCHORED" to PathStatus.NO_ISSUER,
                "UNSUPPORTED_ALGORITHM" to PathStatus.NO_ISSUER,
                "PLATFORM_ONLY" to PathStatus.NO_ISSUER,
                "STRUCTURE" to PathStatus.PARSE_FAILED,
                "OVERSIZE" to PathStatus.PARSE_FAILED,
                "PRODUCER_UNKEYABLE" to PathStatus.PARSE_FAILED,
                "RELATED_BUDGET" to PathStatus.PATH_BUDGET_EXCEEDED,
                "VERIFICATION_BUDGET" to PathStatus.PATH_BUDGET_EXCEEDED,
                "EXPLORATION_BUDGET" to PathStatus.PATH_BUDGET_EXCEEDED,
                "FALLBACK_LIMIT" to PathStatus.PATH_BUDGET_EXCEEDED,
            )
        assertEquals(spec, PathReason.entries.map { it.name to it.status })
        // The union: every walker and parse reason, and every budget a walk ends on, is a reason of its own name.
        val names = PathReason.entries.map { it.name }
        assertTrue(names.containsAll(NoIssuerReason.entries.map { it.name }))
        assertTrue(names.containsAll(ParseReason.entries.map { it.name }))
        assertTrue(names.containsAll(WalkEnd.entries.filter { it != WalkEnd.COMPLETE }.map { it.name }))
    }

    @Test
    fun `a path built from equal inputs is equal, and newBuilder round-trips`() {
        assertValueSemantics(found(), found())
        assertValueSemantics(found(), found().newBuilder().build())
        assertValueSemantics(everyField(), everyField().newBuilder().build())
        for (reason in PathReason.entries) {
            assertValueSemantics(
                withReason(reason),
                withReason(reason).newBuilder().build(),
            )
        }
        assertNotEquals<Any>(found(), "path")
    }

    @Test
    fun `every path field takes part in equality`() {
        val base = everyField()
        val changed =
            mapOf<String, Finding.Path.Builder.() -> Finding.Path.Builder>(
                "status" to { status(PathStatus.PATH_BUDGET_EXCEEDED).reason(PathReason.RELATED_BUDGET) },
                "source" to { source(ChainSource.RECONSTRUCTED) },
                "reason" to { reason(PathReason.UNANCHORED) },
                "issuerSpkiSha256s" to { issuerSpkiSha256s(listOf(hash(5), hash(4))) },
                "anchorSha256" to { anchorSha256(null) },
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
    }

    @Test
    fun `toString names every path field and prints hashes in hex`() {
        val text = everyField().toString()
        for (field in listOf("status", "source", "reason", "issuerSpkiSha256s", "anchorSha256")) {
            assertTrue("$field=" in text, "$field missing from $text")
        }
        assertTrue(text.startsWith("Path(status=NO_ISSUER, source=PLATFORM, reason=PLATFORM_ONLY"), text)
        assertTrue("anchorSha256=${"03".repeat(32)}" in text, text)
        assertTrue("issuerSpkiSha256s=[${"04".repeat(32)}, ${"05".repeat(32)}]" in text, text)
    }

    @Test
    fun `the builder defaults and its required fields`() {
        val p =
            Finding.Path
                .Builder()
                .status(PathStatus.NOT_WALKED)
                .source(ChainSource.RECONSTRUCTED)
                .build()
        assertNull(p.reason)
        assertNull(p.anchorSha256)
        assertEquals(emptyList(), p.issuerSpkiSha256s)
        val noSource =
            assertFailsWith<IllegalArgumentException> {
                Finding.Path
                    .Builder()
                    .status(PathStatus.FOUND)
                    .build()
            }
        assertEquals("source is not set", noSource.message)
        val noStatus =
            assertFailsWith<IllegalArgumentException> {
                Finding.Path
                    .Builder()
                    .source(ChainSource.PLATFORM)
                    .build()
            }
        assertEquals("status is not set", noStatus.message)
    }

    @Test
    fun `the reason invariant throws when broken, in both directions`() {
        fun broken(
            status: PathStatus,
            reason: PathReason?,
        ): String =
            assertFailsWith<IllegalArgumentException>("$status, $reason") {
                found()
                    .newBuilder()
                    .status(status)
                    .reason(reason)
                    .build()
            }.message!!
        val explained = setOf(PathStatus.NO_ISSUER, PathStatus.PARSE_FAILED, PathStatus.PATH_BUDGET_EXCEEDED)
        for (status in PathStatus.entries) {
            if (status in explained) {
                assertTrue("reason is set exactly when status is NO_ISSUER" in broken(status, null), "$status")
                for (reason in PathReason.entries.filter { it.status != status }) {
                    assertTrue("is not a $status reason" in broken(status, reason), "$status, $reason")
                }
            } else {
                for (reason in PathReason.entries) {
                    assertTrue("reason is set exactly when status is NO_ISSUER" in broken(status, reason), "$status")
                }
            }
        }
    }

    @Test
    fun `the builder copies what it is given and the getters hand out copies`() {
        val issuer = hash(4)
        val anchor = hash(3)
        val p =
            found()
                .newBuilder()
                .issuerSpkiSha256s(listOf(issuer))
                .anchorSha256(anchor)
                .build()
        issuer[0] = 9
        anchor[0] = 9
        p.issuerSpkiSha256s[0][0] = 9
        p.anchorSha256!![0] = 9
        assertContentEquals(hash(4), p.issuerSpkiSha256s.single())
        assertContentEquals(hash(3), p.anchorSha256)
    }

    @Test
    fun `walk stats are a value type`() {
        assertValueSemantics(WalkStats(1, 2, 3, 4), WalkStats(1, 2, 3, 4))
        assertNotEquals(WalkStats(1, 2, 3, 4), WalkStats(0, 2, 3, 4))
        assertNotEquals(WalkStats(1, 2, 3, 4), WalkStats(1, 0, 3, 4))
        assertNotEquals(WalkStats(1, 2, 3, 4), WalkStats(1, 2, 0, 4))
        assertNotEquals(WalkStats(1, 2, 3, 4), WalkStats(1, 2, 3, 0))
        assertNotEquals<Any>(WalkStats(1, 2, 3, 4), "stats")
        assertEquals(
            "WalkStats(verifications=1, candidatesExplored=2, relatedExploredAtLeaf=3, unrelatedExploredAtLeaf=4)",
            WalkStats(1, 2, 3, 4).toString(),
        )
    }

    @Test
    fun `the walk's other findings are value types with required fields`() {
        val ua =
            Finding.UnsupportedAlgorithm
                .Builder()
                .oid("1.2.3")
                .where(Layer.PATH)
                .outcomeDepended(true)
                .build()
        assertValueSemantics(ua, ua.newBuilder().build())
        assertNotEquals(ua, ua.newBuilder().oid("1.2.4").build())
        assertNotEquals(ua, ua.newBuilder().where(Layer.CRLITE).build())
        assertNotEquals(ua, ua.newBuilder().outcomeDepended(false).build())
        assertNotEquals<Any>(ua, "ua")
        assertEquals("UnsupportedAlgorithm(oid=1.2.3, where=PATH, outcomeDepended=true)", ua.toString())
        assertEquals(
            false,
            Finding.UnsupportedAlgorithm
                .Builder()
                .oid("1.2.3")
                .where(Layer.PATH)
                .build()
                .outcomeDepended,
        )

        val ve =
            Finding.VerifierError
                .Builder()
                .oid("1.2.840.10045.4.3.2")
                .message("provider threw")
                .build()
        assertValueSemantics(ve, ve.newBuilder().build())
        assertNotEquals(ve, ve.newBuilder().oid("1.2.840.10045.4.3.3").build())
        assertNotEquals(ve, ve.newBuilder().message("other").build())
        assertNotEquals<Any>(ve, "ve")
        assertEquals("VerifierError(oid=1.2.840.10045.4.3.2, message=provider threw)", ve.toString())

        val fn =
            Finding.FallbackNotUsed
                .Builder()
                .reason(FallbackReason.FAILED)
                .build()
        assertValueSemantics(fn, fn.newBuilder().build())
        for (reason in FallbackReason.entries - FallbackReason.FAILED) {
            assertNotEquals(fn, fn.newBuilder().reason(reason).build())
        }
        assertNotEquals<Any>(fn, "fn")
        assertEquals("FallbackNotUsed(reason=FAILED)", fn.toString())

        val am =
            Finding.AlgorithmIdMismatch
                .Builder()
                .certIndex(1)
                .build()
        assertValueSemantics(am, am.newBuilder().build())
        assertNotEquals(am, am.newBuilder().certIndex(2).build())
        assertNotEquals<Any>(am, "am")
        assertEquals("AlgorithmIdMismatch(certIndex=1)", am.toString())
        assertEquals(
            0,
            am
                .newBuilder()
                .certIndex(0)
                .build()
                .certIndex,
            "the leaf is index 0",
        )

        fun message(block: () -> Any): String = assertFailsWith<IllegalArgumentException> { block() }.message!!
        assertEquals(
            "oid is not set",
            message {
                Finding.UnsupportedAlgorithm
                    .Builder()
                    .where(Layer.PATH)
                    .build()
            },
        )
        assertEquals(
            "where is not set",
            message {
                Finding.UnsupportedAlgorithm
                    .Builder()
                    .oid("1.2")
                    .build()
            },
        )
        assertEquals(
            "oid is not set",
            message {
                Finding.VerifierError
                    .Builder()
                    .message("m")
                    .build()
            },
        )
        assertEquals(
            "message is not set",
            message {
                Finding.VerifierError
                    .Builder()
                    .oid("1.2")
                    .build()
            },
        )
        assertEquals("reason is not set", message { Finding.FallbackNotUsed.Builder().build() })
        assertEquals("certIndex is not set", message { Finding.AlgorithmIdMismatch.Builder().build() })
        assertTrue(
            "got -1" in
                message {
                    Finding.AlgorithmIdMismatch
                        .Builder()
                        .certIndex(-1)
                        .build()
                },
        )
    }

    @Test
    fun `findings of different subtypes are never equal`() {
        val findings: List<Finding> =
            listOf(
                found(),
                Finding.UnsupportedAlgorithm
                    .Builder()
                    .oid("1.2")
                    .where(Layer.PATH)
                    .build(),
                Finding.VerifierError
                    .Builder()
                    .oid("1.2")
                    .message("m")
                    .build(),
                Finding.FallbackNotUsed
                    .Builder()
                    .reason(FallbackReason.SKIPPED)
                    .build(),
                Finding.AlgorithmIdMismatch
                    .Builder()
                    .certIndex(0)
                    .build(),
            )
        for (a in findings) for (b in findings) if (a !== b) assertNotEquals(a, b)
    }
}
