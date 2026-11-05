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
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class FindingTest {
    private fun hash(b: Int) = ByteArray(32) { b.toByte() }

    private fun found() =
        Finding.Path
            .Builder()
            .status(PathStatus.FOUND)
            .source(ChainSource.RECONSTRUCTED)
            .terminalKind(TerminalKind.ANCHOR)
            .endReason(WalkEnd.COMPLETE)
            .endDepth(3)
            .anchorSnapshotId(7)
            .pathsFound(1)
            .reportedPathSha256s(listOf(hash(1), hash(2), hash(3)))
            .issuerSpkiSha256s(listOf(hash(4)))
            .anchorSha256(hash(3))
            .walkStats(WalkStats(2, 2, 1, 0))
            .build()

    /**
     * Every field set away from its builder default, so a round trip that drops one shows. The reason fields exclude
     * each other, so a NO_ISSUER and a PARSE_FAILED fixture between them set all three; credentialType has only X509.
     */
    private fun everyField(status: PathStatus): Finding.Path =
        Finding.Path
            .Builder()
            .status(status)
            .source(ChainSource.PLATFORM)
            .noIssuerReason(NoIssuerReason.PLATFORM_ONLY.takeIf { status == PathStatus.NO_ISSUER })
            .walkerReason(NoIssuerReason.UNANCHORED)
            .parseReason(ParseReason.PRODUCER_UNKEYABLE.takeIf { status == PathStatus.PARSE_FAILED })
            .keyabilityClause(KeyabilityClause.TIME.takeIf { status == PathStatus.PARSE_FAILED })
            .terminalKind(TerminalKind.ANCHOR)
            .rewalkEnd(WalkEnd.VERIFICATION_BUDGET)
            .endReason(WalkEnd.EXPLORATION_BUDGET)
            .endDepth(2)
            .cacheHit(true)
            .anchorSnapshotId(11)
            .usedFallback(true)
            .pathsFound(3)
            .reportedPathSha256s(listOf(hash(1), hash(3)))
            .issuerSpkiSha256s(listOf(hash(4), hash(5)))
            .candidatesDropped(2)
            .anchorSha256(hash(3))
            .walkStats(WalkStats(5, 6, 7, 8))
            .credentialType(CredentialType.X509)
            .build()

    private fun noIssuer(reason: NoIssuerReason) =
        found()
            .newBuilder()
            .status(PathStatus.NO_ISSUER)
            .noIssuerReason(reason)
            .build()

    private fun parseFailed(
        reason: ParseReason,
        clause: KeyabilityClause? = null,
    ) = found()
        .newBuilder()
        .status(PathStatus.PARSE_FAILED)
        .parseReason(reason)
        .keyabilityClause(clause)
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
            listOf("NO_CANDIDATE", "ALL_CANDIDATES_INVALID", "UNANCHORED", "PLATFORM_ONLY"),
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
                "MANIFEST_LAST_MODIFIED",
                "SEED_SIGNED_TIME",
                "SEQUENCE_TIME",
                "ARTIFACT_DATE",
            ),
            Freshness.entries.map { it.name },
        )
    }

    @Test
    fun `a path built from equal inputs is equal, and newBuilder round-trips`() {
        assertValueSemantics(found(), found())
        assertValueSemantics(found(), found().newBuilder().build())
        for (p in listOf(everyField(PathStatus.NO_ISSUER), everyField(PathStatus.PARSE_FAILED))) {
            assertValueSemantics(p, p.newBuilder().build())
        }
        assertNotEquals<Any>(found(), "path")
    }

    @Test
    fun `every path field takes part in equality`() {
        val base = found()
        val changed =
            mapOf<String, Finding.Path.Builder.() -> Finding.Path.Builder>(
                "status" to { status(PathStatus.PATH_BUDGET_EXCEEDED) },
                "source" to { source(ChainSource.PLATFORM) },
                "walkerReason" to { walkerReason(NoIssuerReason.NO_CANDIDATE) },
                "terminalKind" to { terminalKind(null) },
                "rewalkEnd" to { rewalkEnd(WalkEnd.COMPLETE) },
                "endReason" to { endReason(WalkEnd.RELATED_BUDGET) },
                "endDepth" to { endDepth(4) },
                "cacheHit" to { cacheHit(true) },
                "anchorSnapshotId" to { anchorSnapshotId(8) },
                "usedFallback" to { usedFallback(true) },
                "pathsFound" to { pathsFound(2) },
                "reportedPathSha256s" to { reportedPathSha256s(listOf(hash(3), hash(2), hash(1))) },
                "issuerSpkiSha256s" to { issuerSpkiSha256s(listOf(hash(4), hash(5))) },
                "candidatesDropped" to { candidatesDropped(1) },
                "anchorSha256" to { anchorSha256(null) },
                "walkStats" to { walkStats(WalkStats(2, 2, 1, 1)) },
                // credentialType has one value in M1 (X509), so no second value to differ by.
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
        // The reason fields are set only with their status, so each differs from a sibling of the same status.
        assertNotEquals(noIssuer(NoIssuerReason.NO_CANDIDATE), noIssuer(NoIssuerReason.UNANCHORED))
        assertNotEquals(parseFailed(ParseReason.STRUCTURE), parseFailed(ParseReason.OVERSIZE))
        assertNotEquals(
            parseFailed(ParseReason.PRODUCER_UNKEYABLE, KeyabilityClause.HEADER),
            parseFailed(ParseReason.PRODUCER_UNKEYABLE, KeyabilityClause.KEY),
        )
    }

    @Test
    fun `toString names every path field and prints hashes in hex`() {
        val text = noIssuer(NoIssuerReason.UNANCHORED).toString()
        val fields =
            listOf(
                "status",
                "source",
                "noIssuerReason",
                "walkerReason",
                "parseReason",
                "keyabilityClause",
                "terminalKind",
                "rewalkEnd",
                "endReason",
                "endDepth",
                "cacheHit",
                "anchorSnapshotId",
                "usedFallback",
                "pathsFound",
                "reportedPathSha256s",
                "issuerSpkiSha256s",
                "candidatesDropped",
                "anchorSha256",
                "walkStats",
                "credentialType",
            )
        for (field in fields) assertTrue("$field=" in text, "$field missing from $text")
        assertTrue(text.startsWith("Path(status=NO_ISSUER, source=RECONSTRUCTED, noIssuerReason=UNANCHORED"), text)
        assertTrue("anchorSha256=${"03".repeat(32)}" in text, text)
        assertTrue("issuerSpkiSha256s=[${"04".repeat(32)}]" in text, text)
    }

    @Test
    fun `the builder defaults and its required fields`() {
        val p =
            Finding.Path
                .Builder()
                .status(PathStatus.NOT_WALKED)
                .source(ChainSource.RECONSTRUCTED)
                .build()
        assertNull(p.terminalKind)
        assertNull(p.endReason)
        assertNull(p.endDepth)
        assertNull(p.anchorSha256)
        assertEquals(0, p.anchorSnapshotId)
        assertEquals(0, p.pathsFound)
        assertEquals(0, p.candidatesDropped)
        assertEquals(false, p.cacheHit)
        assertEquals(false, p.usedFallback)
        assertEquals(emptyList(), p.reportedPathSha256s)
        assertEquals(emptyList(), p.issuerSpkiSha256s)
        assertEquals(WalkStats(0, 0, 0, 0), p.walkStats)
        assertEquals(CredentialType.X509, p.credentialType)
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
    fun `each path invariant throws when broken, in both directions`() {
        fun broken(change: Finding.Path.Builder.() -> Finding.Path.Builder): String =
            assertFailsWith<IllegalArgumentException> { found().newBuilder().change().build() }.message!!
        assertTrue(
            "parseReason is set exactly when status is PARSE_FAILED" in broken { parseReason(ParseReason.STRUCTURE) },
        )
        assertTrue(
            "parseReason is set exactly when status is PARSE_FAILED" in broken { status(PathStatus.PARSE_FAILED) },
        )
        assertTrue(
            "keyabilityClause is set exactly when parseReason is PRODUCER_UNKEYABLE" in
                broken {
                    status(
                        PathStatus.PARSE_FAILED,
                    ).parseReason(ParseReason.STRUCTURE).keyabilityClause(KeyabilityClause.OID)
                },
        )
        assertTrue(
            "keyabilityClause is set exactly when parseReason is PRODUCER_UNKEYABLE" in
                broken { status(PathStatus.PARSE_FAILED).parseReason(ParseReason.PRODUCER_UNKEYABLE) },
        )
        assertTrue("noIssuerReason is set exactly when status is NO_ISSUER" in broken { status(PathStatus.NO_ISSUER) })
        assertTrue(
            "noIssuerReason is set exactly when status is NO_ISSUER" in
                broken { noIssuerReason(NoIssuerReason.NO_CANDIDATE) },
        )
        // The walker's own reason is not tied to the status: PLATFORM_ONLY keeps it after a later promotion.
        assertEquals(
            NoIssuerReason.NO_CANDIDATE,
            found()
                .newBuilder()
                .walkerReason(NoIssuerReason.NO_CANDIDATE)
                .build()
                .walkerReason,
        )
    }

    @Test
    fun `the builder copies what it is given and the getters hand out copies`() {
        val leaf = hash(1)
        val issuer = hash(4)
        val anchor = hash(3)
        val p =
            found()
                .newBuilder()
                .reportedPathSha256s(listOf(leaf, anchor))
                .issuerSpkiSha256s(listOf(issuer))
                .anchorSha256(anchor)
                .build()
        leaf[0] = 9
        issuer[0] = 9
        anchor[0] = 9
        p.reportedPathSha256s[0][0] = 9
        p.issuerSpkiSha256s[0][0] = 9
        p.anchorSha256!![0] = 9
        assertContentEquals(hash(1), p.reportedPathSha256s[0])
        assertContentEquals(hash(3), p.reportedPathSha256s[1])
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
