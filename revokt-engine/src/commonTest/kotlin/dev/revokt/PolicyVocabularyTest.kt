// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The enum constants an exemption or a policy can see and name as strings (#120's CEL-readiness criteria for #81 and
 * #84): each constant's `name` is frozen within a major, never its ordinal. A constant may be added in a minor where
 * the enum is growable, which adds a name here; a rename or a removal fails this test. `Rule` is compared as a set,
 * since its order is precedence, which `RuleModelTest` pins: a rule inserted within its class group is not a vocabulary
 * change.
 */
class PolicyVocabularyTest {
    private fun names(entries: List<Enum<*>>): List<String> = entries.map { it.name }

    @Test
    fun `the rule names are these`() {
        assertEquals(
            setOf(
                "REVOKED",
                "PATH_BUDGET_EXCEEDED",
                "NO_DATA",
                "ENGINE_ERROR",
                "PARSE_FAILED",
                "ISSUER_UNVERIFIED",
                "NO_ISSUER",
                "NOT_ENROLLED",
                "NO_SCTS",
                "NOT_COVERED",
                "STALE",
                "UNSIGNED_DATA",
            ),
            Rule.entries.mapTo(HashSet()) { it.name },
        )
    }

    @Test
    fun `the other policy enums' names are these, in declaration order`() {
        val expected =
            mapOf(
                "RuleClass" to listOf("EVIDENCE", "UNEVALUABLE", "NON_ANSWER", "DATA_QUALITY"),
                "Layer" to listOf("PATH", "CRLITE"),
                "PathStatus" to
                    listOf(
                        "FOUND",
                        "NO_ISSUER",
                        "ISSUER_UNVERIFIED",
                        "PATH_BUDGET_EXCEEDED",
                        "PARSE_FAILED",
                        "NOT_WALKED",
                    ),
                "NoIssuerReason" to listOf("NO_CANDIDATE", "ALL_CANDIDATES_INVALID", "UNANCHORED", "PLATFORM_ONLY"),
                "TrustClass" to listOf("SIGNED", "MIRROR", "SYSTEM", "BUNDLED"),
                "Dataset" to listOf("CRLITE"),
                "CredentialType" to listOf("X509"),
                "ChainSource" to listOf("PLATFORM", "RECONSTRUCTED", "PRESENTED"),
                "ParseReason" to listOf("STRUCTURE", "OVERSIZE", "PRODUCER_UNKEYABLE"),
                "KeyabilityClause" to
                    listOf("HEADER", "TBS_SHAPE", "INTEGER", "OID", "NAME", "TIME", "KEY", "EXTENSION"),
                "TerminalKind" to listOf("ANCHOR"),
                "WalkEnd" to listOf("COMPLETE", "RELATED_BUDGET", "VERIFICATION_BUDGET", "EXPLORATION_BUDGET"),
                "Freshness" to
                    listOf(
                        "RECORD_LAST_MODIFIED",
                        "LAST_VERIFIED_POLL",
                        "MANIFEST_LAST_MODIFIED",
                        "SEED_SIGNED_TIME",
                        "SEQUENCE_TIME",
                        "ARTIFACT_DATE",
                    ),
                "EngineErrorProducer" to listOf("BOUNDARY", "ENGINE", "EXEMPTION"),
                "CrliteQueryResult" to
                    listOf(
                        "NOT_REVOKED",
                        "REVOKED",
                        "NOT_COVERED",
                        "NOT_ENROLLED",
                        "NO_SCTS",
                        "NO_DATA",
                        "ENGINE_ERROR",
                    ),
            )
        val actual =
            mapOf(
                "RuleClass" to names(RuleClass.entries),
                "Layer" to names(Layer.entries),
                "PathStatus" to names(PathStatus.entries),
                "NoIssuerReason" to names(NoIssuerReason.entries),
                "TrustClass" to names(TrustClass.entries),
                "Dataset" to names(Dataset.entries),
                "CredentialType" to names(CredentialType.entries),
                "ChainSource" to names(ChainSource.entries),
                "ParseReason" to names(ParseReason.entries),
                "KeyabilityClause" to names(KeyabilityClause.entries),
                "TerminalKind" to names(TerminalKind.entries),
                "WalkEnd" to names(WalkEnd.entries),
                "Freshness" to names(Freshness.entries),
                "EngineErrorProducer" to names(EngineErrorProducer.entries),
                "CrliteQueryResult" to names(CrliteQueryResult.entries),
            )
        assertEquals(expected.keys, actual.keys)
        for ((enum, names) in expected) assertEquals(names, actual[enum], enum)
    }
}
