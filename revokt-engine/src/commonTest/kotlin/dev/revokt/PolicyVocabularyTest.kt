// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The enum constants a policy names as strings (#120's CEL-readiness criteria for #81 and #84): each constant's `name`
 * is frozen within a major, never its ordinal. A constant may be appended in a minor where the enum is growable, which
 * adds a line here; a rename or a removal fails this test.
 */
class PolicyVocabularyTest {
    @Test
    fun `the policy vocabulary is these names`() {
        assertEquals(
            listOf(
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
            Rule.entries.map { it.name },
        )
        assertEquals(
            listOf("EVIDENCE", "UNEVALUABLE", "NON_ANSWER", "DATA_QUALITY"),
            RuleClass.entries.map { it.name },
        )
        assertEquals(listOf("PATH", "CRLITE"), Layer.entries.map { it.name })
        assertEquals(
            listOf("FOUND", "NO_ISSUER", "ISSUER_UNVERIFIED", "PATH_BUDGET_EXCEEDED", "PARSE_FAILED", "NOT_WALKED"),
            PathStatus.entries.map { it.name },
        )
        assertEquals(
            listOf("NO_CANDIDATE", "ALL_CANDIDATES_INVALID", "UNANCHORED", "PLATFORM_ONLY"),
            NoIssuerReason.entries.map { it.name },
        )
        assertEquals(listOf("SIGNED", "MIRROR", "SYSTEM", "BUNDLED"), TrustClass.entries.map { it.name })
        assertEquals(listOf("CRLITE"), Dataset.entries.map { it.name })
        assertEquals(listOf("X509"), CredentialType.entries.map { it.name })
    }
}
