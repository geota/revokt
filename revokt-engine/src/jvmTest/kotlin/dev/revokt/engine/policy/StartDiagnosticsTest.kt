// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.Outcome
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The S diagnostics of spec §4 that read the configuration: `SEED_PAST_REJECT_THRESHOLD`,
 * `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP` and `RULE_FLIPPED_THIS_MINOR`, each a `WARNING`, each exactly in its case,
 * in §4's order.
 */
class StartDiagnosticsTest {
    private val day = 24L * 60 * 60 * 1_000
    private val now = 1_800_000_000_000L

    private fun codes(
        policy: RevoktPolicy,
        probe: Set<String> = emptySet(),
        seed: Long? = null,
        flipped: (Preset, Rule) -> String? = { _, _ -> null },
    ) = startDiagnostics(policy.form, probe, seed, now, "0.2", flipped).map { it.code to it.rule }

    @Test
    fun `the presets with a full probe and a fresh seed give none`() {
        for (policy in listOf(RevoktPolicy.DEFAULT, RevoktPolicy.STRICT)) {
            assertEquals(listOf(), codes(policy, seed = now - day))
        }
        assertEquals(listOf(), startDiagnostics(RevoktPolicy.STRICT.form, emptySet(), now, now))
    }

    @Test
    fun `SEED_PAST_REJECT_THRESHOLD needs STALE rejecting, a threshold and a seed past it`() {
        val strict = RevoktPolicy.STRICT
        val fired = listOf(DiagnosticCode.SEED_PAST_REJECT_THRESHOLD to Rule.STALE)
        assertEquals(fired, codes(strict, seed = now - 30 * day - 1))
        assertEquals(listOf(), codes(strict, seed = now - 30 * day), "at the threshold it is not past")
        assertEquals(listOf(), codes(strict, seed = null), "no seed live")
        val allowing = strict.newBuilder().rule(Rule.STALE, Outcome.ALLOW).build()
        assertEquals(listOf(), codes(allowing, seed = now - 60 * day))
        val unbounded = strict.newBuilder().rejectStaleAfterMillis(Dataset.CRLITE, null).build()
        assertEquals(listOf(), codes(unbounded, seed = now - 60 * day))
        val d = startDiagnostics(strict.form, emptySet(), now - 31 * day, now).single()
        assertEquals(Severity.WARNING, d.severity)
        assertEquals(Dataset.CRLITE, d.dataset)
    }

    @Test
    fun `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP needs NO_ISSUER rejecting and a classical OID in the probe`() {
        val fired = listOf(DiagnosticCode.UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP to Rule.NO_ISSUER)
        for (oid in CLASSICAL_OIDS) assertEquals(fired, codes(RevoktPolicy.STRICT, probe = setOf(oid)), oid)
        assertEquals(listOf(), codes(RevoktPolicy.DEFAULT, probe = CLASSICAL_OIDS.toSet()), "DEFAULT allows NO_ISSUER")
        assertEquals(listOf(), codes(RevoktPolicy.STRICT, probe = setOf("1.3.101.113", "1.3.132.0.35")))
        val message = startDiagnostics(RevoktPolicy.STRICT.form, setOf("1.3.101.112"), null, now).single().message
        assertTrue("1.3.101.112" in message, message)
    }

    @Test
    fun `RULE_FLIPPED_THIS_MINOR fires for a row flipped this minor that the policy rejects as its preset does`() {
        val table: (Preset, Rule) -> String? = { preset, rule ->
            when {
                preset == Preset.STRICT && rule == Rule.NO_SCTS -> "0.2"
                preset == Preset.STRICT && rule == Rule.NOT_ENROLLED -> "0.1"
                else -> null
            }
        }
        assertEquals(
            listOf(DiagnosticCode.RULE_FLIPPED_THIS_MINOR to Rule.NO_SCTS),
            codes(RevoktPolicy.STRICT, flipped = table),
            "an earlier minor's flip does not fire",
        )
        assertEquals(listOf(), codes(RevoktPolicy.DEFAULT, flipped = table), "another preset's row")
        val lowered =
            RevoktPolicy.STRICT
                .newBuilder()
                .rule(Rule.NO_SCTS, Outcome.ALLOW)
                .build()
        assertEquals(listOf(), codes(lowered, flipped = table), "the policy does not inherit the REJECT")
        assertEquals(listOf(), codes(RevoktPolicy.STRICT), "the shipped table has flipped nothing")
        assertEquals(listOf(), startDiagnostics(RevoktPolicy.STRICT.form, emptySet(), null, now))
    }

    @Test
    fun `the three come in spec order`() {
        val table: (Preset, Rule) -> String? = { _, rule -> if (rule == Rule.NO_SCTS) "0.2" else null }
        assertEquals(
            listOf(
                DiagnosticCode.SEED_PAST_REJECT_THRESHOLD,
                DiagnosticCode.UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP,
                DiagnosticCode.RULE_FLIPPED_THIS_MINOR,
            ),
            codes(RevoktPolicy.STRICT, setOf("1.3.101.112"), now - 31 * day, table).map { it.first },
        )
    }
}
