// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The growability contract's rules (#73) against the committed fixture, one change at a time. */
class RuleGrowabilityTest {
    /** The committed fixture, read from the root project (the test's working directory is build-logic/convention). */
    private val committed = File("../../$RULE_FIXTURE").readText()

    private fun problems(head: String, minor: String = "0.1", base: String = committed) = RuleGrowability.problems(base, head, minor)

    /** [committed] with one rule row's cells replaced, by column name. */
    private fun withRule(text: String, rule: String, vararg cells: Pair<String, String>): String {
        val lines = text.lines()
        val header = lines.dropWhile { it != "[rules]" }[1].split("\t")
        return lines.joinToString("\n") { line ->
            val row = line.split("\t")
            if (row.size == header.size && row[0] == rule) {
                val values = header.zip(row).toMap().toMutableMap().apply { putAll(cells) }
                header.joinToString("\t") { values.getValue(it) }
            } else {
                line
            }
        }
    }

    private fun addAfter(text: String, anchorRow: String, row: String) =
        text.lines().joinToString("\n") { if (it.startsWith("$anchorRow\t")) "$it\n$row" else it }

    private fun assertOne(found: List<String>, vararg fragments: String) {
        assertEquals(1, found.size, "expected one problem, got $found")
        for (f in fragments) assertTrue(f in found.single(), "'$f' not in ${found.single()}")
    }

    @Test
    fun `an unchanged fixture is allowed`() {
        assertEquals(emptyList(), problems(committed))
    }

    @Test
    fun `a new rule with ALLOW, introduced in the current minor and appended to its class group, is allowed`() {
        val head = addAfter(committed, "NOT_COVERED", "NEW_ANSWER\tNON_ANSWER\tCRLITE\ttrue\tfalse\tUNDETERMINED_REVOCATION_STATUS\t0.2\t-\t-\tALLOW\tALLOW")
        assertEquals(emptyList(), problems(head, minor = "0.2"))
    }

    @Test
    fun `a new rule that rejects, or carries an old introducedIn or a flippedIn, is rejected by name`() {
        val rejecting = addAfter(committed, "NOT_COVERED", "NEW_ANSWER\tNON_ANSWER\tCRLITE\ttrue\tfalse\tUNDETERMINED_REVOCATION_STATUS\t0.2\t-\t-\tALLOW\tREJECT")
        assertOne(problems(rejecting, minor = "0.2"), "new rule NEW_ANSWER", "STRICT is REJECT")
        val old = addAfter(committed, "NOT_COVERED", "NEW_ANSWER\tNON_ANSWER\tCRLITE\ttrue\tfalse\tUNDETERMINED_REVOCATION_STATUS\t0.1\t-\t-\tALLOW\tALLOW")
        assertOne(problems(old, minor = "0.2"), "new rule NEW_ANSWER", "introducedIn is 0.1")
        val flipped = addAfter(committed, "NOT_COVERED", "NEW_ANSWER\tNON_ANSWER\tCRLITE\ttrue\tfalse\tUNDETERMINED_REVOCATION_STATUS\t0.2\t0.2\t-\tALLOW\tALLOW")
        assertOne(problems(flipped, minor = "0.2"), "new rule NEW_ANSWER", "flippedIn.DEFAULT")
    }

    @Test
    fun `M2's evidence rules may ship REJECT in both presets from 0_4, and only as evidence rejecting in both`() {
        val onecrl = addAfter(committed, "REVOKED", "ONECRL\tEVIDENCE\tONECRL\ttrue\tfalse\tREVOKED\t0.4\t-\t-\tREJECT\tREJECT")
        assertEquals(emptyList(), problems(onecrl, minor = "0.4"))
        val early = onecrl.replace("\t0.4\t", "\t0.3\t")
        assertEquals(2, problems(early, minor = "0.3").count { "new rule ONECRL" in it && "ALLOW" in it })
        val notEvidence = addAfter(committed, "NOT_COVERED", "ONECRL\tNON_ANSWER\tONECRL\ttrue\tfalse\tREVOKED\t0.4\t-\t-\tREJECT\tREJECT")
        assertTrue(problems(notEvidence, minor = "0.4").any { "new rule ONECRL: DEFAULT is REJECT" in it })
        val mixed = addAfter(committed, "REVOKED", "DENYLIST\tEVIDENCE\tDENYLIST\tfalse\tfalse\tREVOKED\t0.4\t-\t-\tALLOW\tREJECT")
        assertOne(problems(mixed, minor = "0.4"), "new rule DENYLIST: STRICT is REJECT")
    }

    @Test
    fun `a new rule inserted inside its class group, not at its end, is rejected by name`() {
        val head = addAfter(committed, "NOT_ENROLLED", "NEW_ANSWER\tNON_ANSWER\tCRLITE\ttrue\tfalse\tUNDETERMINED_REVOCATION_STATUS\t0.2\t-\t-\tALLOW\tALLOW")
        assertOne(problems(head, minor = "0.2"), "new rule NEW_ANSWER", "before NO_SCTS", "append it after the last NON_ANSWER rule")
    }

    @Test
    fun `nothing is frozen across a major`() {
        val removed = committed.lines().filterNot { it.startsWith("STALE\t") }.joinToString("\n")
        assertEquals(emptyList(), problems(removed, minor = "1.0"))
    }

    @Test
    fun `the one-minor ALLOW to REJECT flip is allowed once, setting flippedIn, in the minor after the rule's introduction`() {
        // A rule introduced in 0.1 with ALLOW in STRICT (made so in the base), flipped in 0.2.
        val base = withRule(committed, "NO_SCTS", "STRICT" to "ALLOW")
        val flipped = withRule(base, "NO_SCTS", "STRICT" to "REJECT", "flippedIn.STRICT" to "0.2")
        assertEquals(emptyList(), problems(flipped, minor = "0.2", base = base))
    }

    @Test
    fun `a flip without flippedIn, in the wrong minor, or a second time, is rejected`() {
        val base = withRule(committed, "NO_SCTS", "STRICT" to "ALLOW")
        val unmarked = withRule(base, "NO_SCTS", "STRICT" to "REJECT")
        assertOne(problems(unmarked, minor = "0.2", base = base), "rule NO_SCTS", "flippedIn.STRICT must record it: set it to 0.2")
        val late = withRule(base, "NO_SCTS", "STRICT" to "REJECT", "flippedIn.STRICT" to "0.3")
        assertOne(problems(late, minor = "0.3", base = base), "rule NO_SCTS", "introduced in 0.1")
        // Already flipped once (in the base), then back to ALLOW and flipped again.
        val once = withRule(committed, "NO_SCTS", "STRICT" to "ALLOW", "flippedIn.STRICT" to "0.2")
        val again = withRule(once, "NO_SCTS", "STRICT" to "REJECT")
        assertOne(problems(again, minor = "0.2", base = once), "rule NO_SCTS", "flips at most once")
    }

    @Test
    fun `REJECT to ALLOW, and a changed flippedIn without a flip, are rejected`() {
        assertOne(problems(withRule(committed, "REVOKED", "DEFAULT" to "ALLOW")), "rule REVOKED", "DEFAULT changed from REJECT to ALLOW")
        assertOne(problems(withRule(committed, "STALE", "flippedIn.DEFAULT" to "0.1")), "rule STALE", "without a flip")
    }

    @Test
    fun `exemptable may turn true, and never false`() {
        assertEquals(emptyList(), problems(withRule(committed, "ENGINE_ERROR", "exemptable" to "true")))
        assertOne(problems(withRule(committed, "NO_DATA", "exemptable" to "false")), "rule NO_DATA", "exemptable changed from true to false")
    }

    @Test
    fun `the frozen columns are frozen, each failure naming the rule and the column`() {
        val changes =
            mapOf(
                "class" to "NON_ANSWER",
                "layer" to "CRLITE",
                "emptyPath" to "true",
                "basicReason" to "UNSPECIFIED",
                "introducedIn" to "0.0",
            )
        for ((column, value) in changes) {
            assertOne(problems(withRule(committed, "PARSE_FAILED", column to value)), "rule PARSE_FAILED", column)
        }
    }

    @Test
    fun `a removed or reordered rule is rejected`() {
        val removed = committed.lines().filterNot { it.startsWith("NOT_COVERED\t") }.joinToString("\n")
        assertOne(problems(removed), "rule NOT_COVERED was removed")
        val lines = committed.lines().toMutableList()
        val a = lines.indexOfFirst { it.startsWith("NOT_ENROLLED\t") }
        val b = lines.indexOfFirst { it.startsWith("NO_SCTS\t") }
        lines[a] = lines[b].also { lines[b] = lines[a] }
        assertOne(problems(lines.joinToString("\n")), "reordered", "NO_SCTS now stands where NOT_ENROLLED stood")
    }

    @Test
    fun `preset rows are frozen, and a new dataset's rows are allowed only outside the staleness map`() {
        assertOne(problems(committed.replace("DEFAULT\tCRLITE\t86400000", "DEFAULT\tCRLITE\t43200000")), "[presets] row DEFAULT", "rollbackWindowMillis")
        assertOne(problems(committed.replace("STRICT\tCRLITE\t259200000\t2592000000\tSIGNED", "STRICT\tCRLITE\t259200000\t2592000000\tMIRROR")), "row STRICT/CRLITE", "minTrustClass")
        val outside = "$committed\nDEFAULT\tONECRL\t-\t-\tBUNDLED\nSTRICT\tONECRL\t-\t-\tSIGNED\n"
        assertEquals(emptyList(), problems(outside))
        val stale = "$committed\nSTRICT\tONECRL\t259200000\t-\tSIGNED\n"
        assertOne(problems(stale), "[datasets] row STRICT/ONECRL was added", "set both staleness columns")
    }

    @Test
    fun `a renamed or added column is rejected before anything else, naming the columns`() {
        assertOne(problems(committed.replace("\tbasicReason\t", "\treason\t")), "[rules] columns changed", "added [reason]", "removed [basicReason]")
        val added = committed.replace("signedSourceFailingAfterMillis\n", "signedSourceFailingAfterMillis\textra\n")
        assertTrue(problems(added).any { "[presets] columns changed" in it || "cells" in it })
    }

    @Test
    fun `malformed rows, duplicated rows and unknown sections are reported, not thrown`() {
        val trailingTab = committed.replace("NOT_COVERED\tNON_ANSWER", "NOT_COVERED\tNON_ANSWER\t")
        assertOne(problems(trailingTab), "remove stray tabs")
        val duplicated = committed.replace("STRICT\tCRLITE\t259200000\t2592000000\tSIGNED", "STRICT\tCRLITE\t259200000\t2592000000\tSIGNED\nSTRICT\tCRLITE\t259200000\t2592000000\tSIGNED")
        assertOne(problems(duplicated), "[datasets] has the row STRICT/CRLITE more than once")
        assertOne(problems("$committed\n[extra]\na\tb\n1\t2\n"), "unknown section [extra]")
    }

    @Test
    fun `a base without a section compares the sections it has`() {
        val noDatasets = committed.substringBefore("[datasets]")
        assertEquals(emptyList(), problems(committed, base = noDatasets))
    }

    @Test
    fun `with no base fixture, the decision is to pass when the base exists or was not required, and to fail when a required base is missing`() {
        val introduced = RuleGrowability.decide(null, committed, "0.1", "abc123", required = true, baseCommitExists = true)
        assertTrue(introduced is RuleGrowability.Outcome.Pass && "being introduced" in introduced.note!!)
        val missing = RuleGrowability.decide(null, committed, "0.1", "abc123", required = true, baseCommitExists = false)
        assertTrue(missing is RuleGrowability.Outcome.Fail && "git fetch --depth=1 origin abc123" in missing.message)
        val local = RuleGrowability.decide(null, committed, "0.1", "origin/main", required = false, baseCommitExists = false)
        assertTrue(local is RuleGrowability.Outcome.Pass && "no base commit" in local.note!!)
    }

    @Test
    fun `with a base, the decision passes a permitted diff silently and fails a forbidden one naming the fixture`() {
        assertEquals(RuleGrowability.Outcome.Pass(null), RuleGrowability.decide(committed, committed, "0.1", "abc123", required = true, baseCommitExists = true))
        val forbidden = RuleGrowability.decide(committed, withRule(committed, "REVOKED", "DEFAULT" to "ALLOW"), "0.1", "abc123", required = true, baseCommitExists = true)
        assertTrue(forbidden is RuleGrowability.Outcome.Fail && RULE_FIXTURE in forbidden.message && "rule REVOKED" in forbidden.message)
    }

    @Test
    fun `the current minor is the version's major and minor`() {
        assertEquals("0.1", RuleGrowability.minorOf("0.1.0-SNAPSHOT"))
        assertEquals("1.12", RuleGrowability.minorOf("1.12.3"))
        assertEquals("0.2", RuleGrowability.minorOf("0.2-SNAPSHOT"))
    }
}
