// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The diagnostics, the runtime warnings, the sync result types and the logger as spec §3 and §4 declare them (#105):
 * the enums pinned to the spec text, value semantics and round trips, and the logger callers' swallowing.
 */
@OptIn(RevoktTestingApi::class)
class DiagnosticsTest {
    private fun diagnostic() =
        PolicyDiagnostic
            .Builder()
            .code(DiagnosticCode.STALE_REJECTS_WITHOUT_THRESHOLD)
            .severity(Severity.ERROR)
            .rule(Rule.NO_DATA)
            .dataset(Dataset.CRLITE)
            .message("no local data source for CRLITE")
            .build()

    private fun failed() =
        SyncResult
            .Builder()
            .outcome(SyncOutcome.FAILED)
            .atMillis(1_700_000_000_000)
            .installed(mapOf(Dataset.CRLITE to "1700000000000/abc"))
            .sourceId("remoteSettings")
            .failure(SyncFailure.SIGNATURE_INVALID)
            .httpStatus(200)
            .cause(IllegalStateException("bad signature"))
            .warnings(listOf(warning()))
            .build()

    private fun warning() =
        RevoktWarning
            .Builder()
            .code(WarningCode.CAP_NEAR_LIMIT)
            .dataset(Dataset.CRLITE)
            .message("the changeset is 3000000 bytes, above half of 4194304")
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
    fun `the closed enums are the spec's, in its order`() {
        assertEquals(listOf("ENFORCE", "OBSERVE", "OFF"), Enforcement.entries.map { it.name })
        assertEquals(listOf("WARNING", "ERROR"), Severity.entries.map { it.name })
        assertEquals(listOf("DEBUG", "INFO", "WARN", "ERROR"), LogLevel.entries.map { it.name })
    }

    @Test
    fun `DiagnosticCode and WarningCode entries are the spec 4 lists`() {
        // Spec §4, `enum class DiagnosticCode` and `enum class WarningCode`, in their order: each lists only the codes
        // the engine produces. Growable: a new code is appended here and there together.
        val diagnostics =
            "EXEMPTION_ON_EVIDENCE_RULE, STALE_REJECTS_WITHOUT_THRESHOLD, EXEMPT_ON_ALLOW, BUDGET_ALLOWS, " +
                "EVIDENCE_LOWERED_BELOW_PRESET, STALENESS_CLEARED_FOR_REQUIRED_DATASET, CHANNEL_UNSET, " +
                "NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, NO_REQUIRED_DATASETS, IN_MEMORY_STORE_WITH_FETCHING_SOURCE, " +
                "FORMAT_UNSUPPORTED, NO_FETCHING_SOURCE, IO_DISPATCHER_UNCONFINED, SEED_PAST_REJECT_THRESHOLD, " +
                "UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP, RULE_FLIPPED_THIS_MINOR"
        assertEquals(diagnostics.split(", "), DiagnosticCode.entries.map { it.name })
        val warnings = "CAP_NEAR_LIMIT, SEED_UNREADABLE, SEED_CHANNEL_MISMATCH"
        assertEquals(warnings.split(", "), WarningCode.entries.map { it.name })
        // Spec §4: NOT_STARTED is the unevaluated counter, never a diagnostic.
        assertTrue(DiagnosticCode.entries.none { it.name == "NOT_STARTED" })
    }

    @Test
    fun `the sync enums are the spec's, in its order`() {
        assertEquals(listOf("INSTALLED", "UNCHANGED", "SKIPPED", "FAILED"), SyncOutcome.entries.map { it.name })
        val failures =
            "BACKOFF, ROLLBACK_REFUSED, CHANGESET_FETCH, CHANGESET_MALFORMED, TOO_MANY_RECORDS, NO_SIGNATURE, " +
                "X5U_URL, X5U_FETCH, X5U_CHAIN, CLOCK_SKEW, SIGNATURE_INVALID, SCHEMA_REJECTED, INDEX_INCONSISTENT, " +
                "ATTACHMENT_BASE, ATTACHMENT_OVER_CAP, ATTACHMENT_FETCH, ATTACHMENT_MISMATCH, FILTER_UNREADABLE, " +
                "FORMAT_UNSUPPORTED, ENGINE_FAILED, STORE_FAILED, INTERNAL_ERROR"
        assertEquals(failures.split(", "), SyncFailure.entries.map { it.name })
        // Spec §4: BACKOFF and ROLLBACK_REFUSED are SKIPPED, not feed failures; every other code is FAILED.
        val skipped = setOf(SyncFailure.BACKOFF, SyncFailure.ROLLBACK_REFUSED)
        for (f in SyncFailure.entries) {
            assertEquals(if (f in skipped) SyncOutcome.SKIPPED else SyncOutcome.FAILED, f.outcome, "$f")
        }
    }

    @Test
    fun `a failure is set exactly for SKIPPED and FAILED, and is a code of that outcome`() {
        fun result(
            outcome: SyncOutcome,
            failure: SyncFailure?,
        ) = SyncResult
            .Builder()
            .outcome(outcome)
            .atMillis(5)
            .failure(failure)
            .build()
        for (outcome in listOf(SyncOutcome.INSTALLED, SyncOutcome.UNCHANGED)) {
            assertNull(result(outcome, null).failure)
            assertFailsWith<IllegalArgumentException> { result(outcome, SyncFailure.CHANGESET_FETCH) }
        }
        for (f in SyncFailure.entries) {
            assertEquals(f, result(f.outcome, f).failure)
            assertFailsWith<IllegalArgumentException> { result(f.outcome, null) }
            val other = if (f.outcome == SyncOutcome.FAILED) SyncOutcome.SKIPPED else SyncOutcome.FAILED
            assertFailsWith<IllegalArgumentException>("$f") { result(other, f) }
        }
    }

    @Test
    fun `a runtime warning built from equal inputs is equal, newBuilder round-trips, and every field counts`() {
        assertValueSemantics(warning(), warning())
        assertValueSemantics(warning(), warning().newBuilder().build())
        assertEquals(
            "RevoktWarning(code=CAP_NEAR_LIMIT, dataset=CRLITE, " +
                "message=the changeset is 3000000 bytes, above half of 4194304)",
            warning().toString(),
        )
        assertNotEquals<Any>(warning(), "warning")
        val changed =
            mapOf<String, RevoktWarning.Builder.() -> RevoktWarning.Builder>(
                "code" to { code(WarningCode.SEED_UNREADABLE) },
                "dataset" to { dataset(null) },
                "message" to { message("another message") },
            )
        for ((field, change) in changed) {
            assertNotEquals(warning(), warning().newBuilder().change().build(), field)
        }
        val bare =
            RevoktWarning
                .Builder()
                .code(WarningCode.SEED_UNREADABLE)
                .message("m")
                .build()
        assertNull(bare.dataset)
        for ((field, set) in mapOf<String, RevoktWarning.Builder.() -> RevoktWarning.Builder>(
            "code" to { message("m") },
            "message" to { code(WarningCode.SEED_UNREADABLE) },
        )) {
            val e = assertFailsWith<IllegalArgumentException> { RevoktWarning.Builder().set().build() }
            assertEquals("$field is not set", e.message)
        }
    }

    @Test
    fun `a diagnostic built from equal inputs is equal, and newBuilder round-trips`() {
        assertValueSemantics(diagnostic(), diagnostic())
        assertValueSemantics(diagnostic(), diagnostic().newBuilder().build())
        assertEquals(
            "PolicyDiagnostic(code=STALE_REJECTS_WITHOUT_THRESHOLD, severity=ERROR, rule=NO_DATA, dataset=CRLITE, " +
                "message=no local data source for CRLITE)",
            diagnostic().toString(),
        )
        assertNotEquals<Any>(diagnostic(), "diagnostic")
    }

    @Test
    fun `every diagnostic field takes part in equality`() {
        val base = diagnostic()
        val changed =
            mapOf<String, PolicyDiagnostic.Builder.() -> PolicyDiagnostic.Builder>(
                "code" to { code(DiagnosticCode.EXEMPT_ON_ALLOW) },
                "severity" to { severity(Severity.WARNING) },
                "rule" to { rule(null) },
                "dataset" to { dataset(null) },
                "message" to { message("another message") },
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
    }

    @Test
    fun `a diagnostic's required fields and its optional ones`() {
        val bare =
            PolicyDiagnostic
                .Builder()
                .code(DiagnosticCode.BUDGET_ALLOWS)
                .severity(Severity.WARNING)
                .message("m")
                .build()
        assertNull(bare.rule)
        assertNull(bare.dataset)
        val required =
            mapOf<String, PolicyDiagnostic.Builder.() -> PolicyDiagnostic.Builder>(
                "code" to { severity(Severity.WARNING).message("m") },
                "severity" to { code(DiagnosticCode.BUDGET_ALLOWS).message("m") },
                "message" to { code(DiagnosticCode.BUDGET_ALLOWS).severity(Severity.WARNING) },
            )
        for ((field, set) in required) {
            val e = assertFailsWith<IllegalArgumentException> { PolicyDiagnostic.Builder().set().build() }
            assertEquals("$field is not set", e.message)
        }
    }

    @Test
    fun `a sync result built from equal inputs is equal, and newBuilder round-trips`() {
        val result = failed()
        val again = result.newBuilder().build()
        assertValueSemantics(result, again)
        assertSame(result.cause, again.cause)
        assertValueSemantics(failed().newBuilder().cause(null).build(), failed().newBuilder().cause(null).build())
        assertNotEquals<Any>(failed(), "result")
    }

    @Test
    fun `cause is not part of a sync result's equality`() {
        // Spec §4: cause is @Transient, null after deserialisation, so a deserialised result equals the original.
        val deserialised = failed().newBuilder().cause(null).build()
        assertValueSemantics(failed(), deserialised)
        assertValueSemantics(failed(), failed().newBuilder().cause(IllegalArgumentException("other")).build())
        assertTrue("cause" !in failed().toString(), failed().toString())
    }

    @Test
    fun `every sync result field but cause takes part in equality`() {
        val base = failed()
        val changed =
            mapOf<String, SyncResult.Builder.() -> SyncResult.Builder>(
                "outcome" to { outcome(SyncOutcome.SKIPPED).failure(SyncFailure.BACKOFF) },
                "atMillis" to { atMillis(1) },
                "installed" to { installed(emptyMap()) },
                "sourceId" to { sourceId(null) },
                "failure" to { failure(SyncFailure.X5U_FETCH) },
                "httpStatus" to { httpStatus(503) },
                "warnings" to { warnings(emptyList()) },
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
    }

    @Test
    fun `toString names every sync result field`() {
        val text = failed().toString()
        val fields =
            listOf(
                "outcome",
                "atMillis",
                "installed",
                "sourceId",
                "failure",
                "httpStatus",
                "warnings",
            )
        for (field in fields) assertTrue("$field=" in text, "$field missing from $text")
        assertTrue(text.startsWith("SyncResult(outcome=FAILED, atMillis=1700000000000, installed="), text)
    }

    @Test
    fun `a sync result's defaults and its required fields`() {
        val r =
            SyncResult
                .Builder()
                .outcome(SyncOutcome.UNCHANGED)
                .atMillis(5)
                .build()
        assertEquals(emptyMap(), r.installed)
        assertEquals(emptyList(), r.warnings)
        for (field in listOf(r.sourceId, r.failure, r.httpStatus, r.cause)) assertNull(field)
        val noOutcome = assertFailsWith<IllegalArgumentException> { SyncResult.Builder().atMillis(5).build() }
        assertEquals("outcome is not set", noOutcome.message)
        val noTime =
            assertFailsWith<IllegalArgumentException> { SyncResult.Builder().outcome(SyncOutcome.UNCHANGED).build() }
        assertEquals("atMillis is not set", noTime.message)
    }

    @Test
    fun `installed and warnings are copied from the builder`() {
        val installed = mutableMapOf(Dataset.CRLITE to "g1")
        val warnings = mutableListOf(warning())
        val r =
            SyncResult
                .Builder()
                .outcome(SyncOutcome.INSTALLED)
                .atMillis(5)
                .installed(installed)
                .warnings(warnings)
                .build()
        installed.clear()
        warnings.clear()
        assertEquals(mapOf(Dataset.CRLITE to "g1"), r.installed)
        assertEquals(listOf(warning()), r.warnings)
    }

    @Test
    fun `installed and warnings are read-only`() {
        // toMap() and toList() copy two or more entries into a mutable collection. Dataset has one value in M1, so
        // installed cannot hold two entries yet; warnings holds two.
        val r =
            SyncResult
                .Builder()
                .outcome(SyncOutcome.INSTALLED)
                .atMillis(5)
                .installed(mapOf(Dataset.CRLITE to "g1"))
                .warnings(listOf(warning(), warning().newBuilder().code(WarningCode.SEED_UNREADABLE).build()))
                .build()

        @Suppress("UNCHECKED_CAST")
        val installed = r.installed as MutableMap<Dataset, String>
        assertFailsWith<UnsupportedOperationException> { installed.clear() }
        @Suppress("UNCHECKED_CAST")
        val warnings = r.warnings as MutableList<RevoktWarning>
        assertFailsWith<UnsupportedOperationException> { warnings.clear() }
    }

    @Test
    fun `safeLog passes the call through and swallows a throwing logger`() {
        val seen = mutableListOf<Triple<LogLevel, String, Throwable?>>()
        val cause = IllegalStateException("cause")
        RevoktLogger { level, message, t -> seen += Triple(level, message, t) }.run {
            safeLog(LogLevel.WARN, "with a cause", cause)
            safeLog(LogLevel.DEBUG, "without")
        }
        assertEquals(
            listOf<Triple<LogLevel, String, Throwable?>>(
                Triple(LogLevel.WARN, "with a cause", cause),
                Triple(LogLevel.DEBUG, "without", null),
            ),
            seen,
        )
        for (thrown in listOf(IllegalStateException("x"), NotImplementedError(), AssertionError("y"))) {
            RevoktLogger { _, _, _ -> throw thrown }.safeLog(LogLevel.ERROR, "swallowed")
        }
    }
}
