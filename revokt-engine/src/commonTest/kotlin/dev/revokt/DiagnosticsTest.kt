// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The diagnostics, the sync result types and the logger as spec §3 and §4 declare them (#105): the enums pinned to the
 * spec text, value semantics and round trips, and the logger callers' swallowing.
 */
@OptIn(RevoktTestingApi::class)
class DiagnosticsTest {
    private fun diagnostic() =
        PolicyDiagnostic
            .Builder()
            .code(DiagnosticCode.NO_DATA_REJECTS_WITHOUT_LOCAL_DATA)
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
            .stage(SyncStage.SIGNATURE)
            .httpStatus(200)
            .cause(IllegalStateException("bad signature"))
            .warnings(listOf(diagnostic().newBuilder().code(DiagnosticCode.SYNC_FAILED).build()))
            .build()

    private fun blocked() =
        SyncResult
            .Builder()
            .outcome(SyncOutcome.BLOCKED_BY_SELF)
            .atMillis(1_700_000_000_000)
            .sourceId("c2spMirror")
            .blockedSource("c2spMirror")
            .blockedChainSha256(ByteArray(32) { 7 })
            .blockedLeafSerial(byteArrayOf(1, 2, 3))
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
    fun `DiagnosticCode entries are the spec 4 list`() {
        // Spec §4 (revision 56), `enum class DiagnosticCode`, in its order, 0.3's codes included. Growable: a new code is
        // appended here and there together.
        val spec =
            "METERED_DEFERRED, CLOCK_BEHIND, NO_FETCHING_SOURCE, INDEX_INCONSISTENT, STORE_MIGRATED, " +
                "STORE_NEWER_LAYOUT, STORAGE_UNSET, FORMAT_UNSUPPORTED, NO_DATA_AT_FLIP, NO_REQUIRED_DATASETS, " +
                "ENGINE_SELF_CHECK_FAILED, FEED_HOST_REVOKED, FETCHER_TRUST_UNAVAILABLE, " +
                "MIRROR_WITH_SEED_NEVER_INSTALLED, IN_MEMORY_STORE_WITH_FETCHING_SOURCE, RULE_FLIPPED_THIS_MINOR, " +
                "EXEMPTION_ON_EVIDENCE_RULE, NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, STALE_REJECTS_WITHOUT_THRESHOLD, " +
                "SEED_PAST_REJECT_THRESHOLD, EXEMPT_ON_ALLOW, UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP, " +
                "STRICT_ON_ANDROID_WITHOUT_NO_ISSUER_EXEMPTION, BUDGET_ALLOWS, EVIDENCE_LOWERED_BELOW_PRESET, " +
                "LOWER_CLASS_SOURCE_NEVER_INSTALLED, STALENESS_CLEARED_FOR_REQUIRED_DATASET, SEED_UNREADABLE, " +
                "SEED_CHANNEL_MISMATCH, STORE_UNREADABLE, STORE_LOCKED, CHANNEL_UNSET, PLATFORM_TRUST_MISMATCH, " +
                "CAP_NEAR_LIMIT, SYNC_FAILED, SYNC_SCHEMA_REJECTED, SOURCE_EMPTY, IO_DISPATCHER_UNCONFINED"
        assertEquals(spec.split(", "), DiagnosticCode.entries.map { it.name })
        // Spec §4: NOT_STARTED is the unevaluated counter, never a diagnostic.
        assertTrue(DiagnosticCode.entries.none { it.name == "NOT_STARTED" })
    }

    @Test
    fun `the sync enums are the spec's, in its order`() {
        assertEquals(
            listOf(
                "INSTALLED",
                "UNCHANGED",
                "DEFERRED",
                "FAILED",
                "CLOCK_SKEW",
                "ROLLBACK_REFUSED",
                "BACKOFF",
                "STORE_FAILED",
                "STORE_LOCKED",
                "BLOCKED_BY_SELF",
            ),
            SyncOutcome.entries.map { it.name },
        )
        assertEquals(
            listOf(
                "FETCHER_TRUST",
                "CHANGESET",
                "X5U",
                "ATTACHMENT",
                "SIGNATURE",
                "SCHEMA",
                "INDEX",
                "PREPARE",
                "SELF_CHECK",
                "ACTIVATE",
                "STORE",
            ),
            SyncStage.entries.map { it.name },
        )
    }

    @Test
    fun `a diagnostic built from equal inputs is equal, and newBuilder round-trips`() {
        assertValueSemantics(diagnostic(), diagnostic())
        assertValueSemantics(diagnostic(), diagnostic().newBuilder().build())
        assertEquals(
            "PolicyDiagnostic(code=NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, severity=ERROR, rule=NO_DATA, dataset=CRLITE, " +
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
                "code" to { code(DiagnosticCode.STORE_LOCKED) },
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
        for (result in listOf(failed(), blocked())) {
            val again = result.newBuilder().build()
            assertValueSemantics(result, again)
            assertSame(result.cause, again.cause)
        }
        assertValueSemantics(blocked(), blocked())
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
                "outcome" to { outcome(SyncOutcome.STORE_FAILED) },
                "atMillis" to { atMillis(1) },
                "installed" to { installed(emptyMap()) },
                "sourceId" to { sourceId(null) },
                "stage" to { stage(SyncStage.X5U) },
                "httpStatus" to { httpStatus(503) },
                "warnings" to { warnings(emptyList()) },
            )
        for ((field, change) in changed) {
            assertNotEquals(base, base.newBuilder().change().build(), field)
        }
        val blocked = blocked()
        val changedBlocked =
            mapOf<String, SyncResult.Builder.() -> SyncResult.Builder>(
                "blockedSource" to { blockedSource("remoteSettings") },
                "blockedChainSha256" to { blockedChainSha256(ByteArray(32) { 8 }) },
                "blockedLeafSerial" to { blockedLeafSerial(null) },
            )
        for ((field, change) in changedBlocked) {
            assertNotEquals(blocked, blocked.newBuilder().change().build(), field)
        }
    }

    @Test
    fun `toString names every sync result field and prints the blocked bytes in hex`() {
        val text = blocked().toString()
        val fields =
            listOf(
                "outcome",
                "atMillis",
                "installed",
                "sourceId",
                "stage",
                "httpStatus",
                "blockedSource",
                "blockedChainSha256",
                "blockedLeafSerial",
                "warnings",
            )
        for (field in fields) assertTrue("$field=" in text, "$field missing from $text")
        assertTrue(text.startsWith("SyncResult(outcome=BLOCKED_BY_SELF, atMillis=1700000000000"), text)
        assertTrue("blockedChainSha256=${"07".repeat(32)}" in text, text)
        assertTrue("blockedLeafSerial=010203" in text, text)
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
        for (field in listOf(r.sourceId, r.stage, r.httpStatus, r.cause, r.blockedSource)) assertNull(field)
        assertNull(r.blockedChainSha256)
        assertNull(r.blockedLeafSerial)
        val noOutcome = assertFailsWith<IllegalArgumentException> { SyncResult.Builder().atMillis(5).build() }
        assertEquals("outcome is not set", noOutcome.message)
        val noTime =
            assertFailsWith<IllegalArgumentException> { SyncResult.Builder().outcome(SyncOutcome.FAILED).build() }
        assertEquals("atMillis is not set", noTime.message)
    }

    @Test
    fun `the blocked fields are set only on a BLOCKED_BY_SELF result`() {
        val outcomes = SyncOutcome.entries - SyncOutcome.BLOCKED_BY_SELF
        val each =
            listOf<SyncResult.Builder.() -> SyncResult.Builder>(
                { blockedSource("c2spMirror") },
                { blockedChainSha256(ByteArray(32)) },
                { blockedLeafSerial(byteArrayOf(1)) },
            )
        for (outcome in outcomes) {
            for (set in each) {
                val e =
                    assertFailsWith<IllegalArgumentException> {
                        SyncResult
                            .Builder()
                            .outcome(outcome)
                            .atMillis(5)
                            .set()
                            .build()
                    }
                assertTrue("set only on a BLOCKED_BY_SELF result" in e.message!!, e.message)
            }
        }
        // The fields are optional on a BLOCKED_BY_SELF result.
        assertNull(
            blocked()
                .newBuilder()
                .blockedLeafSerial(null)
                .build()
                .blockedLeafSerial,
        )
    }

    @Test
    fun `byte getters and builder inputs are copies`() {
        val chain = ByteArray(32) { 9 }
        val r = blocked().newBuilder().blockedChainSha256(chain).build()
        chain[0] = 0
        assertContentEquals(ByteArray(32) { 9 }, r.blockedChainSha256)
        assertNotSame(r.blockedChainSha256, r.blockedChainSha256)
        r.blockedLeafSerial!![0] = 42
        assertContentEquals(byteArrayOf(1, 2, 3), r.blockedLeafSerial)
    }

    @Test
    fun `installed and warnings are copied from the builder`() {
        val installed = mutableMapOf(Dataset.CRLITE to "g1")
        val warnings = mutableListOf(diagnostic())
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
        assertEquals(listOf(diagnostic()), r.warnings)
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
                .warnings(listOf(diagnostic(), diagnostic().newBuilder().code(DiagnosticCode.CAP_NEAR_LIMIT).build()))
                .build()

        @Suppress("UNCHECKED_CAST")
        val installed = r.installed as MutableMap<Dataset, String>
        assertFailsWith<UnsupportedOperationException> { installed.clear() }
        @Suppress("UNCHECKED_CAST")
        val warnings = r.warnings as MutableList<PolicyDiagnostic>
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
