// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)
// The tests set the dispatcher under test explicitly; that is the injection.
@file:Suppress("InjectDispatcher")

package dev.revokt.jsse

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.Enforcement
import dev.revokt.FilterFormat
import dev.revokt.Outcome
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktPolicy
import dev.revokt.Rule
import dev.revokt.SeedSource
import dev.revokt.Severity
import kotlinx.coroutines.Dispatchers
import java.util.concurrent.Executor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * `Revokt.validate(enforcement)` (spec §4): each configuration-dependent V code fires in exactly its case, with its
 * severity under every enforcement, in §4's order around the policy's own diagnostics.
 */
class RevoktValidateTest {
    private data class Seen(
        val code: DiagnosticCode,
        val severity: Severity,
        val dataset: Dataset? = null,
    )

    private fun Revokt.Builder.seen(enforcement: Enforcement): List<Seen> =
        build().validate(enforcement).map { Seen(it.code, it.severity, it.dataset) }

    /** A builder whose own configuration fires nothing: a seed and a fetching source. */
    private fun quiet(): Revokt.Builder = bare().seed(SOME_SEED)

    private val inMemory = Seen(DiagnosticCode.IN_MEMORY_STORE_WITH_FETCHING_SOURCE, Severity.WARNING)

    @Test
    fun `both presets with a seed and Mozilla's source give no ERROR and only the in-memory store warning`() {
        for (policy in listOf(RevoktPolicy.DEFAULT, RevoktPolicy.STRICT)) {
            for (enforcement in Enforcement.entries) {
                val builder = quiet().remoteSettings(remoteSettings()).policy(policy)
                assertEquals(listOf(inMemory), builder.seen(enforcement), "$policy $enforcement")
            }
        }
    }

    @Test
    fun `a seed and no fetching source warn NO_FETCHING_SOURCE only, under every enforcement`() {
        for (enforcement in Enforcement.entries) {
            assertEquals(
                listOf(Seen(DiagnosticCode.NO_FETCHING_SOURCE, Severity.WARNING, Dataset.CRLITE)),
                quiet().seen(enforcement),
                "$enforcement",
            )
        }
    }

    @Test
    fun `NO_DATA rejecting with no local data is an ERROR under ENFORCE only`() {
        val builder = bare().remoteSettings(remoteSettings())
        val expected = { s: Severity ->
            listOf(Seen(DiagnosticCode.NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, s, Dataset.CRLITE), inMemory)
        }
        assertEquals(expected(Severity.ERROR), builder.seen(Enforcement.ENFORCE))
        assertEquals(expected(Severity.WARNING), builder.seen(Enforcement.OBSERVE))
        assertEquals(expected(Severity.WARNING), builder.seen(Enforcement.OFF))
    }

    @Test
    fun `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA fires with no seed, a bundled one absent from the class path included`() {
        val e = Seen(DiagnosticCode.NO_DATA_REJECTS_WITHOUT_LOCAL_DATA, Severity.ERROR, Dataset.CRLITE)
        assertEquals(listOf(e), bare().seen(Enforcement.ENFORCE))
        assertEquals(listOf(e), Revokt.builder().channel(CrliteChannel.COMPAT).seen(Enforcement.ENFORCE))
        withContextResources(setOf("revokt/seed-compat.zip")) {
            assertEquals(
                listOf(Seen(DiagnosticCode.NO_FETCHING_SOURCE, Severity.WARNING, Dataset.CRLITE)),
                Revokt.builder().channel(CrliteChannel.COMPAT).seen(Enforcement.ENFORCE),
            )
        }
    }

    @Test
    fun `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA does not fire when NO_DATA allows or nothing is required`() {
        val allows =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.NO_DATA, Outcome.ALLOW)
                .build()
        assertEquals(emptyList(), bare().policy(allows).seen(Enforcement.ENFORCE))
        val nothingRequired =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .requiredDatasets(emptySet())
                .build()
        assertEquals(emptyList(), bare().policy(nothingRequired).seen(Enforcement.ENFORCE))
    }

    @Test
    fun `a CRLite source without CRLITE required warns NO_REQUIRED_DATASETS`() {
        val nothingRequired =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .requiredDatasets(emptySet())
                .build()
        val warning = Seen(DiagnosticCode.NO_REQUIRED_DATASETS, Severity.WARNING, Dataset.CRLITE)
        for (enforcement in Enforcement.entries) {
            assertEquals(listOf(warning), quiet().policy(nothingRequired).seen(enforcement), "seed, $enforcement")
            assertEquals(
                listOf(warning, inMemory),
                bare().remoteSettings(remoteSettings()).policy(nothingRequired).seen(enforcement),
                "fetching source, $enforcement",
            )
        }
        // No CRLite source at all: nothing to lose.
        assertEquals(
            emptyList(),
            Revokt
                .builder()
                .seed(SeedSource.none())
                .policy(nothingRequired)
                .seen(Enforcement.ENFORCE),
        )
    }

    @Test
    fun `an engine that cannot read v3 with Mozilla's source is FORMAT_UNSUPPORTED, an ERROR under ENFORCE only`() {
        val builder = { quiet().remoteSettings(remoteSettings()).revocationEngine(StubEngine(setOf(FilterFormat.V4))) }
        val expected = { s: Severity -> listOf(inMemory, Seen(DiagnosticCode.FORMAT_UNSUPPORTED, s, Dataset.CRLITE)) }
        assertEquals(expected(Severity.ERROR), builder().seen(Enforcement.ENFORCE))
        assertEquals(expected(Severity.WARNING), builder().seen(Enforcement.OBSERVE))
        assertEquals(expected(Severity.WARNING), builder().seen(Enforcement.OFF))
    }

    @Test
    fun `FORMAT_UNSUPPORTED needs a remote settings source and an engine without v3`() {
        assertEquals(
            listOf(Seen(DiagnosticCode.NO_FETCHING_SOURCE, Severity.WARNING, Dataset.CRLITE)),
            quiet().revocationEngine(StubEngine(setOf(FilterFormat.V4))).seen(Enforcement.ENFORCE),
        )
        assertEquals(
            listOf(inMemory),
            quiet()
                .remoteSettings(
                    remoteSettings(),
                ).revocationEngine(StubEngine(setOf(FilterFormat.V3)))
                .seen(Enforcement.ENFORCE),
        )
    }

    @Test
    fun `IO_DISPATCHER_UNCONFINED fires for exactly Dispatchers Unconfined`() {
        val warning = Seen(DiagnosticCode.IO_DISPATCHER_UNCONFINED, Severity.WARNING)
        for (enforcement in Enforcement.entries) {
            assertEquals(
                listOf(inMemory, warning),
                quiet()
                    .remoteSettings(
                        remoteSettings(),
                    ).apply { ioDispatcher = Dispatchers.Unconfined }
                    .seen(enforcement),
            )
        }
        assertEquals(
            listOf(inMemory),
            quiet()
                .remoteSettings(remoteSettings())
                .apply {
                    ioDispatcher =
                        Dispatchers.Default
                }.seen(Enforcement.ENFORCE),
        )
        // Other inline executors are §4's sentence only.
        assertEquals(
            listOf(inMemory),
            quiet()
                .remoteSettings(remoteSettings())
                .ioExecutor(
                    Executor {
                        it.run()
                    },
                ).seen(Enforcement.ENFORCE),
        )
    }

    @Test
    fun `the configuration's codes come first in spec section 4's order, then the policy's, then the dispatcher's`() {
        val policy =
            RevoktPolicy.DEFAULT
                .newBuilder()
                .rule(Rule.PATH_BUDGET_EXCEEDED, Outcome.ALLOW)
                .build()
        val builder =
            bare()
                .remoteSettings(remoteSettings())
                .policy(policy)
                .revocationEngine(StubEngine(setOf(FilterFormat.V4)))
                .apply { ioDispatcher = Dispatchers.Unconfined }
        assertEquals(
            listOf(
                DiagnosticCode.NO_DATA_REJECTS_WITHOUT_LOCAL_DATA,
                DiagnosticCode.IN_MEMORY_STORE_WITH_FETCHING_SOURCE,
                DiagnosticCode.FORMAT_UNSUPPORTED,
                DiagnosticCode.BUDGET_ALLOWS,
                DiagnosticCode.IO_DISPATCHER_UNCONFINED,
            ),
            builder.seen(Enforcement.ENFORCE).map { it.code },
        )
    }

    @Test
    fun `validateOrThrow throws on an ERROR and names it, and returns on WARNINGs`() {
        val revokt = bare().build()
        val e = assertFailsWith<IllegalStateException> { revokt.validateOrThrow(Enforcement.ENFORCE) }
        assertTrue("NO_DATA_REJECTS_WITHOUT_LOCAL_DATA" in e.message.orEmpty(), e.message)
        revokt.validateOrThrow(Enforcement.OBSERVE)
        revokt.validateOrThrow(Enforcement.OFF)
        quiet().build().validateOrThrow(Enforcement.ENFORCE)
    }

    @Test
    fun `no diagnostic is an ERROR under OFF`() {
        val worst =
            bare()
                .remoteSettings(remoteSettings())
                .revocationEngine(StubEngine(setOf(FilterFormat.V4)))
                .policy(
                    RevoktPolicy.STRICT
                        .newBuilder()
                        .rule(Rule.REVOKED, Outcome.ALLOW)
                        .build(),
                ).build()
        assertTrue(worst.validate(Enforcement.ENFORCE).any { it.severity == Severity.ERROR })
        val off: List<PolicyDiagnostic> = worst.validate(Enforcement.OFF)
        assertTrue(off.isNotEmpty() && off.all { it.severity == Severity.WARNING }, "$off")
    }
}
