// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.jsse

import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.Enforcement
import dev.revokt.FilterFormat
import dev.revokt.Outcome
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevoktInternalApi
import dev.revokt.Rule
import dev.revokt.Severity
import dev.revokt.policyDiagnostic
import dev.revokt.validatePolicy
import kotlinx.coroutines.Dispatchers

/**
 * `Revokt.validate(enforcement)` (spec §4): the configuration-dependent V diagnostics, in the order §4 lists them, then
 * the policy's own (revokt-engine's `validatePolicy`), then `IO_DISPATCHER_UNCONFINED`. A per-dataset code lists its
 * datasets in declaration order. Only `NO_DATA_REJECTS_WITHOUT_LOCAL_DATA`, `FORMAT_UNSUPPORTED` and
 * `EVIDENCE_LOWERED_BELOW_PRESET` can be an `ERROR`, and only under `ENFORCE`, so under `OFF` every one is a `WARNING`.
 */
internal fun validateConfiguration(
    config: RevoktConfig,
    enforcement: Enforcement,
): List<PolicyDiagnostic> =
    noDataRejectsWithoutLocalData(config, enforcement) +
        noRequiredDatasets(config) +
        inMemoryStoreWithFetchingSource(config) +
        formatUnsupported(config, enforcement) +
        noFetchingSource(config) +
        validatePolicy(config.policy, enforcement) +
        ioDispatcherUnconfined(config)

private fun requiredDatasets(config: RevoktConfig): List<Dataset> =
    Dataset.entries.filter { it in config.policy.requiredDatasets }

/** `ERROR` under `ENFORCE`, else `WARNING`: under `OFF` every V code is a `WARNING` (spec §4). */
private fun Enforcement.errorWhenEnforced(): Severity =
    when (this) {
        Enforcement.ENFORCE -> Severity.ERROR
        else -> Severity.WARNING
    }

/** `NO_DATA` rejects and a required dataset has no local source: every handshake rejects until a first fetch lands. */
private fun noDataRejectsWithoutLocalData(
    config: RevoktConfig,
    enforcement: Enforcement,
): List<PolicyDiagnostic> =
    if (config.policy.outcome(Rule.NO_DATA) != Outcome.REJECT) {
        emptyList()
    } else {
        requiredDatasets(config).filterNot(config::hasLocalSource).map { dataset ->
            diagnostic(
                DiagnosticCode.NO_DATA_REJECTS_WITHOUT_LOCAL_DATA,
                enforcement.errorWhenEnforced(),
                dataset,
                "NO_DATA rejects and required dataset $dataset has no local data source (a seed), so every " +
                    "handshake is rejected until data arrives: add its seed artifact, or allow NO_DATA",
            )
        }
    }

/** A CRLite source without `CRLITE` among the required datasets: a loss of data would be silent. */
private fun noRequiredDatasets(config: RevoktConfig): List<PolicyDiagnostic> =
    if (config.hasCrliteSource && Dataset.CRLITE !in config.policy.requiredDatasets) {
        listOf(
            diagnostic(
                DiagnosticCode.NO_REQUIRED_DATASETS,
                Severity.WARNING,
                Dataset.CRLITE,
                "a CRLite source is configured, but CRLITE is not a required dataset, so a loss of data would be silent",
            ),
        )
    } else {
        emptyList()
    }

/** The in-memory store with a fetching source: a full download on every restart, and no crash recovery. */
private fun inMemoryStoreWithFetchingSource(config: RevoktConfig): List<PolicyDiagnostic> =
    if (config.inMemoryStore && Dataset.entries.any(config::hasFetchingSource)) {
        listOf(
            diagnostic(
                DiagnosticCode.IN_MEMORY_STORE_WITH_FETCHING_SOURCE,
                Severity.WARNING,
                null,
                "the store is in memory and a fetching source is configured: every restart downloads the data again",
            ),
        )
    } else {
        emptyList()
    }

/** A Remote Settings source while the engine does not read v3, the format Mozilla serves (spec §3.2). */
private fun formatUnsupported(
    config: RevoktConfig,
    enforcement: Enforcement,
): List<PolicyDiagnostic> =
    if (config.remoteSettings != null && FilterFormat.V3 !in config.engineFormats) {
        listOf(
            diagnostic(
                DiagnosticCode.FORMAT_UNSUPPORTED,
                enforcement.errorWhenEnforced(),
                Dataset.CRLITE,
                "the Remote Settings source serves V3 filters, and engine ${config.engineName} reads only " +
                    "${config.engineFormats}, so every sync would fail",
            ),
        )
    } else {
        emptyList()
    }

/** A required dataset with a local source and no fetching source: it updates only through the seed re-check. */
private fun noFetchingSource(config: RevoktConfig): List<PolicyDiagnostic> =
    requiredDatasets(config)
        .filter { config.hasLocalSource(it) && !config.hasFetchingSource(it) }
        .map { dataset ->
            diagnostic(
                DiagnosticCode.NO_FETCHING_SOURCE,
                Severity.WARNING,
                dataset,
                "required dataset $dataset has a seed and no fetching source, so its data changes only when the seed " +
                    "is replaced",
            )
        }

/** `ioDispatcher` is exactly `Dispatchers.Unconfined`: fetches would run on the loader, before their timeout applies. */
@Suppress("InjectDispatcher") // Compared with the injected one, never used to dispatch.
private fun ioDispatcherUnconfined(config: RevoktConfig): List<PolicyDiagnostic> =
    if (config.ioDispatcher === Dispatchers.Unconfined) {
        listOf(
            diagnostic(
                DiagnosticCode.IO_DISPATCHER_UNCONFINED,
                Severity.WARNING,
                null,
                "ioDispatcher is Dispatchers.Unconfined, which runs each fetch on the loader thread, where the " +
                    "per-fetch timeout cannot apply; use Dispatchers.IO or a thread pool",
            ),
        )
    } else {
        emptyList()
    }

private fun diagnostic(
    code: DiagnosticCode,
    severity: Severity,
    dataset: Dataset?,
    message: String,
): PolicyDiagnostic = policyDiagnostic(code, severity, rule = null, dataset = dataset, message = message)
