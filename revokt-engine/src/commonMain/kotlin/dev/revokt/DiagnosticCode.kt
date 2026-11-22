// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What a [PolicyDiagnostic] is about (spec §4): one code per configuration check that `validate(enforcement)` runs.
 * Runtime conditions are [WarningCode]s, and why a sync stopped is its [SyncFailure]. Growable: a code may be added in
 * a minor, so a `when` over codes needs an `else` branch. Persist `name`, never `ordinal`. Match on the code, never on
 * the message.
 */
public enum class DiagnosticCode {
    /** An exemption registered on an `EVIDENCE` rule. */
    EXEMPTION_ON_EVIDENCE_RULE,

    /** `STALE` rejects and no dataset has a `rejectStaleAfter`, so the rule can never fire. */
    STALE_REJECTS_WITHOUT_THRESHOLD,

    /** An exemption on a rule whose outcome is `ALLOW`. */
    EXEMPT_ON_ALLOW,

    /** `PATH_BUDGET_EXCEEDED` allows. */
    BUDGET_ALLOWS,

    /** An `EVIDENCE` rule allowed where the preset the policy derives from rejects. */
    EVIDENCE_LOWERED_BELOW_PRESET,

    /** A required dataset's staleness entry cleared. */
    STALENESS_CLEARED_FOR_REQUIRED_DATASET,

    /**
     * A CRLite source, a seed included, configured with no `channel`: `Revokt.Builder.build()` throws, naming this code
     * in its message. No [PolicyDiagnostic] carries it.
     */
    CHANNEL_UNSET,

    /** `NO_DATA` rejects, and a required dataset has no local data source (a seed): an `ERROR` under `ENFORCE`. */
    NO_DATA_REJECTS_WITHOUT_LOCAL_DATA,

    /** A CRLite source is configured, and `CRLITE` is not a required dataset, so a loss of data would be silent. */
    NO_REQUIRED_DATASETS,

    /** The in-memory store with a fetching source: a full download on every restart. */
    IN_MEMORY_STORE_WITH_FETCHING_SOURCE,

    /** A Remote Settings source, and the revocation engine does not read v3, the format Mozilla serves. */
    FORMAT_UNSUPPORTED,

    /** A required dataset with a local data source and no fetching source: it updates only when the seed does. */
    NO_FETCHING_SOURCE,

    /** `ioDispatcher` is `Dispatchers.Unconfined`, so fetches would run on the loader thread. */
    IO_DISPATCHER_UNCONFINED,
}
