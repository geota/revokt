// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What a [PolicyDiagnostic] is about (spec §4): one code per `validate()`, `start()`, sync or setter bullet. Growable:
 * a code may be added in a minor, so a `when` over codes needs an `else` branch. Persist `name`, never `ordinal`.
 * Match on the code, never on the message. Each constant names the call that emits it, as §4 does: **R** =
 * `Revokt.Builder.build()` throws, **V** = `validate(enforcement)` returns it, **S** = `start()` appends it to the
 * state's warnings, **sync** = on [SyncResult.warnings].
 */
public enum class DiagnosticCode {
    /** sync: a metered-deferred full download (§7.2), with [SyncOutcome.DEFERRED]. */
    METERED_DEFERRED,

    /** sync: a future-dated seed or changeset was installed (§6.3); the local clock is behind the signed data. */
    CLOCK_BEHIND,

    /** V: a required dataset with a local data source and no fetching source. */
    NO_FETCHING_SOURCE,

    /** sync: an over-cap built index (§3.2), an index-name collision (§6.5) or a manifest's names (§7.3). */
    INDEX_INCONSISTENT,

    /** S: the store was migrated (§6.5). */
    STORE_MIGRATED,

    /** S: the store's layout is newer than this engine's (§6.5). */
    STORE_NEWER_LAYOUT,

    /** R: `AndroidPlatformTrust` with no explicit `storage` (§3). */
    STORAGE_UNSET,

    /** V and sync: a source whose format the revocation engine does not list (§3.2). */
    FORMAT_UNSUPPORTED,

    /** V, in `STARTED`: a flip to `ENFORCE` that rejects on `NO_DATA` while a sole local source is unreadable. */
    NO_DATA_AT_FLIP,

    /** V: a CRLite source configured and `CRLITE` not a required dataset. */
    NO_REQUIRED_DATASETS,

    /** sync: the §6.5 self-check mismatched, with [SyncOutcome.FAILED]. */
    ENGINE_SELF_CHECK_FAILED,

    /** sync: the signed source's feed-host hold expired and fetches proceed (§8). */
    FEED_HOST_REVOKED,

    /** S: the fetcher trust manager's snapshot build failed. */
    FETCHER_TRUST_UNAVAILABLE,

    /** V: a `c2spMirror` configured with a seed source; the mirror is bootstrap-only (§7.3). */
    MIRROR_WITH_SEED_NEVER_INSTALLED,

    /** V: `RevoktStorage.inMemory()` with a fetching source. */
    IN_MEMORY_STORE_WITH_FETCHING_SOURCE,

    /** S: a rule whose preset row flipped in this minor rejects by inheritance. */
    RULE_FLIPPED_THIS_MINOR,

    /** V: an exemption registered on an `EVIDENCE` rule. */
    EXEMPTION_ON_EVIDENCE_RULE,

    /** V: `NO_DATA` rejects and a required dataset has no local data source. */
    NO_DATA_REJECTS_WITHOUT_LOCAL_DATA,

    /** V: `STALE` rejects and no dataset has a `rejectStaleAfter`, so the rule can never fire. */
    STALE_REJECTS_WITHOUT_THRESHOLD,

    /** S: `STALE` rejects and the seed is already past a dataset's `rejectStaleAfter`. */
    SEED_PAST_REJECT_THRESHOLD,

    /** V: an exemption on a rule whose outcome is `ALLOW`. */
    EXEMPT_ON_ALLOW,

    /** S: `ISSUER_UNVERIFIED` rejects and the verifier cannot verify a classical algorithm. */
    UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP,

    /** V: `STRICT` on `AndroidPlatformTrust` with no `NO_ISSUER` exemption (§5.2). */
    STRICT_ON_ANDROID_WITHOUT_NO_ISSUER_EXEMPTION,

    /** V: `PATH_BUDGET_EXCEEDED` allows. */
    BUDGET_ALLOWS,

    /** V: an `EVIDENCE` rule allowed where the preset the policy derives from rejects. */
    EVIDENCE_LOWERED_BELOW_PRESET,

    /** V: a `MIRROR` or `SYSTEM` source below its dataset's `minTrustClass` while `UNSIGNED_DATA` rejects (§7.3). */
    LOWER_CLASS_SOURCE_NEVER_INSTALLED,

    /** V: a required dataset's staleness entry cleared. */
    STALENESS_CLEARED_FOR_REQUIRED_DATASET,

    /** S: the seed could not be read (§6.5). */
    SEED_UNREADABLE,

    /** S: the seed's channel is not the configured one (§6.5). */
    SEED_CHANNEL_MISMATCH,

    /** S: the store could not be read (§6.5). */
    STORE_UNREADABLE,

    /** S: another process holds the store lock; the instance is read-only (§5.1). */
    STORE_LOCKED,

    /** R: a CRLite source, a seed included, with no `channel`. */
    CHANNEL_UNSET,

    /** R: an Android runtime with a `platformTrust` that is not `AndroidPlatformTrust`. */
    PLATFORM_TRUST_MISMATCH,

    /** sync: a body, record count or manifest above half its `RevoktLimits` constant, or over the cap (§5.1). */
    CAP_NEAR_LIMIT,

    /** sync: a `FAILED`, `STORE_FAILED` or `CLOCK_SKEW` sync, with the cause. */
    SYNC_FAILED,

    /** sync: a verified changeset whose records fail the collection schema. */
    SYNC_SCHEMA_REJECTED,

    /**
     * S and sync: a `MIRROR` or `SYSTEM` generation with no filters or no coverage was refused (§7.3), naming the
     * source; `NO_DATA` keeps firing. A mirror's sync is [SyncOutcome.FAILED] at stage `INDEX`.
     */
    SOURCE_EMPTY,
}
