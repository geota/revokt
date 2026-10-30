// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.CrliteQueryResult
import dev.revokt.ParseReason
import dev.revokt.PathStatus
import dev.revokt.Rule

/** The rule a path status fires (spec §4 "Status-to-rule mappings"), or null. */
internal fun PathStatus.firedRule(): Rule? =
    when (this) {
        PathStatus.FOUND, PathStatus.NOT_WALKED -> null
        PathStatus.NO_ISSUER -> Rule.NO_ISSUER
        PathStatus.ISSUER_UNVERIFIED -> Rule.ISSUER_UNVERIFIED
        PathStatus.PATH_BUDGET_EXCEEDED -> Rule.PATH_BUDGET_EXCEEDED
        PathStatus.PARSE_FAILED -> Rule.PARSE_FAILED
    }

/**
 * The rule an engine's answer fires (spec §4 "Status-to-rule mappings"), or null. An engine's `NO_DATA` fires nothing
 * when the dataset has no published generation, since `Rule.NO_DATA` is driven by `requiredDatasets` and step 7 does
 * not query such an engine; with a generation published it is the engine's error.
 */
internal fun CrliteQueryResult.firedRule(generationPublished: Boolean): Rule? =
    when (this) {
        CrliteQueryResult.NOT_REVOKED -> null
        CrliteQueryResult.REVOKED -> Rule.REVOKED
        CrliteQueryResult.NOT_COVERED -> Rule.NOT_COVERED
        CrliteQueryResult.NOT_ENROLLED -> Rule.NOT_ENROLLED
        CrliteQueryResult.NO_SCTS -> Rule.NO_SCTS
        CrliteQueryResult.NO_DATA -> if (generationPublished) Rule.ENGINE_ERROR else null
        CrliteQueryResult.ENGINE_ERROR -> Rule.ENGINE_ERROR
    }

/** A rule-keyed counter map zero-filled over `Rule.entries`, as `RevoktStatus` and `RevoktEvent` hold them (spec §9). */
internal fun zeroRuleCounts(): Map<Rule, Long> = Rule.entries.associateWith { 0L }

/** The `parseFailed` counters, zero-filled over `ParseReason.entries` (spec §9). */
internal fun zeroParseFailedCounts(): Map<ParseReason, Long> = ParseReason.entries.associateWith { 0L }
