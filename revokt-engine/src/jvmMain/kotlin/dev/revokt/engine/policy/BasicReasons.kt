// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Rule
import java.security.cert.CertPathValidatorException.BasicReason

/**
 * The per-rule reason of the `CertPathValidatorException` a rejection carries as its cause (spec §4), total over
 * `Rule.entries`: `REVOKED` for `REVOKED` (and M2's `ONECRL`, `CRLSET`, `DENYLIST`), `UNDETERMINED_REVOCATION_STATUS`
 * for every unevaluable, non-answer and data-quality rule, so a `NO_DATA`, budget or `STRICT` rejection is never
 * triaged as a revocation. A rule added in a minor declares its reason with its row (M3 `CT` and M4 `DISTRUST`:
 * `UNSPECIFIED`).
 */
internal fun Rule.basicReason(): BasicReason =
    when (this) {
        Rule.REVOKED -> BasicReason.REVOKED

        Rule.PATH_BUDGET_EXCEEDED, Rule.NO_DATA, Rule.ENGINE_ERROR, Rule.PARSE_FAILED, Rule.ISSUER_UNVERIFIED,
        Rule.NO_ISSUER, Rule.NOT_ENROLLED, Rule.NO_SCTS, Rule.NOT_COVERED, Rule.STALE, Rule.UNSIGNED_DATA,
        -> BasicReason.UNDETERMINED_REVOCATION_STATUS
    }
