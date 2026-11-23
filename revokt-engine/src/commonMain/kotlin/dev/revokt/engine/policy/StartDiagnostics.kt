// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.policy

import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.Outcome
import dev.revokt.PolicyDiagnostic
import dev.revokt.RevoktTestingApi
import dev.revokt.Rule
import dev.revokt.Severity

/**
 * The S diagnostics of spec §4 that read the configuration (`DiagnosticCode`s), in the order §4 lists them: each a
 * `WARNING`, which `start()` returns beside `validate()`'s. They need what only `start()` knows: [probe], the verifier's
 * startup probe, and [seedTimestampMillis], the signed `<ts>` of the seed generation `start()` installed (null when it
 * installed none, or not yet), read against [nowMillis].
 *
 * [currentMinor] and [flippedIn] are the growability table's (`PolicyTable`), as in `validatePolicy`; tests pass others
 * to reach a flipped row before any preset row has flipped.
 */
internal fun startDiagnostics(
    policy: PolicyForm,
    probe: Set<String>,
    seedTimestampMillis: Long?,
    nowMillis: Long,
    currentMinor: String = PolicyTable.CURRENT_MINOR,
    flippedIn: (Preset, Rule) -> String? = PolicyTable::flippedIn,
): List<PolicyDiagnostic> =
    seedPastRejectThreshold(policy, seedTimestampMillis, nowMillis) +
        unverifiedRejectsWithClassicalGap(policy, probe) +
        ruleFlippedThisMinor(policy) { rule -> flippedIn(policy.preset, rule) == currentMinor }

/**
 * `STALE` rejects and the seed is already older than its dataset's `rejectStaleAfter` (spec §4): once the §8 gate opens,
 * every handshake rejects until a sync succeeds. The seed is a `CRLITE` generation.
 */
internal fun seedPastRejectThreshold(
    policy: PolicyForm,
    seedTimestampMillis: Long?,
    nowMillis: Long,
): List<PolicyDiagnostic> {
    val threshold = policy.staleness(Dataset.CRLITE)?.rejectStaleAfterMillis
    return if (policy.outcome(Rule.STALE) == Outcome.REJECT &&
        seedTimestampMillis != null &&
        threshold != null &&
        nowMillis - seedTimestampMillis > threshold
    ) {
        listOf(
            diagnostic(
                DiagnosticCode.SEED_PAST_REJECT_THRESHOLD,
                Rule.STALE,
                Dataset.CRLITE,
                "STALE rejects and the seed is already older than CRLITE's rejectStaleAfter, so every handshake is " +
                    "rejected once the first sync attempt completes, until a sync succeeds",
            ),
        )
    } else {
        emptyList()
    }
}

/**
 * `NO_ISSUER` rejects and the verifier's startup probe cannot verify a classical algorithm, key or curve (spec §4): the
 * WebPKI's common chains would be rejected as unverified.
 */
internal fun unverifiedRejectsWithClassicalGap(
    policy: PolicyForm,
    probe: Set<String>,
): List<PolicyDiagnostic> {
    val gap = CLASSICAL_OIDS.filter { it in probe }
    return if (policy.outcome(Rule.NO_ISSUER) == Outcome.REJECT && gap.isNotEmpty()) {
        listOf(
            diagnostic(
                DiagnosticCode.UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP,
                Rule.NO_ISSUER,
                null,
                "NO_ISSUER rejects and the signature verifier cannot verify $gap, so chains that use them are " +
                    "rejected: use a verifier that supports them",
            ),
        )
    } else {
        emptyList()
    }
}

/**
 * Each rule whose preset row flipped `ALLOW → REJECT` in the current minor ([flipped]) and that the policy rejects as
 * its preset does (spec §4 "by inheritance"), in `Rule.PRECEDENCE` order: a runtime signal that this build enforces a
 * newly flipped rule. `PolicyForm` does not record whether a row was set, and an explicit `REJECT` equal to the
 * preset's enforces the flipped rule all the same.
 */
internal fun ruleFlippedThisMinor(
    policy: PolicyForm,
    flipped: (Rule) -> Boolean,
): List<PolicyDiagnostic> {
    val preset = PolicyTable.preset(policy.preset)
    return Rule.PRECEDENCE
        .filter {
            flipped(it) && policy.outcome(it) == Outcome.REJECT && preset.outcome(it) == Outcome.REJECT
        }.map { rule ->
            diagnostic(
                DiagnosticCode.RULE_FLIPPED_THIS_MINOR,
                rule,
                null,
                "$rule now rejects: ${policy.preset}, which this policy derives from, flipped it from ALLOW to " +
                    "REJECT in this minor",
            )
        }
}

/**
 * The classical algorithms of spec §4 `UNVERIFIED_REJECTS_WITH_CLASSICAL_GAP`, as the startup probe names them (the
 * signature, key and curve OID tables, §3): RSA PKCS#1 with SHA-256/384/512 and `rsaEncryption`; ECDSA with
 * SHA-256/384/512, `id-ecPublicKey`, P-256 and P-384; Ed25519.
 */
internal val CLASSICAL_OIDS: List<String> =
    listOf(
        "1.2.840.113549.1.1.11",
        "1.2.840.113549.1.1.12",
        "1.2.840.113549.1.1.13",
        "1.2.840.113549.1.1.1",
        "1.2.840.10045.4.3.2",
        "1.2.840.10045.4.3.3",
        "1.2.840.10045.4.3.4",
        "1.2.840.10045.2.1",
        "1.2.840.10045.3.1.7",
        "1.3.132.0.34",
        "1.3.101.112",
    )

@OptIn(RevoktTestingApi::class)
private fun diagnostic(
    code: DiagnosticCode,
    rule: Rule?,
    dataset: Dataset?,
    message: String,
): PolicyDiagnostic =
    PolicyDiagnostic
        .Builder()
        .code(code)
        .severity(Severity.WARNING)
        .rule(rule)
        .dataset(dataset)
        .message(message)
        .build()
