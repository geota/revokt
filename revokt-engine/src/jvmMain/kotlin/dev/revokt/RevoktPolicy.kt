// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.policy.PolicyForm
import dev.revokt.engine.policy.Preset
import dev.revokt.engine.policy.StalenessTable
import dev.revokt.engine.policy.anchorExemptable
import dev.revokt.engine.policy.validatePolicy
import java.time.Duration

/**
 * The policy (spec §4, §8): an [outcome] for every [Rule], per-rule exemptions, [requiredDatasets], a per-dataset
 * staleness map, a per-dataset `minTrustClass` floor and three time fields, stored as milliseconds with
 * `java.time.Duration` accessors. There are two presets, [DEFAULT] and [STRICT], and no from-scratch builder:
 * [newBuilder] starts from this policy's values and keeps the preset it derives from (§4 "Growability contract"), so a
 * rule added in a minor takes that preset's row. Compiles to the internal commonMain form decide and evaluate read.
 * Immutable; equality is identity, since an [Exemption] has none.
 */
public class RevoktPolicy private constructor(
    internal val form: PolicyForm,
) {
    public val requiredDatasets: Set<Dataset> = form.requiredDatasets

    public val rollbackWindowMillis: Long = form.rollbackWindowMillis

    public val clockSkewMillis: Long = form.clockSkewMillis

    public val signedSourceFailingAfterMillis: Long = form.signedSourceFailingAfterMillis

    public fun outcome(rule: Rule): Outcome = form.outcome(rule)

    /** The exemption registered for [rule], or null. */
    public fun exemption(rule: Rule): Exemption? = form.exemption(rule)

    /** [dataset]'s staleness thresholds, or null when the dataset has no entry (then `STALE` never fires for it). */
    public fun staleness(dataset: Dataset): Staleness? = form.staleness(dataset)?.let(Staleness::of)

    /** The floor below which `UNSIGNED_DATA` fires for [dataset]; the preset's floor for a dataset with no entry. */
    public fun minTrustClass(dataset: Dataset): TrustClass = form.minTrustClass(dataset)

    public fun rollbackWindow(): Duration = Duration.ofMillis(rollbackWindowMillis)

    /** Also every coverage future bound (§8). */
    public fun clockSkew(): Duration = Duration.ofMillis(clockSkewMillis)

    public fun signedSourceFailingAfter(): Duration = Duration.ofMillis(signedSourceFailingAfterMillis)

    /** A builder holding this policy's values, deriving from the same preset. */
    public fun newBuilder(): Builder = Builder(form)

    override fun toString(): String = "RevoktPolicy(preset=${form.preset}, outcomes=${form.outcomes})"

    public companion object {
        /** Rejects the evidence, the path budget and missing data (§8). */
        @JvmField public val DEFAULT: RevoktPolicy = RevoktPolicy(PolicyForm.of(Preset.DEFAULT))

        /** Rejects everything but `NOT_COVERED` (§8). */
        @JvmField public val STRICT: RevoktPolicy = RevoktPolicy(PolicyForm.of(Preset.STRICT))
    }

    /**
     * Derives a policy from a preset (spec §4). Every method returns this builder; [build] runs the §4 B checks and
     * throws `IllegalArgumentException` on the first that fails: a `rejectStaleAfter` below its `staleAfter`, and an
     * exemption on a rule that is not exemptable. Time arguments are non-negative milliseconds; Kotlin also has
     * `kotlin.time.Duration` overloads as extensions.
     */
    public class Builder internal constructor(
        from: PolicyForm,
    ) {
        private val preset = from.preset
        private val outcomes = LinkedHashMap(from.outcomes)
        private val exemptions = LinkedHashMap(from.exemptions)
        private var requiredDatasets: Set<Dataset> = from.requiredDatasets
        private val staleness = LinkedHashMap(from.staleness)
        private val minTrustClass = LinkedHashMap(from.minTrustClassEntries)
        private var rollbackWindowMillis = from.rollbackWindowMillis
        private var clockSkewMillis = from.clockSkewMillis
        private var signedSourceFailingAfterMillis = from.signedSourceFailingAfterMillis

        public fun rule(
            rule: Rule,
            outcome: Outcome,
        ): Builder = apply { outcomes[rule] = outcome }

        /** Registers [exemption] for [rule]; a second call for the same rule replaces the first. */
        public fun exempt(
            rule: Rule,
            exemption: Exemption,
        ): Builder = apply { exemptions[rule] = exemption }

        public fun clearExemption(rule: Rule): Builder = apply { exemptions.remove(rule) }

        /**
         * `exempt(rule, Exemption.anchorIn(sha256s))` for every exemptable rule that is not `EVIDENCE`, is not marked
         * "empty path" in the §8 table (`NO_ISSUER`, `ISSUER_UNVERIFIED`: use `hostSuffixIn` and `platformOnly`) and
         * whose outcome in this builder is `REJECT` now (spec §4). It applies at its call position: a later [rule] or
         * [exempt] on the same rule wins, and a rule raised to `REJECT` after the call is not covered. Each element of
         * [sha256s] is the SHA-256 of an anchor's DER as revokt reads it (§5.3); the set is copied now.
         */
        public fun exemptAnchors(sha256s: Collection<ByteArray>): Builder =
            apply {
                val anchors = Exemption.anchorIn(sha256s)
                for (rule in Rule.entries) {
                    if (rule.anchorExemptable() && outcomes.getValue(rule) == Outcome.REJECT) exemptions[rule] = anchors
                }
            }

        public fun requiredDatasets(set: Set<Dataset>): Builder = apply { requiredDatasets = buildSet { addAll(set) } }

        public fun staleness(
            dataset: Dataset,
            s: Staleness,
        ): Builder = apply { staleness[dataset] = s.toTable() }

        /** Removes [dataset]'s staleness entry; for a required dataset `validate()` warns. */
        public fun clearStaleness(dataset: Dataset): Builder = apply { staleness.remove(dataset) }

        /**
         * Sets or, with null, clears only [dataset]'s reject threshold, keeping its `staleAfter`. On a dataset with no
         * entry, a non-null [d] creates one with `staleAfter = rejectStaleAfter` and null changes nothing.
         */
        public fun rejectStaleAfter(
            dataset: Dataset,
            d: Duration?,
        ): Builder = rejectStaleAfterMillis(dataset, d?.toMillis())

        /** [rejectStaleAfter] in milliseconds. */
        public fun rejectStaleAfterMillis(
            dataset: Dataset,
            millis: Long?,
        ): Builder =
            apply {
                require(millis == null || millis >= 0) { "rejectStaleAfter is non-negative, got $millis ms" }
                val entry = staleness[dataset]
                when {
                    entry != null -> staleness[dataset] = StalenessTable(entry.staleAfterMillis, millis)
                    millis != null -> staleness[dataset] = StalenessTable(millis, millis)
                }
            }

        /** `UNSIGNED_DATA` fires for [dataset] iff its generation's `trustClass` ranks below [floor]. */
        public fun minTrustClass(
            dataset: Dataset,
            floor: TrustClass,
        ): Builder = apply { minTrustClass[dataset] = floor }

        public fun rollbackWindow(d: Duration): Builder = rollbackWindowMillis(d.toMillis())

        public fun rollbackWindowMillis(millis: Long): Builder =
            apply { rollbackWindowMillis = nonNegative("rollbackWindow", millis) }

        public fun clockSkew(d: Duration): Builder = clockSkewMillis(d.toMillis())

        public fun clockSkewMillis(millis: Long): Builder = apply { clockSkewMillis = nonNegative("clockSkew", millis) }

        public fun signedSourceFailingAfter(d: Duration): Builder = signedSourceFailingAfterMillis(d.toMillis())

        public fun signedSourceFailingAfterMillis(millis: Long): Builder =
            apply { signedSourceFailingAfterMillis = nonNegative("signedSourceFailingAfter", millis) }

        public fun build(): RevoktPolicy {
            for ((dataset, s) in staleness) {
                val reject = s.rejectStaleAfterMillis
                require(reject == null || reject >= s.staleAfterMillis) {
                    "$dataset: rejectStaleAfter ($reject ms) is below staleAfter (${s.staleAfterMillis} ms)"
                }
            }
            for (rule in exemptions.keys) {
                require(rule.exemptable) { "$rule is not exemptable, so it takes no exemption (spec §8)" }
            }
            return RevoktPolicy(
                PolicyForm(
                    preset = preset,
                    outcomes = outcomes,
                    exemptions = exemptions,
                    requiredDatasets = requiredDatasets,
                    staleness = staleness,
                    minTrustClass = minTrustClass,
                    rollbackWindowMillis = rollbackWindowMillis,
                    clockSkewMillis = clockSkewMillis,
                    signedSourceFailingAfterMillis = signedSourceFailingAfterMillis,
                ),
            )
        }

        private fun nonNegative(
            name: String,
            millis: Long,
        ): Long {
            require(millis >= 0) { "$name is non-negative, got $millis ms" }
            return millis
        }
    }
}

/** The policy's V diagnostics (spec §4) that are functions of the policy alone; see the commonMain form's. */
internal fun validatePolicy(
    policy: RevoktPolicy,
    enforcement: Enforcement,
): List<PolicyDiagnostic> = validatePolicy(policy.form, enforcement)

/** [RevoktPolicy.Builder.rejectStaleAfter] over a `kotlin.time.Duration`, in whole milliseconds. */
@JvmSynthetic
public fun RevoktPolicy.Builder.rejectStaleAfter(
    dataset: Dataset,
    d: kotlin.time.Duration?,
): RevoktPolicy.Builder = rejectStaleAfterMillis(dataset, d?.inWholeMilliseconds)

/** [RevoktPolicy.Builder.rollbackWindow] over a `kotlin.time.Duration`, in whole milliseconds. */
@JvmSynthetic
public fun RevoktPolicy.Builder.rollbackWindow(d: kotlin.time.Duration): RevoktPolicy.Builder =
    rollbackWindowMillis(d.inWholeMilliseconds)

/** [RevoktPolicy.Builder.clockSkew] over a `kotlin.time.Duration`, in whole milliseconds. */
@JvmSynthetic
public fun RevoktPolicy.Builder.clockSkew(d: kotlin.time.Duration): RevoktPolicy.Builder =
    clockSkewMillis(d.inWholeMilliseconds)

/** [RevoktPolicy.Builder.signedSourceFailingAfter] over a `kotlin.time.Duration`, in whole milliseconds. */
@JvmSynthetic
public fun RevoktPolicy.Builder.signedSourceFailingAfter(d: kotlin.time.Duration): RevoktPolicy.Builder =
    signedSourceFailingAfterMillis(d.inWholeMilliseconds)
