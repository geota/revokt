// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The policy result of one evaluation (spec §4), independent of `Enforcement`: [Rejected] means "policy says reject",
 * and only the trust manager decides whether to throw. Closed: exactly [Accepted] and [Rejected]. Both are output types,
 * values with a private constructor and a `@RevoktTestingApi` builder; equality, hashing and `toString` are by content
 * except [elapsedNanos], a timing field. Every field is plain data: rules, findings and data states, no lambdas and no
 * platform objects, so the same facts can be handed to a policy language later (#81, #84).
 */
public sealed interface Verdict {
    /**
     * Every rule that fired, whatever its outcome, exempted rules included. Iterates in `Rule.PRECEDENCE` order
     * whatever order the rules were given in; a read-only view.
     */
    public val rules: Set<Rule>

    /** On [Rejected], the first fired, non-exempted `REJECT` rule in `Rule.PRECEDENCE`. On [Accepted], null. */
    public val rule: Rule?

    public val findings: List<Finding>

    /** How long the evaluation took. A timing field, so not part of equality, hashing or `toString`. */
    public val elapsedNanos: Long

    /** The path finding; its status is `NOT_WALKED` when the engine did not reach the walk (the catch boundary). */
    public val path: Finding.Path

    /**
     * The first `Finding.Crlite` with result `REVOKED` in `path.issuerSpkiSha256s` order; else the finding for
     * `issuerSpkiSha256s[0]`; else null.
     */
    public val crlite: Finding.Crlite?

    /** An entry for every required and every consulted dataset, on every verdict, `ENGINE_ERROR` included. */
    public val dataStates: Map<Dataset, Finding.DataState>

    // generationEpoch, the verdict-cache key (§4: @RevoktInternalApi, not stable across processes), is declared on each
    // class rather than here, because the API dump does not leave out an opt-in member of an interface.

    /** The policy accepts the chain: no fired `REJECT` rule is left once exemptions have run. */
    @OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
    public class Accepted private constructor(
        builder: Builder,
    ) : Verdict {
        override val rules: Set<Rule> = builder.rules

        override val rule: Rule? get() = null

        override val findings: List<Finding> = builder.findings

        override val elapsedNanos: Long = builder.elapsedNanos

        override val path: Finding.Path = requireNotNull(builder.path) { "path is not set" }

        override val crlite: Finding.Crlite? = builder.crlite

        override val dataStates: Map<Dataset, Finding.DataState> = builder.dataStates

        /** The generation epoch the verdict was computed under: a verdict-cache key, not stable across processes. */
        @RevoktInternalApi
        public val generationEpoch: Long = builder.generationEpoch

        /** A builder holding this verdict's values, [elapsedNanos] included. */
        @RevoktTestingApi
        public fun newBuilder(): Builder =
            Builder()
                .rules(rules)
                .findings(findings)
                .elapsedNanos(elapsedNanos)
                .path(path)
                .crlite(crlite)
                .dataStates(dataStates)
                .generationEpoch(generationEpoch)

        private fun fields(): List<Pair<String, Any?>> = fieldsOf(this, generationEpoch)

        override fun equals(other: Any?): Boolean = other is Accepted && fields() == other.fields()

        override fun hashCode(): Int = fields().hashCode()

        override fun toString(): String =
            fields().joinToString(prefix = "Accepted(", postfix = ")") { (name, value) -> "$name=$value" }

        /** Builds a [Verdict.Accepted] for tests and fakes. */
        @RevoktTestingApi
        public class Builder {
            internal var rules: Set<Rule> = emptySet()
                private set
            internal var findings: List<Finding> = emptyList()
                private set
            internal var elapsedNanos: Long = 0
                private set
            internal var path: Finding.Path? = null
                private set
            internal var crlite: Finding.Crlite? = null
                private set
            internal var dataStates: Map<Dataset, Finding.DataState> = emptyMap()
                private set

            @RevoktInternalApi
            internal var generationEpoch: Long = 0
                private set

            /** Replaces the fired rules with a read-only copy of [rules], in `Rule.PRECEDENCE` order. */
            public fun rules(rules: Set<Rule>): Builder = apply { this.rules = inPrecedence(rules) }

            /** Replaces the findings with a read-only copy of [findings]. */
            public fun findings(findings: List<Finding>): Builder =
                apply {
                    this.findings =
                        buildList { addAll(findings) }
                }

            public fun elapsedNanos(nanos: Long): Builder = apply { elapsedNanos = nanos }

            public fun path(path: Finding.Path): Builder = apply { this.path = path }

            public fun crlite(crlite: Finding.Crlite?): Builder = apply { this.crlite = crlite }

            /** Replaces the data states with a read-only copy of [dataStates]. */
            public fun dataStates(dataStates: Map<Dataset, Finding.DataState>): Builder =
                apply { this.dataStates = buildMap { putAll(dataStates) } }

            @RevoktInternalApi
            public fun generationEpoch(epoch: Long): Builder = apply { generationEpoch = epoch }

            public fun build(): Accepted = Accepted(this)
        }
    }

    /**
     * The policy rejects the chain: [rule] is the first fired, non-exempted `REJECT` rule in `Rule.PRECEDENCE`, never
     * null (Java's `getRule()` is `@NotNull` here). The builder checks that [rule] is one of [rules].
     */
    @OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
    public class Rejected private constructor(
        builder: Builder,
    ) : Verdict {
        override val rules: Set<Rule> = builder.rules

        override val rule: Rule = requireNotNull(builder.rule) { "rule is not set" }

        override val findings: List<Finding> = builder.findings

        override val elapsedNanos: Long = builder.elapsedNanos

        override val path: Finding.Path = requireNotNull(builder.path) { "path is not set" }

        override val crlite: Finding.Crlite? = builder.crlite

        override val dataStates: Map<Dataset, Finding.DataState> = builder.dataStates

        /** The generation epoch the verdict was computed under: a verdict-cache key, not stable across processes. */
        @RevoktInternalApi
        public val generationEpoch: Long = builder.generationEpoch

        init {
            require(rule in rules) { "rule is one of the fired rules (spec §4): got rule=$rule, rules=$rules" }
        }

        /** A builder holding this verdict's values, [elapsedNanos] included. */
        @RevoktTestingApi
        public fun newBuilder(): Builder =
            Builder()
                .rules(rules)
                .rule(rule)
                .findings(findings)
                .elapsedNanos(elapsedNanos)
                .path(path)
                .crlite(crlite)
                .dataStates(dataStates)
                .generationEpoch(generationEpoch)

        private fun fields(): List<Pair<String, Any?>> = fieldsOf(this, generationEpoch)

        override fun equals(other: Any?): Boolean = other is Rejected && fields() == other.fields()

        override fun hashCode(): Int = fields().hashCode()

        override fun toString(): String =
            fields().joinToString(prefix = "Rejected(", postfix = ")") { (name, value) -> "$name=$value" }

        /** Builds a [Verdict.Rejected] for tests and fakes; [build] checks the invariant the constructor does. */
        @RevoktTestingApi
        public class Builder {
            internal var rules: Set<Rule> = emptySet()
                private set
            internal var rule: Rule? = null
                private set
            internal var findings: List<Finding> = emptyList()
                private set
            internal var elapsedNanos: Long = 0
                private set
            internal var path: Finding.Path? = null
                private set
            internal var crlite: Finding.Crlite? = null
                private set
            internal var dataStates: Map<Dataset, Finding.DataState> = emptyMap()
                private set

            @RevoktInternalApi
            internal var generationEpoch: Long = 0
                private set

            /** Replaces the fired rules with a read-only copy of [rules], in `Rule.PRECEDENCE` order. */
            public fun rules(rules: Set<Rule>): Builder = apply { this.rules = inPrecedence(rules) }

            public fun rule(rule: Rule): Builder = apply { this.rule = rule }

            /** Replaces the findings with a read-only copy of [findings]. */
            public fun findings(findings: List<Finding>): Builder =
                apply {
                    this.findings =
                        buildList { addAll(findings) }
                }

            public fun elapsedNanos(nanos: Long): Builder = apply { elapsedNanos = nanos }

            public fun path(path: Finding.Path): Builder = apply { this.path = path }

            public fun crlite(crlite: Finding.Crlite?): Builder = apply { this.crlite = crlite }

            /** Replaces the data states with a read-only copy of [dataStates]. */
            public fun dataStates(dataStates: Map<Dataset, Finding.DataState>): Builder =
                apply { this.dataStates = buildMap { putAll(dataStates) } }

            @RevoktInternalApi
            public fun generationEpoch(epoch: Long): Builder = apply { generationEpoch = epoch }

            public fun build(): Rejected = Rejected(this)
        }
    }
}

/** [rules] as a read-only set that iterates in `Rule.PRECEDENCE` order. */
private fun inPrecedence(rules: Set<Rule>): Set<Rule> = buildSet { Rule.PRECEDENCE.filterTo(this) { it in rules } }

/**
 * Every field of [verdict] but `elapsedNanos`, named, in declaration order: equality, hashing and `toString` of both
 * verdicts read this one list. `elapsedNanos` is left out because it is a timing field (spec §4).
 */
private fun fieldsOf(
    verdict: Verdict,
    generationEpoch: Long,
): List<Pair<String, Any?>> =
    listOf(
        "rules" to verdict.rules,
        "rule" to verdict.rule,
        "findings" to verdict.findings,
        "path" to verdict.path,
        "crlite" to verdict.crlite,
        "dataStates" to verdict.dataStates,
        "generationEpoch" to generationEpoch,
    )
