// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * One finding about a configuration or a sync (spec §4): returned by `validate(enforcement)`, carried on the state's
 * warnings and on [SyncResult.warnings]. Tests and consumers match on [code], never on [message]. An output type: a
 * value with a private constructor and a `@RevoktTestingApi` builder.
 */
@OptIn(RevoktTestingApi::class)
public class PolicyDiagnostic private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).
    public val code: DiagnosticCode = requireNotNull(builder.code) { "code is not set" }

    public val severity: Severity = requireNotNull(builder.severity) { "severity is not set" }

    /** The rule the diagnostic is about, if any. */
    public val rule: Rule? = builder.rule

    /** The dataset the diagnostic is about, if any: for example each required dataset with no local source. */
    public val dataset: Dataset? = builder.dataset

    /** For people; never matched on. */
    public val message: String = requireNotNull(builder.message) { "message is not set" }

    /** A builder holding this diagnostic's values. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .code(code)
            .severity(severity)
            .rule(rule)
            .dataset(dataset)
            .message(message)

    /** Every field, named, in declaration order: equality, hashing and [toString] all read this one list. */
    private fun fields(): List<Pair<String, Any?>> =
        listOf(
            "code" to code,
            "severity" to severity,
            "rule" to rule,
            "dataset" to dataset,
            "message" to message,
        )

    override fun equals(other: Any?): Boolean = other is PolicyDiagnostic && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    override fun toString(): String =
        fields().joinToString(prefix = "PolicyDiagnostic(", postfix = ")") { (name, value) -> "$name=$value" }

    /** Builds a [PolicyDiagnostic] for tests and fakes. */
    @RevoktTestingApi
    public class Builder {
        internal var code: DiagnosticCode? = null
            private set
        internal var severity: Severity? = null
            private set
        internal var rule: Rule? = null
            private set
        internal var dataset: Dataset? = null
            private set
        internal var message: String? = null
            private set

        public fun code(code: DiagnosticCode): Builder = apply { this.code = code }

        public fun severity(severity: Severity): Builder = apply { this.severity = severity }

        public fun rule(rule: Rule?): Builder = apply { this.rule = rule }

        public fun dataset(dataset: Dataset?): Builder = apply { this.dataset = dataset }

        public fun message(message: String): Builder = apply { this.message = message }

        public fun build(): PolicyDiagnostic = PolicyDiagnostic(this)
    }
}
