// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * One runtime warning (spec §4): carried on [SyncResult.warnings] and raised by the seed load. Tests and consumers
 * match on [code], never on [message]. An output type: a value with a private constructor and an internal builder.
 * Internal until the public `sync()` and `state` (0.3, #221).
 */
internal class RevoktWarning private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).
    public val code: WarningCode = requireNotNull(builder.code) { "code is not set" }

    /** The dataset the warning is about, if any. */
    public val dataset: Dataset? = builder.dataset

    /** For people; never matched on. */
    public val message: String = requireNotNull(builder.message) { "message is not set" }

    /** A builder holding this warning's values. */
    internal fun newBuilder(): Builder =
        Builder()
            .code(code)
            .dataset(dataset)
            .message(message)

    /** Every field, named, in declaration order: equality, hashing and [toString] all read this one list. */
    private fun fields(): List<Pair<String, Any?>> =
        listOf(
            "code" to code,
            "dataset" to dataset,
            "message" to message,
        )

    override fun equals(other: Any?): Boolean = other is RevoktWarning && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    override fun toString(): String =
        fields().joinToString(prefix = "RevoktWarning(", postfix = ")") { (name, value) -> "$name=$value" }

    /** Builds a [RevoktWarning] for tests and fakes. */
    internal class Builder {
        internal var code: WarningCode? = null
            private set
        internal var dataset: Dataset? = null
            private set
        internal var message: String? = null
            private set

        public fun code(code: WarningCode): Builder = apply { this.code = code }

        public fun dataset(dataset: Dataset?): Builder = apply { this.dataset = dataset }

        public fun message(message: String): Builder = apply { this.message = message }

        public fun build(): RevoktWarning = RevoktWarning(this)
    }
}
