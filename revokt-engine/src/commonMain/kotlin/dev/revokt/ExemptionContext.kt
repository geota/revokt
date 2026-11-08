// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * What an [Exemption] is asked about (spec §4, §8 exemptions): one fired, exemptable `REJECT` rule and the facts of the
 * evaluation that fired it. An output type, growable: new evidence (M3 SCTs, M4 the distrust record) lands as new
 * nullable properties. A value with a private constructor and a `@RevoktTestingApi` builder; equality is by content.
 * The builder checks that [chain] is null exactly when [credentialType] is not `X509`.
 */
@OptIn(RevoktTestingApi::class)
public class ExemptionContext private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).
    public val rule: Rule = requireNotNull(builder.rule) { "rule is not set" }

    /** The presented chain; null for a non-X.509 credential (M5). */
    public val chain: PresentedChain? = builder.chain

    public val credentialType: CredentialType = builder.credentialType

    /** The verdict's path finding; for an empty reported path its `anchorSha256` is null. */
    public val path: Finding.Path = requireNotNull(builder.path) { "path is not set" }

    /**
     * The host as host' (§5.1 flow step 2: ASCII lowercased, one trailing dot stripped); null when the call carried
     * none, or when it was empty once normalised.
     */
    public val host: String? = builder.host

    public val nowMillis: Long = requireNotNull(builder.nowMillis) { "nowMillis is not set" }

    /** The verdict's data states: an entry for every required and every consulted dataset. */
    public val dataStates: Map<Dataset, Finding.DataState> = builder.dataStates

    init {
        require((chain == null) == (credentialType != CredentialType.X509)) {
            "chain is null exactly when credentialType is not X509 (spec §4): got credentialType=$credentialType, " +
                "chain ${if (chain == null) "null" else "set"}"
        }
    }

    /** A builder holding this context's values. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .rule(rule)
            .chain(chain)
            .credentialType(credentialType)
            .path(path)
            .primedHost(host)
            .nowMillis(nowMillis)
            .dataStates(dataStates)

    /** Every field, named, in declaration order: equality, hashing and [toString] all read this one list. */
    private fun fields(): List<Pair<String, Any?>> =
        listOf(
            "rule" to rule,
            "chain" to chain,
            "credentialType" to credentialType,
            "path" to path,
            "host" to host,
            "nowMillis" to nowMillis,
            "dataStates" to dataStates,
        )

    override fun equals(other: Any?): Boolean = other is ExemptionContext && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    override fun toString(): String =
        fields().joinToString(prefix = "ExemptionContext(", postfix = ")") { (name, value) -> "$name=$value" }

    /** Builds an [ExemptionContext] for tests and fakes; [build] checks the invariant the constructor does. */
    @RevoktTestingApi
    public class Builder {
        internal var rule: Rule? = null
            private set
        internal var chain: PresentedChain? = null
            private set
        internal var credentialType: CredentialType = CredentialType.X509
            private set
        internal var path: Finding.Path? = null
            private set
        internal var host: String? = null
            private set
        internal var nowMillis: Long? = null
            private set
        internal var dataStates: Map<Dataset, Finding.DataState> = emptyMap()
            private set

        public fun rule(rule: Rule): Builder = apply { this.rule = rule }

        public fun chain(chain: PresentedChain?): Builder = apply { this.chain = chain }

        public fun credentialType(type: CredentialType): Builder = apply { credentialType = type }

        public fun path(path: Finding.Path): Builder = apply { this.path = path }

        /** The host as the call carried it; stored as host' (an empty one as null). Pass it once, not normalised. */
        public fun host(host: String?): Builder = apply { this.host = normalisedHost(host) }

        /** A host that is already host', kept as it is: [hostPrime] strips one dot, so applying it twice would differ. */
        internal fun primedHost(host: String?): Builder = apply { this.host = host }

        public fun nowMillis(millis: Long): Builder = apply { nowMillis = millis }

        /** Replaces the data states with a read-only copy of [dataStates]. */
        public fun dataStates(dataStates: Map<Dataset, Finding.DataState>): Builder =
            apply { this.dataStates = buildMap { putAll(dataStates) } }

        public fun build(): ExemptionContext = ExemptionContext(this)
    }
}
