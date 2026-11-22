// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.fetch.AllowedDomains
import dev.revokt.engine.fetch.X5uUrl
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import kotlin.jvm.JvmField

/**
 * One Mozilla Remote Settings source (spec §4, §7.1): where the changesets, attachments and x5u chains come from, and the
 * pinned roots the x5u chain must end in. §7.1's per-source values live here, each overridable: the base URLs, the bucket
 * and collections, the allowed domains and the x5u host rewrites, the pinned root set, the `User-Agent` and the source
 * id. The protocol's fixed rules and the `RevoktLimits` caps do not. [DEFAULT] is Mozilla's production service.
 *
 * A private mirror that serves the three Mozilla hosts' bytes unchanged is configured with [Builder.baseUrl],
 * [Builder.attachmentBaseUrl], [Builder.allowedDomains] holding the mirror host and
 * `x5uHostRewrite("content-signature-2.cdn.mozilla.net", mirrorHost)`, and verifies and installs as `SIGNED` under the
 * default [sourceId]. The https and no-userinfo rule on every URL here is checked when the `Revokt` is built, and the
 * x5u port rule when an x5u URL is fetched; this type checks only the allowed domains and the rewrites ([Builder]). A
 * value type: equality is by content, and `ByteArray` getters return fresh copies.
 */
public class MozillaRemoteSettings private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).

    /**
     * The Kinto API base: default `…/v1`; `…/v2` is the documented alternative (spec §7.1). The client joins it to each
     * path with exactly one `/`, so a trailing `/` here makes no difference.
     */
    public val baseUrl: String = builder.baseUrl

    /** The bucket every collection lives in: default `security-state`. */
    public val bucket: String = builder.bucket

    private val collections: Map<Dataset, String> = buildMap { putAll(builder.collections) }

    /**
     * The base every relative `attachment.location` is resolved against, when set: pinned, for a private mirror. Null,
     * the default, reads the server root's `capabilities.attachments.base_url` (`GET <baseUrl>/`) once per sync, before
     * the first attachment it fetches, as Firefox does; that value must be an `https` URL whose host [allowedDomains]
     * allows, or the sync is `FAILED` with `ATTACHMENT_BASE` (spec §7.1). The client joins the base to the location
     * with exactly one `/`, as for [baseUrl].
     */
    public val attachmentBaseUrl: String? = builder.attachmentBaseUrl

    /**
     * The domains an x5u host (after [x5uHostRewrites]) and the server's attachment base URL host must be under: a host
     * is allowed when it equals an entry or ends with `.` and an entry, so `cdn.mozilla.net` allows
     * `content-signature-2.cdn.mozilla.net` but not `evilcdn.mozilla.net`. Default `cdn.mozilla.net`, Mozilla's CDN. Each
     * is a DNS host name ([Builder]). Hosts are compared exactly, ASCII case included, so an entry should be lowercase
     * as Mozilla's are. The server root response is unsigned: this rule is what keeps a compromised settings host from
     * pointing clients at arbitrary hosts.
     */
    public val allowedDomains: Set<String> = buildSet { addAll(builder.allowedDomains) }

    /**
     * The x5u host rewrites, from a host to the one fetched instead: applied once to the parsed x5u URI host before the
     * [allowedDomains] check. Every target is allowed by [allowedDomains], and both sides are DNS host names
     * ([Builder]). Default none. Hosts are compared exactly, ASCII case included. The client still re-parses the
     * rewritten URI, re-applies the scheme, userinfo and port rules to it, and requires its parsed host to equal the
     * target (spec §7.1).
     */
    public val x5uHostRewrites: Map<String, String> = buildMap { putAll(builder.x5uHostRewrites) }

    private val pins: Set<ByteString> = buildSet { addAll(builder.pinnedRootSpkiSha256s) }

    /** The `User-Agent` sent with every request. */
    public val userAgent: String = builder.userAgent

    /** The source's name: its `updater.json` key and `SyncResult.sourceId`. Default `mozilla-remote-settings`. */
    public val sourceId: String = builder.sourceId

    init {
        for (domain in allowedDomains) {
            requireBareHost("allowedDomains entry", domain)
            require('.' in domain) {
                "allowedDomains entry \"$domain\" is a single label, which would allow a whole top-level domain " +
                    "(spec §4, §7.1)"
            }
        }
        for ((from, to) in x5uHostRewrites) {
            requireBareHost("x5uHostRewrite from", from)
            requireBareHost("x5uHostRewrite to", to)
            require(AllowedDomains.allows(to, allowedDomains)) {
                "x5uHostRewrite(\"$from\", \"$to\"): \"$to\" is not under allowedDomains $allowedDomains; " +
                    "add it with allowedDomains(…) (spec §4, §7.1)"
            }
        }
    }

    private fun requireBareHost(
        what: String,
        host: String,
    ) {
        require(X5uUrl.isHostName(host)) {
            "$what \"$host\" is not a DNS host name: LDH labels of 1 to 63 characters separated by single dots, at " +
                "most 253 characters, no trailing dot, and a last label that is not a number (spec §4, §7.1)"
        }
    }

    /** The collection [dataset] is fetched from (default `cert-revocations` for [Dataset.CRLITE]), or null when none. */
    public fun collection(dataset: Dataset): String? = collections[dataset]

    /** The SPKI SHA-256 hashes the x5u chain's terminal must match, compared by content; fresh copies, in order set. */
    public val pinnedRootSpkiSha256s: List<ByteArray> get() = pins.map { it.toByteArray() }

    internal val pinnedRootSpkis: Set<ByteString> get() = pins

    /** A builder holding this source's values. */
    public fun newBuilder(): Builder {
        val builder =
            Builder()
                .baseUrl(baseUrl)
                .bucket(bucket)
                .attachmentBaseUrl(attachmentBaseUrl)
                .allowedDomains(allowedDomains)
                .pinnedRootSpkiSha256s(pinnedRootSpkiSha256s)
                .userAgent(userAgent)
                .sourceId(sourceId)
        for ((dataset, name) in collections) builder.collection(dataset, name)
        for ((from, to) in x5uHostRewrites) builder.x5uHostRewrite(from, to)
        return builder
    }

    override fun equals(other: Any?): Boolean = other is MozillaRemoteSettings && fields() == other.fields()

    override fun hashCode(): Int = fields().hashCode()

    override fun toString(): String =
        "MozillaRemoteSettings(baseUrl=$baseUrl, bucket=$bucket, collections=$collections, " +
            "attachmentBaseUrl=$attachmentBaseUrl, allowedDomains=$allowedDomains, x5uHostRewrites=$x5uHostRewrites, " +
            "pinnedRootSpkiSha256s=${pins.map { it.hex() }}, userAgent=$userAgent, sourceId=$sourceId)"

    private fun fields(): List<Any?> =
        listOf(
            baseUrl,
            bucket,
            collections,
            attachmentBaseUrl,
            allowedDomains,
            x5uHostRewrites,
            pins,
            userAgent,
            sourceId,
        )

    /**
     * Builds a [MozillaRemoteSettings], starting from [DEFAULT]'s values, so a mirror configuration keeps Mozilla's pin.
     * [build] throws [IllegalArgumentException] in two cases (spec §4): an [x5uHostRewrite] target that [allowedDomains]
     * does not allow, and an [allowedDomains] entry or either side of an [x5uHostRewrite] that is not a DNS host name as the x5u
     * URL grammar reads one (spec §7.1): LDH labels of 1 to 63 characters separated by single dots, at most 253
     * characters, no trailing dot, and a last label that is not a number, so no port, userinfo, path or IP literal.
     * ASCII upper case is allowed, since hosts are compared exactly. The fetch-time check accepts exactly these names.
     */
    public class Builder {
        internal var baseUrl: String = DEFAULT_BASE_URL
            private set
        internal var bucket: String = DEFAULT_BUCKET
            private set
        internal val collections: LinkedHashMap<Dataset, String> = linkedMapOf(Dataset.CRLITE to CRLITE_COLLECTION)
        internal var attachmentBaseUrl: String? = null
            private set
        internal var allowedDomains: Set<String> = setOf(MOZILLA_CDN_DOMAIN)
            private set
        internal val x5uHostRewrites: LinkedHashMap<String, String> = LinkedHashMap()
        internal var pinnedRootSpkiSha256s: Set<ByteString> = setOf(ROOT_CA_PRODUCTION_AMO_SPKI_SHA256)
            private set
        internal var userAgent: String = DEFAULT_USER_AGENT
            private set
        internal var sourceId: String = DEFAULT_SOURCE_ID
            private set

        public fun baseUrl(url: String): Builder = apply { baseUrl = url }

        public fun bucket(name: String): Builder = apply { bucket = name }

        /** The collection [dataset] is fetched from; replaces the earlier name. */
        public fun collection(
            dataset: Dataset,
            name: String,
        ): Builder = apply { collections[dataset] = name }

        /** Pins the attachment base URL; null, the default, reads it from the server ([attachmentBaseUrl]). */
        public fun attachmentBaseUrl(url: String?): Builder = apply { attachmentBaseUrl = url }

        /** Replaces the allowed domains with a copy of [domains] ([allowedDomains]). */
        public fun allowedDomains(domains: Set<String>): Builder = apply { allowedDomains = domains.toSet() }

        /**
         * Rewrites the x5u URI host [from] to [to] before the [allowedDomains] check, so no JSON is rewritten on the
         * wire; replaces an earlier rewrite of [from]. [allowedDomains] must allow [to] when [build] runs. Both are DNS host names,
         * compared exactly, ASCII case included; the client re-checks the rewritten URI ([x5uHostRewrites]).
         */
        public fun x5uHostRewrite(
            from: String,
            to: String,
        ): Builder = apply { x5uHostRewrites[from] = to }

        /** Replaces the pinned root SPKI SHA-256 set with copies of [hashes], compared by content. */
        public fun pinnedRootSpkiSha256s(hashes: Collection<ByteArray>): Builder =
            apply { pinnedRootSpkiSha256s = hashes.mapTo(LinkedHashSet()) { it.toByteString() } }

        public fun userAgent(ua: String): Builder = apply { userAgent = ua }

        public fun sourceId(id: String): Builder = apply { sourceId = id }

        public fun build(): MozillaRemoteSettings = MozillaRemoteSettings(this)
    }

    public companion object {
        private const val DEFAULT_BASE_URL = "https://firefox.settings.services.mozilla.com/v1"
        private const val DEFAULT_BUCKET = "security-state"
        private const val CRLITE_COLLECTION = "cert-revocations"

        // The domain of Mozilla's CDN, which serves the x5u chains and the attachments (spec §7.1).
        private const val MOZILLA_CDN_DOMAIN = "cdn.mozilla.net"
        private const val DEFAULT_USER_AGENT = "revokt"
        private const val DEFAULT_SOURCE_ID = "mozilla-remote-settings"

        /** Spec §7.1 and Appendix A (revision 49): the SPKI SHA-256 of `CN=root-ca-production-amo`. */
        private val ROOT_CA_PRODUCTION_AMO_SPKI_SHA256: ByteString =
            "3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7".decodeHex()

        /** Mozilla's production Remote Settings, with the §7.1 values. */
        @JvmField
        public val DEFAULT: MozillaRemoteSettings = Builder().build()
    }
}
