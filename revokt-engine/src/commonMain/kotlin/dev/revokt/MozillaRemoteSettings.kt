// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import kotlin.jvm.JvmField

/**
 * One Mozilla Remote Settings source (spec §4, §7.1): where the changesets, attachments and x5u chains come from, and the
 * pinned roots the x5u chain must end in. §7.1's per-source values live here, each overridable: the base URLs, the bucket
 * and collections, the x5u host allowlist and rewrites, the pinned root set, the `User-Agent` and the source id. The
 * protocol's fixed rules and the `RevoktLimits` caps do not. [DEFAULT] is Mozilla's production service.
 *
 * A private mirror that serves the three Mozilla hosts' bytes unchanged is configured with [Builder.baseUrl],
 * [Builder.attachmentBaseUrl] and `x5uHostRewrite("content-signature-2.cdn.mozilla.net", mirrorHost)`, and verifies
 * and installs as `SIGNED` under the default [sourceId]. The https and no-userinfo rule on every URL here is checked
 * when the `Revokt` is built, and the x5u port rule when an x5u URL is fetched; this type checks only the x5u hosts and
 * rewrites ([Builder]). A value type: equality is by content, and `ByteArray` getters return fresh copies.
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
     * The base every relative `attachment.location` is resolved against; pinned here, never taken from the server. The
     * client joins it to the location with exactly one `/`, as for [baseUrl].
     */
    public val attachmentBaseUrl: String = builder.attachmentBaseUrl

    /**
     * The hosts an x5u URL may name, after [x5uHostRewrites]: default `content-signature-2.cdn.mozilla.net`. Each is a
     * bare ASCII DNS name ([Builder]). Hosts are compared exactly, ASCII case included, so an entry should be lowercase
     * as Mozilla's are.
     */
    public val x5uHosts: Set<String> = buildSet { addAll(builder.x5uHosts) }

    /**
     * The x5u host rewrites, from a host to the one fetched instead: applied once to the parsed x5u URI host before the
     * [x5uHosts] check. Every target is in [x5uHosts], and both sides are bare ASCII DNS names ([Builder]). Default
     * none. Hosts are compared exactly, ASCII case included. The client still re-parses the rewritten URI, re-applies
     * the scheme, userinfo and port rules to it, and requires its parsed host to equal the target (spec §7.1).
     */
    public val x5uHostRewrites: Map<String, String> = buildMap { putAll(builder.x5uHostRewrites) }

    private val pins: Set<ByteString> = buildSet { addAll(builder.pinnedRootSpkiSha256s) }

    /** The `User-Agent` sent with every request. */
    public val userAgent: String = builder.userAgent

    /** The source's name: its `updater.json` key and `SyncResult.sourceId`. Default `mozilla-remote-settings`. */
    public val sourceId: String = builder.sourceId

    init {
        for (host in x5uHosts) requireBareHost("x5uHosts entry", host)
        for ((from, to) in x5uHostRewrites) {
            requireBareHost("x5uHostRewrite from", from)
            requireBareHost("x5uHostRewrite to", to)
            require(to in x5uHosts) {
                "x5uHostRewrite(\"$from\", \"$to\"): \"$to\" is not in x5uHosts $x5uHosts; add it with x5uHosts(…) " +
                    "(spec §4, §7.1)"
            }
        }
    }

    private fun requireBareHost(
        what: String,
        host: String,
    ) {
        require(host.isNotEmpty() && host.none { it in NOT_IN_BARE_HOST || it.code > ASCII_MAX }) {
            "$what \"$host\" is not a bare ASCII DNS name: empty, non-ASCII, or holding one of $NOT_IN_BARE_HOST " +
                "(spec §4, revision 56)"
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
                .x5uHosts(x5uHosts)
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
            "attachmentBaseUrl=$attachmentBaseUrl, x5uHosts=$x5uHosts, x5uHostRewrites=$x5uHostRewrites, " +
            "pinnedRootSpkiSha256s=${pins.map { it.hex() }}, userAgent=$userAgent, sourceId=$sourceId)"

    private fun fields(): List<Any> =
        listOf(baseUrl, bucket, collections, attachmentBaseUrl, x5uHosts, x5uHostRewrites, pins, userAgent, sourceId)

    /**
     * Builds a [MozillaRemoteSettings], starting from [DEFAULT]'s values, so a mirror configuration keeps Mozilla's pin.
     * [build] throws [IllegalArgumentException] in two cases (spec §4, revision 56): an [x5uHostRewrite] target outside
     * [x5uHosts], and an [x5uHosts] entry or either side of an [x5uHostRewrite] that is not a bare ASCII DNS name, that
     * is one that is empty, holds a non-ASCII character or holds any of `:`, `@`, `/`, `?`, `#` and `[`. Nothing else
     * about a host is checked here: the fetch-time x5u rules still refuse what is not a DNS host name (spec §7.1).
     */
    public class Builder {
        internal var baseUrl: String = DEFAULT_BASE_URL
            private set
        internal var bucket: String = DEFAULT_BUCKET
            private set
        internal val collections: LinkedHashMap<Dataset, String> = linkedMapOf(Dataset.CRLITE to CRLITE_COLLECTION)
        internal var attachmentBaseUrl: String = DEFAULT_ATTACHMENT_BASE_URL
            private set
        internal var x5uHosts: Set<String> = setOf(MOZILLA_X5U_HOST)
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

        public fun attachmentBaseUrl(url: String): Builder = apply { attachmentBaseUrl = url }

        /** Replaces the x5u host allowlist with a copy of [hosts]. */
        public fun x5uHosts(hosts: Set<String>): Builder = apply { x5uHosts = hosts.toSet() }

        /**
         * Rewrites the x5u URI host [from] to [to] before the [x5uHosts] check, so no JSON is rewritten on the wire;
         * replaces an earlier rewrite of [from]. [to] must be in [x5uHosts] when [build] runs. Both are bare hosts,
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

        // The server root's capabilities.attachments.base_url, read 2026-11-06 (spec §7.1 pins it here).
        private const val DEFAULT_ATTACHMENT_BASE_URL = "https://firefox-settings-attachments.cdn.mozilla.net/"
        private const val MOZILLA_X5U_HOST = "content-signature-2.cdn.mozilla.net"
        private const val DEFAULT_USER_AGENT = "revokt"
        private const val DEFAULT_SOURCE_ID = "mozilla-remote-settings"

        // Spec §4 (revision 56): what keeps a port, userinfo, a path, a query, a fragment or an IP literal out of a host.
        private const val NOT_IN_BARE_HOST = ":@/?#["
        private const val ASCII_MAX = 0x7F

        /** Spec §7.1 and Appendix A (revision 49): the SPKI SHA-256 of `CN=root-ca-production-amo`. */
        private val ROOT_CA_PRODUCTION_AMO_SPKI_SHA256: ByteString =
            "3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7".decodeHex()

        /** Mozilla's production Remote Settings, with the §7.1 values. */
        @JvmField
        public val DEFAULT: MozillaRemoteSettings = Builder().build()
    }
}
