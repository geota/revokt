// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import kotlin.jvm.JvmField

/**
 * One Mozilla Remote Settings source (spec §4, §7.1): where the changesets, attachments and x5u chains come from, and the
 * pinned roots the x5u chain must end in. Every §7.1 constant lives here, per source and overridable; [DEFAULT] is
 * Mozilla's production service.
 *
 * A private mirror that serves the three Mozilla hosts' bytes unchanged is configured with [Builder.baseUrl],
 * [Builder.attachmentBaseUrl] and `x5uHostRewrite("content-signature-2.cdn.mozilla.net", mirrorHost)`, and verifies
 * and installs as `SIGNED` under the default [sourceId]. The https and no-userinfo rule on every URL here is checked
 * when the `Revokt` is built, and the x5u port rule when an x5u URL is fetched; this type checks only the rewrite. A
 * value type: equality is by content, and `ByteArray` getters return fresh copies.
 */
public class MozillaRemoteSettings private constructor(
    builder: Builder,
) {
    // The constructor takes its Builder, so the accessor Kotlin emits for the nested Builder keeps one signature as
    // fields are added (the class is growable).

    /** The Kinto API base, without a trailing `/`: default `…/v1`; `…/v2` is the documented alternative (spec §7.1). */
    public val baseUrl: String = builder.baseUrl

    /** The bucket every collection lives in: default `security-state`. */
    public val bucket: String = builder.bucket

    private val collections: Map<Dataset, String> = buildMap { putAll(builder.collections) }

    /** The base every relative `attachment.location` is resolved against; pinned here, never taken from the server. */
    public val attachmentBaseUrl: String = builder.attachmentBaseUrl

    /** The hosts an x5u URL may name, after [x5uHostRewrites]: default `content-signature-2.cdn.mozilla.net`. */
    public val x5uHosts: Set<String> = buildSet { addAll(builder.x5uHosts) }

    /**
     * The x5u host rewrites, from a host to the one fetched instead: applied once to the parsed x5u URI host before the
     * [x5uHosts] check. Every target is in [x5uHosts]. Default none.
     */
    public val x5uHostRewrites: Map<String, String> = buildMap { putAll(builder.x5uHostRewrites) }

    private val pins: Set<ByteString> = buildSet { addAll(builder.pinnedRootSpkiSha256s) }

    /** The `User-Agent` sent with every request. */
    public val userAgent: String = builder.userAgent

    /** The source's name: its `updater.json` key and `SyncResult.sourceId`. Default `mozilla-remote-settings`. */
    public val sourceId: String = builder.sourceId

    init {
        for ((from, to) in x5uHostRewrites) {
            require(to in x5uHosts) {
                "x5uHostRewrite(\"$from\", \"$to\"): \"$to\" is not in x5uHosts $x5uHosts; add it with x5uHosts(…) " +
                    "(spec §4, §7.1)"
            }
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
     * [build] throws [IllegalArgumentException] in one case: an [x5uHostRewrite] target outside [x5uHosts].
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
         * replaces an earlier rewrite of [from]. [to] must be in [x5uHosts] when [build] runs.
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

        /** Spec §7.1 and Appendix A (revision 49): the SPKI SHA-256 of `CN=root-ca-production-amo`. */
        private val ROOT_CA_PRODUCTION_AMO_SPKI_SHA256: ByteString =
            "3317FA45154AC7DA55694D3782316056471FC147C04AED3E03FFE99565B1E2E7".decodeHex()

        /** Mozilla's production Remote Settings, with the §7.1 values. */
        @JvmField
        public val DEFAULT: MozillaRemoteSettings = Builder().build()
    }
}
