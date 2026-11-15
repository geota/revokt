// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

/**
 * A configured C2SP manifest mirror (spec §7.3, the `c2spMirror` source of §4), the `MIRROR` trust class. [baseUrl] is
 * the configured URL as [HopUrl] re-serialised it, with a `/` appended when it does not end in one; the manifest and
 * every mirror file are fetched from it followed by their name, nothing else from the manifest entering a URL.
 * [sourceId] is its `updater.json` key and `SyncResult.sourceId`; [userAgent] is sent on every request.
 *
 * Internal until the `Revokt` builder's `sources { c2spMirror(url) }` exists (0.3, §11); [Builder.build] is where that
 * builder's checks of the URL run.
 */
internal class C2spMirrorSource private constructor(
    val baseUrl: String,
    val sourceId: String,
    val userAgent: String,
) {
    /** The URL of the manifest, `<base>manifest.json`. */
    val manifestUrl: String get() = baseUrl + MANIFEST

    /** The URL of the mirror file [filename], a §7.3-checked `manifest.json` filename: `<base><filename>`. */
    fun fileUrl(filename: String): String = baseUrl + filename

    override fun toString(): String = "C2spMirrorSource($baseUrl, sourceId=$sourceId)"

    /** Builds a [C2spMirrorSource] from the configured mirror [url]. */
    class Builder(
        private val url: String,
    ) {
        private var sourceId: String = DEFAULT_SOURCE_ID
        private var userAgent: String = DEFAULT_USER_AGENT

        fun sourceId(id: String): Builder = apply { sourceId = id }

        fun userAgent(ua: String): Builder = apply { userAgent = ua }

        /**
         * The source, or [IllegalArgumentException] when [url] breaks a rule (spec §4 R bullets, §7.3): it must be
         * `https` with no userinfo, a DNS host name or an IP literal, a port from 1 to 65535 when one is written, and an
         * RFC 3986 path, as [HopUrl.parse] reads every URL of a redirect chain (the maintainer's decisions on #192), and
         * it must carry no query and no fragment, since every mirror URL is the base followed by a name.
         */
        fun build(): C2spMirrorSource {
            require('?' !in url) { "the c2spMirror URL \"$url\" has a query (spec §4, §7.3)" }
            require('#' !in url) { "the c2spMirror URL \"$url\" has a fragment (spec §4, §7.3)" }
            val parsed =
                when (val read = HopUrl.parse(url)) {
                    is HopUrlRead.Parsed -> {
                        read.url
                    }

                    is HopUrlRead.Refused -> {
                        throw IllegalArgumentException(
                            "the c2spMirror URL \"$url\" is not an https URL revokt fetches (spec §4, §7.3): " +
                                "${read.failure}: ${read.detail}",
                        )
                    }
                }
            require(sourceId.isNotEmpty()) { "sourceId is empty" }
            val text = parsed.toString()
            return C2spMirrorSource(if (text.endsWith('/')) text else "$text/", sourceId, userAgent)
        }
    }

    internal companion object {
        /** The manifest's name under the base. */
        const val MANIFEST = "manifest.json"

        /** The source id when none is set (the spec names none; this is the source's name in §4's `sources { }`). */
        const val DEFAULT_SOURCE_ID = "c2spMirror"

        private const val DEFAULT_USER_AGENT = "revokt"
    }
}
