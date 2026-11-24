// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

/** Why an x5u URL is refused before any fetch; each is `SyncFailure.X5U_URL` (spec §7.1). */
internal enum class X5uUrlFailure {
    /** Not `https://host[:port]/path`, as [X5uUrl] reads it. */
    SYNTAX,

    /** A scheme other than `https`. */
    SCHEME,

    /** A userinfo (`@`) in the authority. */
    USERINFO,

    /** A port other than 443, or an empty one. */
    PORT,

    /** The host after the rewrite is not under `allowedDomains` ([AllowedDomains]). */
    HOST,

    /** The rewritten URI's parsed host is not the rewrite target exactly (a target carrying a port, userinfo or path). */
    REWRITE,
}

/** An x5u URL check: [url] is what is fetched when [failure] is null. */
internal class X5uUrlCheck private constructor(
    val url: String?,
    val failure: X5uUrlFailure?,
    val detail: String,
) {
    companion object {
        fun allowed(url: String): X5uUrlCheck = X5uUrlCheck(url, null, url)

        fun refused(
            failure: X5uUrlFailure,
            detail: String,
        ): X5uUrlCheck = X5uUrlCheck(null, failure, detail)
    }
}

/**
 * The x5u URL rules of spec §7.1 ("x5u chain": HTTPS from a host under the allowed domains, "the parsed URI host after
 * rejecting userinfo, a non-https scheme and a port other than 443"; the private-mirror paragraph: "the rewrite is
 * applied to the parsed x5u URI host before the `allowedDomains` check … the https-only, port-443 and no-userinfo rules apply to the mirror host
 * too"), with the #177 review's contract for the rewrite.
 *
 * The URL is read by [StrictUrl]'s narrow grammar, so no URL parser downstream can see another host than the one
 * checked: `https://` (lowercase), an authority that is a DNS host name (labels of ASCII letters, digits and `-`,
 * separated by single dots, no trailing dot) and an optional port, then a path starting with `/` whose characters are
 * RFC 3986 `pchar`s, `/` and `?`, with every `%` followed by two hex digits. No fragment, no IP literal (nor a host
 * whose last label is a number), no percent-encoded or non-ASCII host (`java.net.URI.getHost()` would be null for the
 * latter). What is fetched is re-serialised from the parts: `https://`, the checked host, the path; an explicit `:443`
 * is dropped.
 *
 * Hosts are compared exactly, ASCII case included, against [x5uHostRewrites][dev.revokt.MozillaRemoteSettings.x5uHostRewrites]
 * and [allowedDomains][dev.revokt.MozillaRemoteSettings.allowedDomains] ([AllowedDomains], #177). After a rewrite the rewritten URI is re-parsed and
 * every rule re-applied, and its parsed host must equal the target exactly, so a target carrying a port, userinfo or a
 * path cannot get past §7.1.
 */
internal object X5uUrl {
    private const val SCHEME = "https://"

    fun check(
        url: String,
        domains: Set<String>,
        rewrites: Map<String, String>,
    ): X5uUrlCheck {
        val parsed =
            when (val read = parse(url)) {
                is Read.Refused -> return read.check(url)
                is Read.Parsed -> read
            }
        val target = rewrites[parsed.host]
        val fetched =
            if (target == null) {
                parsed
            } else {
                // The rewritten URI: the original with its host replaced, re-parsed and re-checked whole (#177).
                val rewritten = SCHEME + target + parsed.port + parsed.path
                when (val again = parse(rewritten)) {
                    is Read.Refused -> {
                        return again.check(rewritten)
                    }

                    is Read.Parsed -> {
                        if (again.host != target) {
                            return X5uUrlCheck.refused(
                                X5uUrlFailure.REWRITE,
                                "rewrite target \"$target\" parses as host \"${again.host}\"",
                            )
                        }
                        again
                    }
                }
            }
        if (!AllowedDomains.allows(fetched.host, domains)) {
            return X5uUrlCheck.refused(X5uUrlFailure.HOST, "host \"${fetched.host}\" is not under allowedDomains")
        }
        return X5uUrlCheck.allowed(SCHEME + fetched.host + fetched.path)
    }

    private sealed class Read {
        class Parsed(
            val host: String,
            /** `""` or `":443"`, as written. */
            val port: String,
            val path: String,
        ) : Read()

        class Refused(
            val failure: X5uUrlFailure,
            val detail: String,
        ) : Read() {
            fun check(url: String): X5uUrlCheck = X5uUrlCheck.refused(failure, "$detail: \"$url\"")
        }
    }

    private fun parse(url: String): Read {
        val read =
            when (val strict = StrictUrl.parse(url)) {
                is StrictUrlRead.Parsed -> strict
                is StrictUrlRead.Refused -> return Read.Refused(failure(strict.failure), strict.detail)
            }
        val port = read.port?.let { ":$it" } ?: ""
        if (port.isNotEmpty() && port != ":443") return Read.Refused(X5uUrlFailure.PORT, "port \"${port.drop(1)}\"")
        val path = read.rest
        if (!path.startsWith('/') || !StrictUrl.isPathAndQuery(path)) {
            return Read.Refused(X5uUrlFailure.SYNTAX, "not a plain path")
        }
        return Read.Parsed(read.host, port, path)
    }

    /** The x5u failure for a [StrictUrl] refusal: a host that is not a DNS name is a syntax failure here. */
    private fun failure(strict: StrictUrlFailure): X5uUrlFailure =
        when (strict) {
            StrictUrlFailure.SYNTAX, StrictUrlFailure.HOST -> X5uUrlFailure.SYNTAX
            StrictUrlFailure.SCHEME -> X5uUrlFailure.SCHEME
            StrictUrlFailure.USERINFO -> X5uUrlFailure.USERINFO
        }
}
