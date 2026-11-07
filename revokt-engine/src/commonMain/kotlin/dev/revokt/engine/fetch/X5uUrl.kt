// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

/** Why an x5u URL is refused before any fetch; each is `SyncOutcome.FAILED` at stage `X5U` (spec §7.1). */
internal enum class X5uUrlFailure {
    /** Not `https://host[:port]/path`, as [X5uUrl] reads it. */
    SYNTAX,

    /** A scheme other than `https`. */
    SCHEME,

    /** A userinfo (`@`) in the authority. */
    USERINFO,

    /** A port other than 443, or an empty one. */
    PORT,

    /** The host after the rewrite is not in `x5uHosts`. */
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
 * The x5u URL rules of spec §7.1 ("x5u chain": HTTPS from the allowlist, "the parsed URI host after rejecting userinfo,
 * a non-https scheme and a port other than 443"; the private-mirror paragraph: "the rewrite is applied to the parsed
 * x5u URI host before the `x5uHosts` check … the https-only, port-443 and no-userinfo rules apply to the mirror host
 * too"), with the #177 review's contract for the rewrite.
 *
 * The URL is read by a deliberately narrow grammar, so no URL parser downstream can see another host than the one
 * checked: `https://` (lowercase), an authority that is a DNS host name (labels of ASCII letters, digits and `-`,
 * separated by single dots, no trailing dot) and an optional port, then a path starting with `/` whose characters are
 * RFC 3986 `pchar`s, `/` and `?`, with every `%` followed by two hex digits. No fragment, no IP literal, no
 * percent-encoded or non-ASCII host (`java.net.URI.getHost()` would be null for the latter). What is fetched is
 * re-serialised from the parts: `https://`, the checked host, the path; an explicit `:443` is dropped.
 *
 * Hosts are compared exactly, ASCII case included, against [x5uHostRewrites][dev.revokt.MozillaRemoteSettings.x5uHostRewrites]
 * and [x5uHosts][dev.revokt.MozillaRemoteSettings.x5uHosts] (#177). After a rewrite the rewritten URI is re-parsed and
 * every rule re-applied, and its parsed host must equal the target exactly, so a target carrying a port, userinfo or a
 * path cannot get past §7.1.
 */
internal object X5uUrl {
    private const val SCHEME = "https://"
    private const val MAX_HOST = 253
    private const val MAX_LABEL = 63

    /** `pchar` (RFC 3986 §3.3) without `%`, plus `/` and `?`: unreserved, sub-delims, `:` and `@`. */
    private val AUTHORITY_ENDS = charArrayOf('/', '?', '#')

    private const val PATH_CHARS = "-._~!$&'()*+,;=:@/?"

    fun check(
        url: String,
        hosts: Set<String>,
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
        if (fetched.host !in hosts) {
            return X5uUrlCheck.refused(X5uUrlFailure.HOST, "host \"${fetched.host}\" is not in x5uHosts")
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
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return Read.Refused(X5uUrlFailure.SYNTAX, "no scheme")
        if (url.substring(0, schemeEnd + 3) != SCHEME) return Read.Refused(X5uUrlFailure.SCHEME, "not https")
        val start = schemeEnd + 3
        val end = url.indexOfAny(AUTHORITY_ENDS, start).let { if (it < 0) url.length else it }
        val authority = url.substring(start, end)
        if ('@' in authority) return Read.Refused(X5uUrlFailure.USERINFO, "userinfo")
        val colon = authority.lastIndexOf(':')
        val host = if (colon < 0) authority else authority.substring(0, colon)
        val port = if (colon < 0) "" else authority.substring(colon)
        if (!isHostName(host)) return Read.Refused(X5uUrlFailure.SYNTAX, "not a DNS host name")
        if (port.isNotEmpty() && port != ":443") return Read.Refused(X5uUrlFailure.PORT, "port \"${port.drop(1)}\"")
        val path = url.substring(end)
        if (!isPath(path)) return Read.Refused(X5uUrlFailure.SYNTAX, "not a plain path")
        return Read.Parsed(host, port, path)
    }

    private fun isHostName(host: String): Boolean {
        if (host.isEmpty() || host.length > MAX_HOST) return false
        return host.split('.').all { label ->
            label.length in 1..MAX_LABEL &&
                label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
        }
    }

    private fun isPath(path: String): Boolean {
        if (!path.startsWith('/')) return false
        var i = 0
        while (i < path.length) {
            val c = path[i]
            when {
                c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in PATH_CHARS -> i++
                c == '%' && i + 2 < path.length && isHex(path[i + 1]) && isHex(path[i + 2]) -> i += 3
                else -> return false
            }
        }
        return true
    }

    private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
}
