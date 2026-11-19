// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

/** Why [StrictUrl] refused a URL. */
internal enum class StrictUrlFailure {
    /** Not `https://authority[rest]` as [StrictUrl] reads it. */
    SYNTAX,

    /** A scheme other than `https`. */
    SCHEME,

    /** A userinfo (`@`) in the authority. */
    USERINFO,

    /** The host is not a DNS host name. */
    HOST,
}

/** A [StrictUrl.parse] result: [Parsed] or [Refused]. */
internal sealed class StrictUrlRead {
    /**
     * An `https` URL's [host] as written, its [port] text after the `:` (null when the authority has no `:`; unchecked,
     * each caller has its own port rule) and [rest], everything after the authority: empty or starting with `/`, `?`
     * or `#`, unchecked ([StrictUrl.isPathAndQuery] checks it).
     */
    class Parsed(
        val host: String,
        val port: String?,
        val rest: String,
    ) : StrictUrlRead()

    class Refused(
        val failure: StrictUrlFailure,
        val detail: String,
    ) : StrictUrlRead()
}

/**
 * The strict URL grammar the x5u URL ([X5uUrl], spec §7.1) is read by. It is deliberately narrow, so no URL parser
 * downstream can see another host than the one checked: `https://` (lowercase), an authority with no userinfo that is
 * a host and an optional port, then the rest. The host is a DNS host name ([isHostName]: labels of ASCII letters,
 * digits and `-`, no trailing dot, a last label that is not a number); never an IP literal, a percent-encoded or a
 * non-ASCII host. What is fetched is re-serialised by the caller from the parts, never the string as given.
 */
internal object StrictUrl {
    private const val SCHEME = "https://"
    private const val MAX_HOST = 253
    private const val MAX_LABEL = 63

    private val AUTHORITY_ENDS = charArrayOf('/', '?', '#')

    /** `pchar` (RFC 3986 §3.3) without `%`, plus `/` and `?`: unreserved, sub-delims, `:` and `@`. */
    private const val PATH_CHARS = "-._~!$&'()*+,;=:@/?"

    /**
     * [url] split into an `https` URL's host, port text and rest; refused when the scheme is not `https://` exactly,
     * the authority holds a `@`, or the host is not a DNS host name.
     */
    fun parse(url: String): StrictUrlRead {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return StrictUrlRead.Refused(StrictUrlFailure.SYNTAX, "no scheme")
        val scheme = url.substring(0, schemeEnd + 3)
        if (scheme != SCHEME) return StrictUrlRead.Refused(StrictUrlFailure.SCHEME, "not https")
        val start = schemeEnd + 3
        val end = url.indexOfAny(AUTHORITY_ENDS, start).let { if (it < 0) url.length else it }
        val authority = url.substring(start, end)
        if ('@' in authority) return StrictUrlRead.Refused(StrictUrlFailure.USERINFO, "userinfo")
        // The port follows the last `:`; a bracketed IPv6 host splits into no DNS host name, so it is refused.
        val colon = authority.lastIndexOf(':')
        val host = if (colon < 0) authority else authority.substring(0, colon)
        val port = if (colon < 0) null else authority.substring(colon + 1)
        if (!isHostName(host)) return StrictUrlRead.Refused(StrictUrlFailure.HOST, "not a DNS host name")
        return StrictUrlRead.Parsed(host, port, url.substring(end))
    }

    /**
     * True when [text] is RFC 3986 `pchar`s, `/` and `?` only, every `%` followed by two hex digits: a path and a query,
     * or a query or a fragment alone. A `#` is not one of them.
     */
    fun isPathAndQuery(text: String): Boolean {
        var i = 0
        while (i < text.length) {
            val c = text[i]
            when {
                c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c in PATH_CHARS -> i++
                c == '%' && i + 2 < text.length && isHex(text[i + 1]) && isHex(text[i + 2]) -> i += 3
                else -> return false
            }
        }
        return true
    }

    /**
     * A DNS host name as this grammar reads one: LDH labels of 1 to 63 characters, ASCII case kept, separated by single
     * dots, at most 253 characters, no trailing dot, and a last label that is not a number. `MozillaRemoteSettings`
     * holds its x5u hosts and rewrites to the same rule at build (spec §4), so both accept exactly the same names.
     */
    fun isHostName(host: String): Boolean {
        if (host.isEmpty() || host.length > MAX_HOST) return false
        val labels = host.split('.')
        val names =
            labels.all { label ->
                label.length in 1..MAX_LABEL &&
                    label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
            }
        // A last label that reads as a number makes the host an IPv4 address to WHATWG URL parsers (`1.2.3.4`,
        // `0x7f.1`), so it is no DNS name here and "no IP literal" holds.
        return names && !isNumeric(labels.last())
    }

    private fun isNumeric(label: String): Boolean {
        val hex = label.length > 1 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X')
        return if (hex) label.drop(2).all(::isHex) else label.all { it in '0'..'9' }
    }

    private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
}
