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

    /** The host is not one the caller allows: not a DNS host name, or, when IP literals are allowed, not one either. */
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
 * The one strict URL grammar every URL revokt fetches from an unsigned or configured string is read by: the x5u URL
 * ([X5uUrl], spec §7.1) and every URL of a mirror's redirect chain ([HopUrl], §7.3). It is deliberately narrow, so no
 * URL parser downstream can see another host than the one checked: `https://` (lowercase), an authority with no
 * userinfo that is a host and an optional port, then the rest. The host is a DNS host name ([isHostName]: labels of
 * ASCII letters, digits and `-`, no trailing dot, a last label that is not a number), and, only when the caller allows
 * IP literals, an IPv4 dotted quad ([isIpv4]) or a bracketed IPv6 address ([isIpv6Literal]); never a percent-encoded or
 * non-ASCII host. What is fetched is re-serialised by the caller from the parts, never the string as given.
 */
internal object StrictUrl {
    private const val SCHEME = "https://"
    private const val MAX_HOST = 253
    private const val MAX_LABEL = 63
    private const val IPV4_PARTS = 4
    private const val MAX_OCTET = 255
    private const val MAX_OCTET_DIGITS = 3
    private const val IPV6_GROUPS = 8
    private const val MAX_GROUP_DIGITS = 4

    private val AUTHORITY_ENDS = charArrayOf('/', '?', '#')

    /** `pchar` (RFC 3986 §3.3) without `%`, plus `/` and `?`: unreserved, sub-delims, `:` and `@`. */
    private const val PATH_CHARS = "-._~!$&'()*+,;=:@/?"

    /**
     * [url] split into an `https` URL's host, port text and rest; refused when the scheme is not `https://` exactly,
     * the authority holds a `@`, or the host is not a DNS host name (nor, with [ipLiterals], an IP literal).
     */
    fun parse(
        url: String,
        ipLiterals: Boolean,
    ): StrictUrlRead {
        val schemeEnd = url.indexOf("://")
        if (schemeEnd < 0) return StrictUrlRead.Refused(StrictUrlFailure.SYNTAX, "no scheme")
        val scheme = url.substring(0, schemeEnd + 3)
        if (scheme != SCHEME) return StrictUrlRead.Refused(StrictUrlFailure.SCHEME, "not https")
        val start = schemeEnd + 3
        val end = url.indexOfAny(AUTHORITY_ENDS, start).let { if (it < 0) url.length else it }
        val authority = url.substring(start, end)
        if ('@' in authority) return StrictUrlRead.Refused(StrictUrlFailure.USERINFO, "userinfo")
        val (host, port) = splitAuthority(authority, ipLiterals)
        if (!isHostName(host) && !(ipLiterals && isIpLiteral(host))) {
            val expected = if (ipLiterals) "a DNS host name or an IP literal" else "a DNS host name"
            return StrictUrlRead.Refused(StrictUrlFailure.HOST, "not $expected")
        }
        return StrictUrlRead.Parsed(host, port, url.substring(end))
    }

    /**
     * [authority] split at the `:` before its port: the last `:`, or, for a bracketed IPv6 host when [ipLiterals]
     * allows one, the `:` right after the `]`, since the address holds colons of its own. The port is null when there
     * is no such `:`.
     */
    private fun splitAuthority(
        authority: String,
        ipLiterals: Boolean,
    ): Pair<String, String?> {
        val colon =
            if (ipLiterals && authority.startsWith('[')) {
                authority.indexOf("]:").let { if (it < 0) -1 else it + 1 }
            } else {
                authority.lastIndexOf(':')
            }
        return if (colon < 0) authority to null else authority.substring(0, colon) to authority.substring(colon + 1)
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

    private fun isIpLiteral(host: String): Boolean = isIpv4(host) || isIpv6Literal(host)

    /**
     * An IPv4 address in dotted-quad form (RFC 3986 `IPv4address`): four decimal octets of 0 to 255 with no leading
     * zero, so no parser can read one as octal (`010`) or as fewer parts (`127.1`).
     */
    fun isIpv4(host: String): Boolean {
        val parts = host.split('.')
        return parts.size == IPV4_PARTS &&
            parts.all { part ->
                part.length in 1..MAX_OCTET_DIGITS &&
                    part.all { it in '0'..'9' } &&
                    (part.length == 1 || part[0] != '0') &&
                    part.toInt() <= MAX_OCTET
            }
    }

    /**
     * A bracketed IPv6 address (RFC 3986 `IP-literal` with `IPv6address`): eight groups of 1 to 4 hex digits, or fewer
     * around one `::`, the last two groups optionally an [isIpv4] address. No zone identifier and no `IPvFuture`.
     */
    fun isIpv6Literal(host: String): Boolean {
        if (host.length < 4 || host[0] != '[' || host.last() != ']') return false
        val address = host.substring(1, host.length - 1)
        val compressed = address.indexOf("::")
        val head = if (compressed < 0) address else address.substring(0, compressed)
        val tail = if (compressed < 0) "" else address.substring(compressed + 2)
        // A second `::` (or a third colon) leaves an empty group, which no hex group matches.
        val groups = groups(head) + groups(tail)
        // A trailing dotted quad stands for the last two groups.
        val last = groups.lastOrNull().orEmpty()
        val ipv4 = '.' in last
        if (ipv4 && !isIpv4(last)) return false
        val hex = if (ipv4) groups.dropLast(1) else groups
        val count = hex.size + if (ipv4) 2 else 0
        return hex.all(::isHexGroup) && if (compressed < 0) count == IPV6_GROUPS else count < IPV6_GROUPS
    }

    private fun isHexGroup(group: String): Boolean = group.length in 1..MAX_GROUP_DIGITS && group.all(::isHex)

    private fun groups(part: String): List<String> = if (part.isEmpty()) emptyList() else part.split(':')

    private fun isNumeric(label: String): Boolean {
        val hex = label.length > 1 && label[0] == '0' && (label[1] == 'x' || label[1] == 'X')
        return if (hex) label.drop(2).all(::isHex) else label.all { it in '0'..'9' }
    }

    private fun isHex(c: Char): Boolean = c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'
}
