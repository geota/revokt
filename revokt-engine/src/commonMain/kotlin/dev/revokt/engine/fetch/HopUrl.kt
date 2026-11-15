// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

/**
 * One URL of a redirect chain as [RedirectingFetcher] reads it (spec §7.3 "Redirects"), by [StrictUrl], the grammar the
 * x5u URL is read by too, with IP literals allowed (the maintainer's decision on #192; the configured `c2spMirror` URL
 * takes the same rule, §4): `https`, a DNS host name, an IPv4 dotted quad or a bracketed IPv6 address, an optional port
 * of 1 to 65535 (no other port rule), a path and an optional query; never userinfo, and any fragment is dropped.
 *
 * [toString] is the URL that is fetched, re-serialised from the parts, never the string as given: `https://`, [host]
 * lowercased, the port only when it is not 443, the path (`/` when empty, dot segments removed) and the query as
 * written. Two URLs are the same hop when their [toString]s are equal, which is what the loop check compares; IPv6
 * addresses are compared as written, lowercased, not in a canonical form.
 */
internal class HopUrl private constructor(
    /** The host, lowercased: DNS names and IPv6 hex digits compare ignoring ASCII case. */
    val host: String,
    /** The port; 443 when the URL names none. */
    val port: Int,
    private val path: String,
    private val query: String?,
) {
    /** True when [other] is on another origin: another host or port (the scheme is always `https`). */
    fun isCrossOrigin(other: HopUrl): Boolean = host != other.host || port != other.port

    /**
     * [reference], a `Location` value, resolved against this URL as RFC 3986 §5.2.2 resolves a reference against a base
     * URI (§5.2.4's dot-segment removal included), then read by [parse]: an absolute URL, a network-path (`//host/p`),
     * an absolute path, a relative path, a query alone or an empty reference. Any fragment is dropped, the base's
     * included, but must still be one RFC 3986 allows.
     */
    fun resolve(reference: String): HopUrlRead {
        val withoutFragment =
            withoutFragment(reference)
                ?: return HopUrlRead.Refused(StrictUrlFailure.SYNTAX, "not an RFC 3986 fragment")
        return when {
            hasScheme(withoutFragment) -> {
                parse(withoutFragment)
            }

            withoutFragment.startsWith("//") -> {
                parse("https:$withoutFragment")
            }

            else -> {
                val refPath = withoutFragment.substringBefore('?')
                val refQuery = if ('?' in withoutFragment) withoutFragment.substringAfter('?') else null
                val (newPath, newQuery) =
                    when {
                        refPath.isEmpty() -> path to (refQuery ?: query)
                        refPath.startsWith('/') -> removeDotSegments(refPath) to refQuery
                        else -> removeDotSegments(merge(refPath)) to refQuery
                    }
                parse(authority() + newPath + (newQuery?.let { "?$it" } ?: ""))
            }
        }
    }

    /** RFC 3986 §5.2.3: [refPath] after the base path's last `/` (the base always has an authority and a path). */
    private fun merge(refPath: String): String = path.substring(0, path.lastIndexOf('/') + 1) + refPath

    private fun authority(): String = "https://" + host + if (port == DEFAULT_PORT) "" else ":$port"

    override fun toString(): String = authority() + path + (query?.let { "?$it" } ?: "")

    override fun equals(other: Any?): Boolean = other is HopUrl && toString() == other.toString()

    override fun hashCode(): Int = toString().hashCode()

    internal companion object {
        private const val DEFAULT_PORT = 443
        private const val MAX_PORT = 65535
        private const val MAX_PORT_DIGITS = 5

        /**
         * [url], an absolute URL, read by [StrictUrl] with IP literals allowed, then the hop rules: a port of 1 to 65535
         * when one is written, the rest a path of `pchar`s and `/` and an optional query of `pchar`s, `/` and `?`, every
         * `%` followed by two hex digits (RFC 3986). A fragment is dropped. Dot segments are removed from the path (RFC
         * 3986 §5.2.4).
         */
        fun parse(url: String): HopUrlRead {
            val withoutFragment =
                withoutFragment(url) ?: return HopUrlRead.Refused(StrictUrlFailure.SYNTAX, "not an RFC 3986 fragment")
            val read =
                when (val strict = StrictUrl.parse(withoutFragment, ipLiterals = true)) {
                    is StrictUrlRead.Parsed -> strict
                    is StrictUrlRead.Refused -> return HopUrlRead.Refused(strict.failure, strict.detail)
                }
            val port =
                if (read.port == null) DEFAULT_PORT else port(read.port) ?: return refused("not a port from 1 to 65535")
            if (!StrictUrl.isPathAndQuery(read.rest)) return refused("not an RFC 3986 path and query")
            val path = removeDotSegments(read.rest.substringBefore('?')).ifEmpty { "/" }
            val query = if ('?' in read.rest) read.rest.substringAfter('?') else null
            return HopUrlRead.Parsed(HopUrl(read.host.lowercase(), port, path, query))
        }

        private fun refused(detail: String): HopUrlRead = HopUrlRead.Refused(StrictUrlFailure.SYNTAX, detail)

        /** [text] before its first `#`, or null when what follows it is not an RFC 3986 fragment. */
        private fun withoutFragment(text: String): String? {
            val hash = text.indexOf('#')
            if (hash < 0) return text
            return if (StrictUrl.isPathAndQuery(text.substring(hash + 1))) text.substring(0, hash) else null
        }

        /** True when [reference] starts with a scheme and its `:` (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"`). */
        private fun hasScheme(reference: String): Boolean {
            val colon = reference.indexOf(':')
            if (colon < 1) return false
            val scheme = reference.substring(0, colon)
            return scheme[0].isAsciiLetter() &&
                scheme.all { it.isAsciiLetter() || it in '0'..'9' || it == '+' || it == '-' || it == '.' }
        }

        private fun port(digits: String): Int? {
            if (digits.isEmpty() || digits.length > MAX_PORT_DIGITS || !digits.all { it in '0'..'9' }) return null
            return digits.toInt().takeIf { it in 1..MAX_PORT }
        }

        /** RFC 3986 §5.2.4 `remove_dot_segments`, over the literal segments (`%2E` is not a dot here). */
        internal fun removeDotSegments(path: String): String {
            val output = ArrayList<String>()
            val segments = path.split('/')
            // A path "/a/b" splits as ["", "a", "b"]: the leading "" is the root, kept as the first output segment.
            for ((index, segment) in segments.withIndex()) {
                val last = index == segments.lastIndex
                when (segment) {
                    "." -> {
                        if (last) output.add("")
                    }

                    ".." -> {
                        if (output.size > 1) output.removeAt(output.lastIndex)
                        if (last) output.add("")
                    }

                    else -> {
                        output.add(segment)
                    }
                }
            }
            return output.joinToString("/")
        }

        private fun Char.isAsciiLetter(): Boolean = this in 'a'..'z' || this in 'A'..'Z'
    }
}

/** A [HopUrl] read: [Parsed], or [Refused] with the [StrictUrl] failure (a bad port or path is [StrictUrlFailure.SYNTAX]). */
internal sealed class HopUrlRead {
    class Parsed(
        val url: HopUrl,
    ) : HopUrlRead()

    class Refused(
        val failure: StrictUrlFailure,
        val detail: String,
    ) : HopUrlRead()
}
