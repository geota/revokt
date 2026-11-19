// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

/**
 * The host rule of spec §7.1 over [MozillaRemoteSettings.allowedDomains][dev.revokt.MozillaRemoteSettings.allowedDomains]:
 * a host is allowed when it equals a domain or ends with `.` and a domain, on a label boundary, compared exactly, ASCII
 * case included. It applies to an x5u host after the rewrite ([X5uUrl]) and to the server's attachment base URL
 * ([AttachmentBase]).
 */
internal object AllowedDomains {
    fun allows(
        host: String,
        domains: Set<String>,
    ): Boolean = domains.any { host == it || host.endsWith(".$it") }
}

/**
 * The server root's `capabilities.attachments.base_url` (spec §7.1), read as [StrictUrl] reads a URL: `https://` in
 * lowercase, no userinfo, a DNS host name (never an IP literal) that [AllowedDomains] allows, no port or port 443, then
 * no path or a path of RFC 3986 `pchar`s and `/` with no query or fragment, since a location is joined after it. What is used is
 * re-serialised from the parts: `https://`, the host, the path; an explicit `:443` is dropped.
 */
internal object AttachmentBase {
    /** The base to join locations to; [reject] is called with why when [url] is refused. */
    inline fun check(
        url: String,
        domains: Set<String>,
        reject: (String) -> Nothing,
    ): String {
        val read =
            when (val strict = StrictUrl.parse(url)) {
                is StrictUrlRead.Parsed -> strict
                is StrictUrlRead.Refused -> reject("${strict.failure}: ${strict.detail}")
            }
        if (read.port != null && read.port != "443") reject("port \"${read.port}\"")
        val path = read.rest
        if (!isPlainPath(path)) reject("not a plain path")
        if (!AllowedDomains.allows(read.host, domains)) reject("host \"${read.host}\" is not under allowedDomains")
        return "https://" + read.host + path
    }

    /** Empty, or `/` and then `pchar`s and `/` only, with no query. */
    fun isPlainPath(path: String): Boolean =
        path.isEmpty() || (path.startsWith('/') && '?' !in path && StrictUrl.isPathAndQuery(path))
}
