// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSession

/**
 * The JDK fetcher's per-connection hostname verifier (spec §3: hostname verification is HttpsURLConnection's). With a
 * verifier that is not the JDK's default and no endpoint identification on the socket, `HttpsURLConnection` matches the
 * host against the session's peer certificate itself (`HostnameChecker`, RFC 2818) after every handshake, a resumed
 * one included, and asks the verifier only when that match fails. This one refuses, so a mismatch is an `IOException`
 * before the request is written, whatever `HttpsURLConnection.setDefaultHostnameVerifier` was given, as long as the
 * socket arrives with no endpoint identification ([TlsOnlySocketFactory] refuses one that does): forcing endpoint identification `HTTPS` on the socket instead would leave the check to the provider,
 * and Conscrypt resumes a session made under a laxer check without matching the name again. The match is the
 * two-argument `HostnameChecker.match`, without the trust manager's public-suffix wildcard rule.
 */
internal object RefusingHostnameVerifier : HostnameVerifier {
    override fun verify(
        hostname: String?,
        session: SSLSession?,
    ): Boolean = false
}
