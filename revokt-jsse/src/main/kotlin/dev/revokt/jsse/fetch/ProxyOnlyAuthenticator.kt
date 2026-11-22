// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.net.Authenticator
import java.net.PasswordAuthentication

/**
 * The per-connection authenticator of the JDK fetcher (spec §4 `http`: "a per-connection
 * `HttpURLConnection.setAuthenticator` that answers `RequestorType.PROXY` only"). A proxy's challenge is passed to the
 * JVM's default authenticator, as the JDK would without it; a server's challenge is never answered, so a 401, even
 * from a trusted intercepting proxy, never reaches the default credentials (spec §3: no fetcher answers a challenge).
 * One object, so the JDK's per-authenticator keep-alive and auth caches stay keyed by one value.
 */
@JdkOnly
internal object ProxyOnlyAuthenticator : Authenticator() {
    override fun getPasswordAuthentication(): PasswordAuthentication? {
        if (requestorType != RequestorType.PROXY) return null
        val fallback = getDefault() ?: return null
        // The default can never be this object: it is only ever set per connection.
        return requestPasswordAuthentication(
            fallback,
            requestingHost,
            requestingSite,
            requestingPort,
            requestingProtocol,
            requestingPrompt,
            requestingScheme,
            requestingURL,
            requestorType,
        )
    }
}
