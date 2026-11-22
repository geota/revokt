// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse

import dev.revokt.PathBuilderFallback
import dev.revokt.PkixPathBuilderFallback
import dev.revokt.PlatformTrust
import dev.revokt.RevoktInternalApi
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

/**
 * The JVM's [PlatformTrust] (spec §3, §5.3).
 *
 * - [defaultDelegate] is the default `TrustManagerFactory`'s `X509ExtendedTrustManager` over the default trust store
 *   (`TrustManagerFactory.getDefaultAlgorithm()`, `init(null as KeyStore?)`, the providers in their configured order:
 *   SunJSSE's on a stock JDK, a FIPS provider where one is configured, as the JDK's own default `SSLContext` resolves
 *   it), created on first use and the same instance afterwards; `IllegalStateException` when the factory offers none.
 * - [requiresExtendedDelegate] is true: SunJSSE applies algorithm constraints and endpoint identification only to an
 *   `X509ExtendedTrustManager`, so fronting a plain one would drop them.
 * - [verifiedChain] is null: the JDK's trust manager exposes no verified path; every chain is `RECONSTRUCTED`.
 * - [pathBuilder] is one [PkixPathBuilderFallback], `CertPathBuilder("PKIX")` over the snapshot's anchors.
 * - [anchors] is the delegate's `getAcceptedIssuers()`; a null array is the empty set.
 * - `canonicalSubject` is the interface default, `X500Principal.getName(CANONICAL)`.
 *
 * `@RevoktInternalApi` in 0.2: `Revokt` wires it itself and has no public `platformTrust(…)` member yet.
 */
@RevoktInternalApi
public class JvmPlatformTrust : PlatformTrust {
    private val delegate: X509ExtendedTrustManager by lazy {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        checkNotNull(factory.trustManagers.filterIsInstance<X509ExtendedTrustManager>().firstOrNull()) {
            "the default TrustManagerFactory (${factory.algorithm}, ${factory.provider.name}) offers no " +
                "X509ExtendedTrustManager (spec §5.3)"
        }
    }

    private val fallback = PkixPathBuilderFallback()

    override fun defaultDelegate(): X509TrustManager = delegate

    override fun requiresExtendedDelegate(): Boolean = true

    override fun verifiedChain(
        delegate: X509TrustManager,
        chain: Array<X509Certificate>,
        host: String?,
    ): List<X509Certificate>? = null

    override fun pathBuilder(): PathBuilderFallback = fallback

    override fun anchors(delegate: X509TrustManager): List<X509Certificate> {
        val issuers: Array<X509Certificate>? = delegate.acceptedIssuers
        return issuers?.toList().orEmpty()
    }
}
