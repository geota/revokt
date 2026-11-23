// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

/**
 * What revokt needs from a platform's TLS stack (spec §3, §5.3): the default trust manager, its trust anchors, the PKIX
 * fallback and the name equality the walker relates certificates by. The JVM's is `JvmPlatformTrust` (revokt-jsse);
 * Android's is `AndroidPlatformTrust` (0.3). Both are final. `@RevoktInternalApi` in 0.2 (spec §3.1 item 4): the
 * binding wires `JvmPlatformTrust()` itself, and the type goes public with its first consumer outside revokt-engine and
 * revokt-jsse, the 0.3 Android binding.
 */
@RevoktInternalApi
public interface PlatformTrust {
    /** The platform's default trust manager, the delegate a `Revokt` captures at `build()`. */
    public fun defaultDelegate(): X509TrustManager

    /**
     * Whether a delegate must be an `X509ExtendedTrustManager`: true on every JVM binding, where fronting a plain one
     * would drop SunJSSE's algorithm constraints and endpoint identification (spec §5.3).
     */
    public fun requiresExtendedDelegate(): Boolean

    /**
     * The path [delegate] verified for [chain] and [host] (decision step 4, Android); null when this binding has none
     * to offer. A throw is a decision step 4 failure.
     */
    public fun verifiedChain(
        delegate: X509TrustManager,
        chain: Array<X509Certificate>,
        host: String?,
    ): List<X509Certificate>?

    /** Decision step 6's PKIX fallback (spec §5.1 "PKIX fallback contract"). */
    public fun pathBuilder(): PathBuilderFallback

    /** [delegate]'s trust anchors, `getAcceptedIssuers()`, from which the anchor snapshot is built (spec §5.1). */
    public fun anchors(delegate: X509TrustManager): List<X509Certificate>

    /**
     * The canonical form of a DER `Name` that two related certificates share, or null when there is none; by default
     * `X500Principal(nameDer).getName(CANONICAL)`, which is what SunJSSE's `X500Name.equals` compares. An override
     * changes which certificates are related, and an issuer it misclassifies is left to the PKIX fallback (spec §5.1
     * deferral rule, §10 residual 1).
     */
    public fun canonicalSubject(nameDer: ByteArray): String? = dev.revokt.canonicalSubject(nameDer)
}
