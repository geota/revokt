// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse

import dev.revokt.PkixPathBuilderFallback
import dev.revokt.RevoktInternalApi
import dev.revokt.engine.walker.AnchorSnapshots
import java.security.cert.X509Certificate
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Spec §5.3 on [JvmPlatformTrust]: the default delegate is the default factory's `X509ExtendedTrustManager`, the same
 * instance on every call; an extended delegate is required; no verified chain; the PKIX fallback; the delegate's
 * anchors, a null array read as none; and the snapshot from the JDK's default trust store.
 */
@OptIn(RevoktInternalApi::class)
class JvmPlatformTrustTest {
    private val trust = JvmPlatformTrust()

    @Test
    fun `jvm the default delegate is the default factory's extended trust manager, memoised`() {
        val delegate = trust.defaultDelegate()
        assertIs<X509ExtendedTrustManager>(delegate)
        assertSame(delegate, trust.defaultDelegate())
        assertTrue(trust.requiresExtendedDelegate())
    }

    @Test
    fun `jvm no verified chain, one PKIX fallback, X500Principal's canonical names`() {
        val delegate = trust.defaultDelegate()
        assertNull(trust.verifiedChain(delegate, emptyArray(), "example.com"))
        assertIs<PkixPathBuilderFallback>(trust.pathBuilder())
        assertSame(trust.pathBuilder(), trust.pathBuilder())
        val name = X500Principal("CN=Example, O=Revokt")
        assertEquals(name.getName(X500Principal.CANONICAL), trust.canonicalSubject(name.encoded))
        assertNull(trust.canonicalSubject(byteArrayOf(0x30, 0x01)))
    }

    @Test
    fun `jvm anchors are getAcceptedIssuers, a null array none`() {
        val delegate = trust.defaultDelegate()
        assertEquals(delegate.acceptedIssuers.toList(), trust.anchors(delegate))
        assertEquals(emptyList(), trust.anchors(NullIssuers))
    }

    @Test
    fun `jvm the default trust store gives a snapshot of every anchor`() {
        val delegate = trust.defaultDelegate()
        val built = AnchorSnapshots.build(trust, delegate, 0)
        assertEquals(delegate.acceptedIssuers.size, built.snapshot.anchors.size)
    }

    private object NullIssuers : X509TrustManager {
        override fun checkClientTrusted(
            chain: Array<out X509Certificate>?,
            authType: String?,
        ) = Unit

        override fun checkServerTrusted(
            chain: Array<out X509Certificate>?,
            authType: String?,
        ) = Unit

        override fun getAcceptedIssuers(): Array<X509Certificate>? = null
    }
}
