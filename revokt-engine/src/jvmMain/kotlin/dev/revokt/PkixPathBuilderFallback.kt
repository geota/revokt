// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import java.io.ByteArrayInputStream
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathBuilderException
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Date
import java.util.IdentityHashMap

/**
 * Decision step 6's PKIX fallback over the platform's own `CertPathBuilder("PKIX")` (spec §5.1 "PKIX fallback
 * contract", §5.3); Android runs the same class through ojluni's builder with Conscrypt doing signatures.
 *
 * - **Anchors:** the snapshot's platform encodings (`getEncoded()`) are re-parsed with `CertificateFactory` once per
 *   `AnchorSnapshot.id`, memoised for the last [MEMO_SIZE] ids, into one base `PKIXBuilderParameters`
 *   (`setRevocationEnabled(false)`, `setPolicyQualifiersRejected(false)`, every other parameter the JDK default, as
 *   SunJSSE's `PKIXValidator` leaves them); an anchor the factory rejects is left out, and with none left every build
 *   returns null.
 * - **Each build** clones the base, sets `setDate(nowMillis)` and the target `X509CertSelector` on the leaf, adds a
 *   `CollectionCertStore` holding every presented certificate the factory reads, the leaf included (one it rejects is
 *   left out, as webpki and mozilla::pkix skip a candidate that does not parse), and runs a fresh
 *   `CertPathBuilder.getInstance("PKIX")`. A leaf the factory rejects, or no path (`CertPathBuilderException`), is
 *   null; any other throw propagates, which decide counts as a failed build and caches nowhere.
 * - **The result** lists the leaf first, as the presented leaf's exact bytes (decide requires them), then each
 *   intermediate as the presented bytes it was read from (its `getEncoded()` only when the builder found it elsewhere,
 *   through AIA), then **the trust anchor's certificate** as the snapshot's bytes read for it (`AnchorSnapshot.anchors`),
 *   which decide matches against the index by exact bytes.
 * - **AIA** (spec §10 item 13): it neither sets nor clears `com.sun.security.enableAIAcaIssuers`; with it set, the JDK's
 *   builder fetches issuers over the network, and decide applies its issuer rules to whatever comes back.
 *
 * Thread-safe; one instance serves every snapshot.
 */
public class PkixPathBuilderFallback : PathBuilderFallback {
    /** One snapshot's anchors as the builder takes them: null [base] when none of them parses. */
    private class Anchors(
        val base: PKIXBuilderParameters?,
        val bytesRead: IdentityHashMap<X509Certificate, ByteArray>,
    )

    private val memo =
        object : LinkedHashMap<Long, Anchors>(MEMO_SIZE, LOAD_FACTOR, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, Anchors>?): Boolean = size > MEMO_SIZE
        }

    /** How many times the anchors of a snapshot were parsed; for the memo's tests. */
    @Volatile
    internal var anchorParses: Int = 0
        private set

    override fun build(
        chainDer: List<ByteArray>,
        anchors: AnchorSnapshot,
        nowMillis: Long,
    ): List<ByteArray>? {
        val factory = CertificateFactory.getInstance("X.509")
        val leaf: X509Certificate = chainDer.firstOrNull()?.let { x509(factory, it) } ?: return null
        // Each certificate the factory reads, by identity, to the bytes presented for it.
        val presented = IdentityHashMap<X509Certificate, ByteArray>()
        presented[leaf] = chainDer[0]
        for (i in 1 until chainDer.size) x509(factory, chainDer[i])?.let { presented[it] = chainDer[i] }
        val known = anchorsOf(anchors)
        val params = known.base?.clone() as PKIXBuilderParameters? ?: return null
        params.date = Date(nowMillis)
        params.targetCertConstraints = X509CertSelector().apply { certificate = leaf }
        params.addCertStore(CertStore.getInstance("Collection", CollectionCertStoreParameters(presented.keys.toList())))
        val result =
            try {
                CertPathBuilder.getInstance("PKIX").build(params) as PKIXCertPathBuilderResult
            } catch (_: CertPathBuilderException) {
                return null
            }
        val anchor = result.trustAnchor.trustedCert ?: return null
        val path = result.certPath.certificates.map { it as X509Certificate }
        return buildList {
            add(chainDer[0])
            path.drop(1).forEach { add(presented[it] ?: it.encoded) }
            add(known.bytesRead[anchor] ?: anchor.encoded)
        }
    }

    private fun anchorsOf(snapshot: AnchorSnapshot): Anchors =
        synchronized(memo) {
            memo.getOrPut(snapshot.id) {
                anchorParses++
                val factory = CertificateFactory.getInstance("X.509")
                val bytesRead = IdentityHashMap<X509Certificate, ByteArray>()
                val read = snapshot.anchors
                snapshot.platformEncodings.forEachIndexed { i, encoding ->
                    x509(factory, encoding.toByteArray())?.let { bytesRead[it] = read[i] }
                }
                val base =
                    bytesRead.keys.takeIf { it.isNotEmpty() }?.let { certs ->
                        PKIXBuilderParameters(certs.map { TrustAnchor(it, null) }.toSet(), null).apply {
                            isRevocationEnabled = false
                            policyQualifiersRejected = false
                        }
                    }
                Anchors(base, bytesRead)
            }
        }

    /** [der] as the platform's factory reads it; null where it rejects it, whatever it throws (§9.2 oracle 1). */
    @Suppress("TooGenericExceptionCaught") // a provider's parser may throw any runtime exception on hostile bytes
    private fun x509(
        factory: CertificateFactory,
        der: ByteArray,
    ): X509Certificate? =
        try {
            factory.generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
        } catch (_: CertificateException) {
            null
        } catch (_: RuntimeException) {
            null
        }
}

/** How many snapshots' anchors one instance keeps parsed: the live one and a few being replaced. */
private const val MEMO_SIZE = 8

private const val LOAD_FACTOR = 0.75f
