// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.FakeX509Certificate
import dev.revokt.PathBuilderFallback
import dev.revokt.PathStatus
import dev.revokt.PkixPathBuilderFallback
import dev.revokt.PkixPki
import dev.revokt.PlatformTrust
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.PlatformRead
import dev.revokt.engine.parse.producer.ProducerCorpus
import dev.revokt.verify.JcaSignatureVerifier
import okio.ByteString.Companion.toByteString
import java.security.KeyStore
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Spec §5.1 "Anchor snapshot" and §4 `AnchorSnapshot` on the JVM: [AnchorSnapshots.build] over a delegate's
 * `getAcceptedIssuers()`, each anchor read through the §9.2 read fallback; and the PKIX fallback over the result, which
 * a walk the canonicaliser misleads falls back to (§10 residual 1).
 */
@OptIn(RevoktInternalApi::class)
class AnchorSnapshotsTest {
    /** A [PlatformTrust] whose anchors are [anchors]; [canonical] replaces the canonicaliser when set. */
    private class FakeTrust(
        private val anchors: () -> List<X509Certificate>,
        private val canonical: ((ByteArray) -> String?)? = null,
    ) : PlatformTrust {
        override fun defaultDelegate(): X509TrustManager = error("unused")

        override fun requiresExtendedDelegate(): Boolean = true

        override fun verifiedChain(
            delegate: X509TrustManager,
            chain: Array<X509Certificate>,
            host: String?,
        ): List<X509Certificate>? = null

        override fun pathBuilder(): PathBuilderFallback = PkixPathBuilderFallback()

        override fun anchors(delegate: X509TrustManager): List<X509Certificate> = anchors()

        override fun canonicalSubject(nameDer: ByteArray): String? =
            canonical?.invoke(nameDer) ?: super.canonicalSubject(nameDer)
    }

    private val delegate = jdkDelegate()

    private fun build(
        vararg certificates: X509Certificate,
        now: Long = 7,
    ): IndexedSnapshot = AnchorSnapshots.build(FakeTrust({ certificates.toList() }), delegate, now)

    @Test
    fun `anchors the JDK's default trust store gives a snapshot of every anchor and an index of every parsable one`() {
        val issuers = delegate.acceptedIssuers
        val built = AnchorSnapshots.build(FakeTrust({ delegate.acceptedIssuers.toList() }), delegate, 42)
        val reads = issuers.map { checkNotNull(PlatformRead.of(it)) }
        assertEquals(issuers.size, built.snapshot.anchors.size)
        assertEquals(reads.map { it.read.toByteString() }, built.snapshot.anchors.map { it.toByteString() })
        assertEquals(reads.map { it.encoded.toByteString() }, built.snapshot.platformEncodings)
        val parsable = reads.filter { CertificateParser.parse(it.read) is CertificateParse.Parsed }
        assertTrue(parsable.isNotEmpty(), "the JDK ships anchors revokt parses")
        assertEquals(
            parsable.map { it.read.toByteString().sha256() }.toSet(),
            built.index.store
                .map { it.bytesHash }
                .toSet(),
        )
        assertEquals(42, built.snapshot.createdMillis)
    }

    @Test
    fun `anchors sha256 is over the sorted distinct bytes read, whatever the order and duplicates`() {
        val a = PkixPki.root("Snapshot Root A").x509
        val b = PkixPki.root("Snapshot Root B").x509
        val one = build(a, b).snapshot
        val two = build(b, a, b).snapshot
        assertContentEquals(one.sha256, two.sha256)
        assertEquals(3, two.anchors.size, "anchors keep the platform's list")
        val sorted = listOf(a.encoded, b.encoded).map { it.toByteString() }.sorted()
        assertEquals(
            okio
                .Buffer()
                .write(sorted[0])
                .write(sorted[1])
                .sha256(),
            one.sha256.toByteString(),
        )
        assertNotEquals(one.sha256.toByteString(), build(a).snapshot.sha256.toByteString())
    }

    @Test
    fun `anchors ids advance on every build`() {
        val a = PkixPki.root("Snapshot Root Ids").x509
        val first = build(a).snapshot.id
        val second = build(a).snapshot.id
        assertTrue(second > first, "$second after $first")
    }

    @Test
    fun `anchors an empty, null or throwing anchor set throws IllegalStateException from the builder`() {
        val empty = assertFailsWith<IllegalStateException> { build() }
        assertNull(empty.cause, "empty")
        assertTrue(empty.message!!.contains("no trust anchors"), empty.message)
        val none =
            assertFailsWith<IllegalStateException> { AnchorSnapshots.build(FakeTrust({ nullList() }), delegate, 0) }
        assertNull(none.cause, "a null list is the empty set, not a throw")
        val cause = IllegalArgumentException("store unreadable")
        val thrown =
            assertFailsWith<IllegalStateException> { AnchorSnapshots.build(FakeTrust({ throw cause }), delegate, 0) }
        assertSame(cause, thrown.cause)
        val withNull = listOf(PkixPki.root("Null Neighbour").x509, nullCertificate())
        val held =
            assertFailsWith<IllegalStateException> { AnchorSnapshots.build(FakeTrust({ withNull }), delegate, 0) }
        assertNull(held.cause, "a null anchor")
        assertTrue(held.message!!.contains("null"), held.message)
    }

    @Test
    fun `anchors an interrupt from getAcceptedIssuers keeps the flag, a fatal error escapes as it is`() {
        try {
            assertFailsWith<IllegalStateException> {
                AnchorSnapshots.build(FakeTrust({ throw InterruptedException() }), delegate, 0)
            }
            assertTrue(Thread.interrupted(), "the interrupt flag is restored")
        } finally {
            Thread.interrupted()
        }
        assertFailsWith<OutOfMemoryError> {
            AnchorSnapshots.build(
                FakeTrust({ throw OutOfMemoryError() }),
                delegate,
                0,
            )
        }
    }

    @Test
    fun `anchors a set none of which parses throws, one whose getEncoded throws is left out`() {
        val unparsable = FakeX509Certificate(encoded = { byteArrayOf(0x30, 0x00) })
        assertFailsWith<IllegalStateException> { build(unparsable) }
        val noBytes = FakeX509Certificate(encoded = { throw CertificateEncodingException("gone") })
        val root = PkixPki.root("Snapshot Root Kept").x509
        val built = build(noBytes, root, unparsable)
        assertEquals(
            listOf(root.encoded, byteArrayOf(0x30, 0x00)).map {
                it.toByteString()
            },
            built.snapshot.anchors.map { it.toByteString() },
        )
        assertEquals(1, built.index.store.size)
    }

    @Test
    fun `anchors an anchor read through the platform canon keeps its getEncoded for the PKIX fallback`() {
        val bad =
            PkixPki.x509(
                ProducerCorpus.inputs.first { it.name == "envelope/letsencrypt.org-1/tbs-indefinite-serial-81" }.der,
            )
        val read = checkNotNull(PlatformRead.of(bad))
        assertTrue(read.platformCanon)
        val root = PkixPki.root("Snapshot Root Canon").x509
        val built = build(bad, root)
        assertEquals(listOf(read.read, root.encoded).map { it.toByteString() }, built.snapshot.anchors.map { it.toByteString() })
        assertEquals(listOf(bad.encoded, root.encoded).map { it.toByteString() }, built.snapshot.platformEncodings)
        assertTrue(built.index.isAnchorBytes(built.index.cert(CertificateParser.parse(read.read).let { (it as CertificateParse.Parsed).certificate })))
    }

    @Test
    fun `anchors the index relates by the platform trust's canonicaliser`() {
        val root = PkixPki.root("Snapshot Canonical").x509
        val built = AnchorSnapshots.build(FakeTrust({ listOf(root) }, canonical = { "same" }), delegate, 0)
        assertEquals(
            "same",
            built.index.store
                .single()
                .canonicalSubject,
        )
    }

    @Test
    fun `anchors a misled canonicaliser leaves the link to the PKIX fallback`() {
        val root = PkixPki.root("Residual Root")
        val intermediate = PkixPki.issue("Residual Intermediate", root, ca = true)
        val leaf =
            PkixPki.issue(
                "leaf.residual.example",
                intermediate,
                ca = false,
                issuerName = PkixPki.name("Residual Intermediate", printable = true),
            )
        val chain = listOf(leaf.der, intermediate.der)

        fun decision(canonical: ((ByteArray) -> String?)?): PathDecisionView {
            val built = AnchorSnapshots.build(FakeTrust({ listOf(root.x509) }, canonical = canonical), delegate, 0)
            val verifier = JcaSignatureVerifier()
            val context =
                DecideContext(
                    verifier,
                    verifier.unsupportedOids(),
                    lruMap(RevoktLimits.CROSS_CALL_MEMO_ENTRIES),
                    PkixPathBuilderFallback(),
                    PkixPki.NOW,
                    platformOnly = true,
                )
            val d = decide(chain, built.index, built.snapshot, context)
            return PathDecisionView(d.path.status, d.detail.usedFallback, d.issuerKeys)
        }
        val intermediateKey =
            intermediate.keys.public.encoded
                .toByteString()
                .sha256()
        val canonical = decision(canonical = null)
        assertEquals(
            PathDecisionView(PathStatus.FOUND, false, listOf(intermediateKey)),
            canonical,
            "related canonically",
        )
        // A canonicaliser that never matches: the respelled issuer is unrelated, and the walk ends NotFound.
        val misled = decision(canonical = { "unrelated-" + it.toByteString().hex() })
        assertEquals(PathDecisionView(PathStatus.FOUND, true, listOf(intermediateKey)), misled, "the fallback's path")
    }

    private data class PathDecisionView(
        val status: PathStatus,
        val usedFallback: Boolean,
        val keys: List<okio.ByteString>,
    )

    private companion object {
        fun jdkDelegate(): X509TrustManager {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(null as KeyStore?)
            return factory.trustManagers.filterIsInstance<X509TrustManager>().first()
        }

        /** A null where Kotlin's types allow none, as a Java delegate or platform trust may return one. */
        @Suppress("UNCHECKED_CAST")
        fun <T> javaNull(): T = null as T

        fun nullList(): List<X509Certificate> = javaNull()

        fun nullCertificate(): X509Certificate = javaNull()
    }
}
