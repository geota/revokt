// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.jsse.fetch

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.Socket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.TimeZone
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager

/**
 * A test CA and its leaves, minted at test time with the test JDK's providers (EC P-256, ECDSA with SHA-256), and the
 * TLS contexts the loopback server and the fetcher use. Not a fixture format: nothing here is committed bytes.
 */
internal object TestPki {
    private const val DAY_MILLIS = 86_400_000L
    private val PASSWORD = "test".toCharArray()
    private val SERIALS = AtomicLong(1)

    val caKeys: KeyPair = ecKeys()
    val ca: X509Certificate =
        certificate(caKeys, "revokt test CA", caKeys.private, "revokt test CA", ca = true, san = null)

    /** A leaf for `127.0.0.1` (an iPAddress SAN), which every loopback test connects to. */
    val loopback: Leaf = leaf(sanIp = byteArrayOf(127, 0, 0, 1))

    /** A leaf whose only SAN is a DNS name that is not the host the fetcher dials. */
    val wrongHost: Leaf = leaf(sanDns = "not-this-host.example")

    class Leaf(
        val keys: KeyPair,
        val certificate: X509Certificate,
    )

    /** The server side: [leaf] and the CA as its chain. */
    fun serverContext(leaf: Leaf): SSLContext {
        val store = KeyStore.getInstance("PKCS12")
        store.load(null, null)
        store.setKeyEntry("leaf", leaf.keys.private, PASSWORD, arrayOf(leaf.certificate, ca))
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(store, PASSWORD)
        return SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
    }

    /** A PKIX trust manager over the test CA alone, recording each server check. */
    fun recordingTrustManager(): RecordingTrustManager {
        val store = KeyStore.getInstance("PKCS12")
        store.load(null, null)
        store.setCertificateEntry("ca", ca)
        val tmf = TrustManagerFactory.getInstance("PKIX")
        tmf.init(store)
        return RecordingTrustManager(tmf.trustManagers.single() as X509ExtendedTrustManager)
    }

    fun clientContext(trustManager: RecordingTrustManager): SSLContext =
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }

    private fun ecKeys(): KeyPair =
        KeyPairGenerator
            .getInstance("EC")
            .apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()

    private fun leaf(
        sanIp: ByteArray? = null,
        sanDns: String? = null,
    ): Leaf {
        val keys = ecKeys()
        val san = if (sanIp != null) Der.tlv(0x87, sanIp) else Der.tlv(0x82, requireNotNull(sanDns).encodeToByteArray())
        return Leaf(
            keys,
            certificate(keys, "revokt test leaf", caKeys.private, "revokt test CA", ca = false, san = san),
        )
    }

    private fun certificate(
        subjectKeys: KeyPair,
        subject: String,
        issuerKey: PrivateKey,
        issuer: String,
        ca: Boolean,
        san: ByteArray?,
    ): X509Certificate {
        val ecdsaSha256 = Der.seq(Der.oid("1.2.840.10045.4.3.2"))
        val now = System.currentTimeMillis()
        val extensions =
            buildList {
                if (ca) {
                    add(Der.extension("2.5.29.19", critical = true, Der.seq(Der.tlv(0x01, byteArrayOf(-1)))))
                    // keyCertSign and cRLSign
                    add(Der.extension("2.5.29.15", critical = true, Der.tlv(0x03, byteArrayOf(1, 0x06))))
                } else {
                    // digitalSignature
                    add(Der.extension("2.5.29.15", critical = true, Der.tlv(0x03, byteArrayOf(7, 0x80.toByte()))))
                    add(Der.extension("2.5.29.37", critical = false, Der.seq(Der.oid("1.3.6.1.5.5.7.3.1"))))
                    add(Der.extension("2.5.29.17", critical = false, Der.seq(requireNotNull(san))))
                }
            }
        val tbs =
            Der.seq(
                Der.tlv(0xA0, Der.integer(BigInteger.valueOf(2))),
                Der.integer(BigInteger.valueOf(now).add(BigInteger.valueOf(SERIALS.getAndIncrement()))),
                ecdsaSha256,
                Der.name(issuer),
                Der.seq(Der.utcTime(Date(now - DAY_MILLIS)), Der.utcTime(Date(now + DAY_MILLIS))),
                Der.name(subject),
                subjectKeys.public.encoded,
                Der.tlv(0xA3, Der.seq(*extensions.toTypedArray())),
            )
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(issuerKey) }
        signature.update(tbs)
        val der = Der.seq(tbs, ecdsaSha256, Der.tlv(0x03, byteArrayOf(0) + signature.sign()))
        return CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
    }

    /** Just enough DER for the certificates above. */
    private object Der {
        fun tlv(
            tag: Int,
            vararg content: ByteArray,
        ): ByteArray {
            val body = ByteArrayOutputStream().apply { content.forEach { write(it) } }.toByteArray()
            return byteArrayOf(tag.toByte()) + length(body.size) + body
        }

        fun seq(vararg parts: ByteArray): ByteArray = tlv(0x30, *parts)

        fun integer(value: BigInteger): ByteArray = tlv(0x02, value.toByteArray())

        fun oid(dotted: String): ByteArray {
            val arcs = dotted.split('.').map { it.toLong() }
            val out = ByteArrayOutputStream()
            out.write((arcs[0] * 40 + arcs[1]).toInt())
            for (arc in arcs.drop(2)) {
                val groups = ArrayList<Int>()
                var v = arc
                do {
                    groups.add((v and 0x7F).toInt())
                    v = v shr 7
                } while (v > 0)
                for (i in groups.indices.reversed()) out.write(if (i > 0) groups[i] or 0x80 else groups[i])
            }
            return tlv(0x06, out.toByteArray())
        }

        fun name(cn: String): ByteArray = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0C, cn.encodeToByteArray()))))

        fun utcTime(date: Date): ByteArray {
            val format = SimpleDateFormat("yyMMddHHmmss'Z'").apply { timeZone = TimeZone.getTimeZone("UTC") }
            return tlv(0x17, format.format(date).encodeToByteArray())
        }

        fun extension(
            oid: String,
            critical: Boolean,
            value: ByteArray,
        ): ByteArray =
            if (critical) {
                seq(oid(oid), tlv(0x01, byteArrayOf(-1)), tlv(0x04, value))
            } else {
                seq(oid(oid), tlv(0x04, value))
            }

        private fun length(n: Int): ByteArray =
            when {
                n < 0x80 -> byteArrayOf(n.toByte())
                n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
                else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
            }
    }
}

/** A trust manager that delegates to [delegate] and records every server-side check it is asked for. */
internal class RecordingTrustManager(
    private val delegate: X509ExtendedTrustManager,
) : X509ExtendedTrustManager() {
    val serverChecks: MutableList<String> = Collections.synchronizedList(ArrayList())

    override fun checkServerTrusted(
        chain: Array<out X509Certificate>,
        authType: String,
        socket: Socket?,
    ) {
        serverChecks.add(chain[0].subjectX500Principal.name)
        delegate.checkServerTrusted(chain, authType, socket)
    }

    override fun checkServerTrusted(
        chain: Array<out X509Certificate>,
        authType: String,
        engine: SSLEngine?,
    ) {
        serverChecks.add(chain[0].subjectX500Principal.name)
        delegate.checkServerTrusted(chain, authType, engine)
    }

    override fun checkServerTrusted(
        chain: Array<out X509Certificate>,
        authType: String,
    ) {
        serverChecks.add(chain[0].subjectX500Principal.name)
        delegate.checkServerTrusted(chain, authType)
    }

    override fun checkClientTrusted(
        chain: Array<out X509Certificate>,
        authType: String,
        socket: Socket?,
    ): Unit = delegate.checkClientTrusted(chain, authType, socket)

    override fun checkClientTrusted(
        chain: Array<out X509Certificate>,
        authType: String,
        engine: SSLEngine?,
    ): Unit = delegate.checkClientTrusted(chain, authType, engine)

    override fun checkClientTrusted(
        chain: Array<out X509Certificate>,
        authType: String,
    ): Unit = delegate.checkClientTrusted(chain, authType)

    override fun getAcceptedIssuers(): Array<X509Certificate> = delegate.acceptedIssuers
}
