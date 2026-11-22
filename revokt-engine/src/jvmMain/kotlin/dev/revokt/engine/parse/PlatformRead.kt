// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.ParseReason
import dev.revokt.RevoktInternalApi
import java.security.cert.X509Certificate

/**
 * One platform certificate as the JVM binding reads it (spec §9.2 "The read fallback", §5.3). [encoded] is
 * `getEncoded()`, over which the identity keys stay (the chain hash and the cache keys built on it). [read] is the bytes
 * the engine parses and hashes (`Cert.der`, `bytesHash`, the anchor-by-bytes check, `AnchorSnapshot.anchors`): the same
 * array as [encoded], or the **platform canon** where revokt's parse of [encoded] is `ParseFailed(STRUCTURE)`.
 *
 * The platform canon is `SEQUENCE { getTBSCertificate(), the TBS signature AlgorithmIdentifier TLV, BIT STRING { 00,
 * getSignature() } }` under minimal new headers: the bytes the JDK verifies the signature over, so a valid signature
 * makes it what the CA signed however the presented encoding was altered. `MAX_CERT_BYTES` is checked on [encoded]
 * before any parse (an oversize one stays [encoded], and parses as `OVERSIZE`) and again by the parser on [read].
 * Where the AlgorithmIdentifier cannot be located, or a getter throws, [read] stays [encoded]: a leaf is then
 * `PARSE_FAILED(STRUCTURE)` and a candidate or an anchor is dropped. `@RevoktInternalApi`: revokt-jsse's adapter and
 * the anchor snapshot are its callers (spec §3.1 item 4). Arrays are shared, not copied.
 */
@RevoktInternalApi
public class PlatformRead private constructor(
    public val encoded: ByteArray,
    public val read: ByteArray,
) {
    /** Whether [read] is the platform canon rather than [encoded]. */
    public val platformCanon: Boolean get() = read !== encoded

    @RevoktInternalApi
    public companion object {
        /**
         * [certificate] as read; null when `getEncoded()` throws or returns null, so the certificate has no bytes at all.
         */
        @Suppress("TooGenericExceptionCaught") // §9.2: a getter that throws leaves the bytes as they are
        public fun of(certificate: X509Certificate): PlatformRead? {
            val encoded: ByteArray =
                try {
                    certificate.encoded
                } catch (e: Exception) {
                    rethrowInterrupt(e)
                    null
                } ?: return null
            // The parser checks MAX_CERT_BYTES before it parses: an oversize certificate is OVERSIZE, never re-read.
            val parse = CertificateParser.parse(encoded)
            if (parse !is CertificateParse.Failed || parse.reason != ParseReason.STRUCTURE) {
                return PlatformRead(encoded, encoded)
            }
            val canon =
                try {
                    canon(certificate.tbsCertificate, certificate.signature)
                } catch (e: Exception) {
                    rethrowInterrupt(e)
                    null
                }
            return PlatformRead(encoded, canon ?: encoded)
        }

        /** No getter blocks, but one that wraps an interrupt keeps the flag. */
        private fun rethrowInterrupt(e: Exception) {
            if (e is InterruptedException) Thread.currentThread().interrupt()
        }

        /**
         * The platform canon of [tbs] (`getTBSCertificate()`) and [signature] (`getSignature()`), or null when the
         * locator finds no AlgorithmIdentifier. The locator reads one-octet identifiers and definite lengths of at most
         * four octets: after the TBS header it skips a first element with identifier `A0`, then one element, and takes
         * the next if its identifier is `30`. Lengths are bounded by [tbs], as the JDK hands it over. Never throws on
         * any input (a fuzz target, §9.1).
         */
        internal fun canon(
            tbs: ByteArray?,
            signature: ByteArray?,
        ): ByteArray? {
            if (tbs == null || signature == null) return null
            val algorithm = locate(tbs) ?: return null
            val bits = tlv(BIT_STRING, byteArrayOf(0) + signature)
            return tlv(SEQUENCE, tbs + algorithm + bits)
        }

        private fun locate(tbs: ByteArray): ByteArray? {
            var position = contentStart(tbs, 0) ?: return null
            val skips = if (position < tbs.size && tbs[position].toInt() and 0xff == VERSION) 2 else 1
            repeat(skips) { position = end(tbs, position) ?: return null }
            val end = end(tbs, position) ?: return null
            return if (tbs[position].toInt() and 0xff == SEQUENCE) tbs.copyOfRange(position, end) else null
        }

        /** Where the content of the element at [position] starts, or null when its header cannot be read. */
        private fun contentStart(
            b: ByteArray,
            position: Int,
        ): Int? = header(b, position)?.let { position + it.first }

        /** Where the element at [position] ends, or null when it cannot be read or runs past [b]. */
        private fun end(
            b: ByteArray,
            position: Int,
        ): Int? = header(b, position)?.let { (size, length) -> (position + size + length).toInt() }

        /**
         * The header at [position]: its size in octets and its content length. Null for a missing identifier or length
         * octet, an indefinite length, five or more length octets, and a content that runs past [b].
         */
        private fun header(
            b: ByteArray,
            position: Int,
        ): Pair<Int, Long>? {
            if (position < 0 || position + 1 >= b.size) return null
            val first = b[position + 1].toInt() and 0xff
            val count = if (first < LONG_FORM) 0 else first and LOW_SEVEN
            if (first == LONG_FORM || count > MAX_LENGTH_OCTETS || position + 2 + count > b.size) return null
            var length = if (count == 0) first.toLong() else 0L
            for (i in 0 until count) length = (length shl BYTE) or (b[position + 2 + i].toLong() and 0xff)
            val size = 2 + count
            return if (position + size + length <= b.size) size to length else null
        }

        private fun tlv(
            tag: Int,
            content: ByteArray,
        ): ByteArray = byteArrayOf(tag.toByte()) + minimalLength(content.size) + content

        private const val SEQUENCE = 0x30
        private const val BIT_STRING = 0x03
        private const val VERSION = 0xa0
        private const val LONG_FORM = 0x80
        private const val LOW_SEVEN = 0x7f
        private const val MAX_LENGTH_OCTETS = 4
        private const val BYTE = 8
    }
}
