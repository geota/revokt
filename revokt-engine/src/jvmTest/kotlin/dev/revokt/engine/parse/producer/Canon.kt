// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse.producer

import java.io.ByteArrayOutputStream

/**
 * `canon(encoded)` of spec §9.2 (revision 35), written independently of revokt's parser until #12's oracle 3b exists:
 * `SEQUENCE { the TBS re-encoded by the unsigned-header rule, the signature AlgorithmIdentifier taken from that TBS, a
 * BIT STRING with zero unused bits holding the signatureValue content after its unused-bits octet }`. The TBS and
 * the signatureValue are re-encoded as the JDK's `DerIndefLenConverter` does, here by straightforward recursion, which
 * is fine for test inputs. Null when the envelope cannot be located.
 */
internal object Canon {
    private class Element(
        val tag: Int,
        val content: ByteArray,
        val end: Int,
    )

    fun of(der: ByteArray): ByteArray? =
        runCatching {
            val certificate = definite(der, 0, der.size)
            require(certificate.end == der.size && certificate.tag == 0x30)
            val start = der.size - certificate.content.size
            val tbs = element(der, start, der.size)
            val algorithm = element(der, tbs.end, der.size)
            val signature = element(der, algorithm.end, der.size)
            require(tbs.tag == 0x30 && algorithm.tag == 0x30 && signature.tag == 0x03 && signature.end == der.size)
            val tbsTlv = tlv(0x30, tbs.content)
            tlv(
                0x30,
                tbsTlv + signatureAlgorithm(tbsTlv) +
                    tlv(0x03, byteArrayOf(0) + signature.content.drop(1).toByteArray()),
            )
        }.getOrNull()

    /** The element at [p]: definite in any form, or indefinite and re-encoded. */
    private fun element(
        b: ByteArray,
        p: Int,
        limit: Int,
    ): Element {
        require(limit - p >= 2)
        if (b[p + 1].toInt() and 0xff != 0x80) return definite(b, p, limit)
        val (content, end) = indefiniteContent(b, p + 2, limit)
        return Element(b[p].toInt() and 0xff, content, end)
    }

    private fun definite(
        b: ByteArray,
        p: Int,
        limit: Int,
    ): Element {
        val first = b[p + 1].toInt() and 0xff
        var q = p + 2
        var length = first.toLong()
        if (first >= 0x80) {
            require(first != 0x80 && first != 0xff)
            length = 0
            repeat(first and 0x7f) {
                length = (length shl 8) or (b[q++].toLong() and 0xff)
                require(length <= limit)
            }
        }
        require(length <= limit - q)
        return Element(b[p].toInt() and 0xff, b.copyOfRange(q, q + length.toInt()), q + length.toInt())
    }

    /** Reads TLVs from [p] to the end-of-contents; nested indefinite TLVs re-encoded, definite ones copied whole. */
    private fun indefiniteContent(
        b: ByteArray,
        p: Int,
        limit: Int,
    ): Pair<ByteArray, Int> {
        val out = ByteArrayOutputStream()
        var q = p
        while (true) {
            require(limit - q >= 2)
            if (b[q].toInt() == 0 && b[q + 1].toInt() == 0) return out.toByteArray() to q + 2
            val lengthOctet = b[q + 1].toInt() and 0xff
            if (lengthOctet == 0x80) {
                val (inner, end) = indefiniteContent(b, q + 2, limit)
                out.write(tlv(b[q].toInt() and 0xff, inner))
                q = end
            } else {
                require(lengthOctet < 0x80 || lengthOctet in 0x81..0x84)
                val e = definite(b, q, limit)
                val headerLength = e.end - q - e.content.size
                require(headerLength == 2 || (e.content.size >= 0x80 && b[q + 2].toInt() != 0)) { "non-minimal length" }
                out.write(b, q, e.end - q)
                q = e.end
            }
        }
    }

    /** The TBS `signature` AlgorithmIdentifier: the element after the optional `[0]` and the serial. */
    private fun signatureAlgorithm(tbs: ByteArray): ByteArray {
        val content = definite(tbs, 0, tbs.size)
        var p = tbs.size - content.content.size
        if (tbs[p].toInt() and 0xff == 0xa0) p = definite(tbs, p, tbs.size).end
        p = definite(tbs, p, tbs.size).end
        val algorithm = definite(tbs, p, tbs.size)
        return tbs.copyOfRange(p, algorithm.end)
    }

    private fun tlv(
        tag: Int,
        content: ByteArray,
    ): ByteArray {
        val n = content.size
        val length =
            when {
                n < 0x80 -> byteArrayOf(n.toByte())
                n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
                n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
                else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
            }
        return byteArrayOf(tag.toByte()) + length + content
    }
}
