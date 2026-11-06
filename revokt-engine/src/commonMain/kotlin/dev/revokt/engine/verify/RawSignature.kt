// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

/**
 * The content signature's `signature` field (spec §7.1, §6.5 "Seed archive"): unpadded base64url of the raw ECDSA pair
 * `r ‖ s`, two halves of equal length, big-endian. The rules follow Firefox's `ContentSignatureVerifier` (maintainer
 * decision on #163, Firefox parity): any non-empty even length is a pair, so a P-256, P-384 or P-521 leaf's signature
 * decodes (P-384's is 96 bytes, 128 characters), and the leaf's key decides whether it verifies. [toDer] is the one
 * crypto routine written in Kotlin (spec §10): the raw pair as the DER `ECDSA-Sig-Value` that `SHA384withECDSA` takes.
 */
internal object RawSignature {
    /** P-521's `r ‖ s`, the largest pair any supported curve signs (2 × 66 bytes); Firefox sets no cap. */
    const val MAX_RAW_BYTES = 132

    private const val MAX_TEXT_CHARS = (MAX_RAW_BYTES * 4 + 2) / 3

    /**
     * The raw pair [text] encodes, or null when it is not unpadded base64url (RFC 4648 §5: `A-Z a-z 0-9 - _`, no `=`)
     * of a non-empty even number of bytes up to [MAX_RAW_BYTES]. As in Firefox, a final partial group of two or three
     * characters is read and its unused low bits are not checked.
     */
    fun decode(text: String): ByteArray? {
        if (text.length > MAX_TEXT_CHARS || text.length % 4 == 1) return null
        val size = text.length * 3 / 4
        if (size == 0 || size % 2 != 0) return null
        val out = ByteArray(size)
        var bits = 0
        var count = 0
        var o = 0
        for (c in text) {
            val v = value(c)
            if (v < 0) return null
            bits = (bits shl 6) or v
            count += 6
            if (count >= 8) {
                count -= 8
                out[o++] = (bits shr count).toByte()
            }
        }
        return out
    }

    private fun value(c: Char): Int =
        when (c) {
            in 'A'..'Z' -> c - 'A'
            in 'a'..'z' -> c - 'a' + 26
            in '0'..'9' -> c - '0' + 52
            '-' -> 62
            '_' -> 63
            else -> -1
        }

    /**
     * `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` (RFC 3279 §2.2.3) of [raw], whose first half is `r` and
     * second `s`: each a minimal non-negative INTEGER (leading zero bytes dropped, one `0x00` added when the high bit is
     * set, zero as the single byte `0x00`), as NSS's `DSAU_EncodeDerSigWithLen` writes it. An INTEGER is at most 67
     * bytes, so its length is one byte; the SEQUENCE's takes the `0x81` form from 128 bytes.
     */
    fun toDer(raw: ByteArray): ByteArray {
        require(raw.isNotEmpty() && raw.size % 2 == 0 && raw.size <= MAX_RAW_BYTES) {
            "an r ‖ s pair is an even 2 to $MAX_RAW_BYTES bytes"
        }
        val r = integer(raw, 0, raw.size / 2)
        val s = integer(raw, raw.size / 2, raw.size)
        val length = r.size + s.size
        val header =
            if (length < 0x80) byteArrayOf(0x30, length.toByte()) else byteArrayOf(0x30, 0x81.toByte(), length.toByte())
        return header + r + s
    }

    private fun integer(
        raw: ByteArray,
        from: Int,
        end: Int,
    ): ByteArray {
        var start = from
        while (start < end - 1 && raw[start] == 0.toByte()) start++
        val pad = if (raw[start] < 0) 1 else 0
        val out = ByteArray(2 + pad + end - start)
        out[0] = 0x02
        out[1] = (pad + end - start).toByte()
        raw.copyInto(out, 2 + pad, start, end)
        return out
    }
}
