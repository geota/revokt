// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

/**
 * The content signature's `signature` field (spec §7.1, §6.5 "Seed archive"): base64url without padding, exactly
 * [TEXT_CHARS] characters encoding the [RAW_BYTES] bytes of P-384 `r ‖ s`, each 48 bytes big-endian. [toDer] is the one
 * crypto routine written in Kotlin (spec §10): the raw pair as the DER `ECDSA-Sig-Value` that `SHA384withECDSA` takes.
 */
internal object RawSignature {
    const val RAW_BYTES = 96
    const val TEXT_CHARS = 128

    private const val HALF = RAW_BYTES / 2

    /**
     * The [RAW_BYTES] bytes [text] encodes, or null when it is not exactly [TEXT_CHARS] characters of the base64url
     * alphabet (RFC 4648 §5). There is no padding to accept: 96 bytes are 32 whole groups of four characters.
     */
    fun decode(text: String): ByteArray? {
        if (text.length != TEXT_CHARS) return null
        val out = ByteArray(RAW_BYTES)
        for (group in 0 until TEXT_CHARS / 4) {
            var bits = 0
            for (i in 0 until 4) {
                val v = value(text[group * 4 + i])
                if (v < 0) return null
                bits = (bits shl 6) or v
            }
            out[group * 3] = (bits shr 16).toByte()
            out[group * 3 + 1] = (bits shr 8).toByte()
            out[group * 3 + 2] = bits.toByte()
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
     * set, zero as the single byte `0x00`). Every length is below 128, so every DER length is one byte.
     */
    fun toDer(raw: ByteArray): ByteArray {
        require(raw.size == RAW_BYTES) { "a P-384 r ‖ s is $RAW_BYTES bytes" }
        val r = integer(raw, 0)
        val s = integer(raw, HALF)
        return byteArrayOf(0x30, (r.size + s.size).toByte()) + r + s
    }

    private fun integer(
        raw: ByteArray,
        from: Int,
    ): ByteArray {
        val end = from + HALF
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
