// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.RevoktLimits

internal sealed class X5uPemRead {
    /** The DER of each block, in body order (leaf first, spec §6.5); never empty. */
    class Certificates(
        val ders: List<ByteArray>,
    ) : X5uPemRead()

    class Failed(
        val reason: X5uPemFailure,
        val detail: String,
    ) : X5uPemRead()
}

internal enum class X5uPemFailure {
    /** The body is over the cap; nothing was decoded. */
    OVERSIZE,

    /** A line that is not where a boundary, a base64 line or the end of the body must be, or no block at all. */
    FRAMING,

    /** A base64 line of the wrong length, alphabet or padding. */
    BASE64,
}

/**
 * The x5u body as served (spec §7.1 "x5u chain", §6.5 `x5u.pem`): one or more `CERTIFICATE` blocks in RFC 7468's
 * strict form, the form Go's `pem.Encode` writes and Mozilla serves. The cap is checked before anything is decoded.
 * A body is a sequence of blocks with nothing before, between or after them; each line ends in LF or CRLF, except that
 * the last `END` line may end the body. A block is `-----BEGIN CERTIFICATE-----`, base64 lines of exactly 64
 * characters, a last line of 4 to 64 characters (a multiple of 4, `=` padding only at its end, the padding bits zero),
 * and `-----END CERTIFICATE-----`. Anything else, a header line or a blank line included, is [X5uPemRead.Failed].
 * The DER is not parsed here.
 */
internal object X5uPem {
    private const val BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val END = "-----END CERTIFICATE-----"
    private const val LINE = 64
    private const val QUANTUM = 4
    private const val LF = '\n'.code.toByte()
    private const val CR = '\r'.code.toByte()
    private const val PAD = '='.code
    private const val SEXTET = 6
    private const val OCTET = 8
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /** Each ASCII code's sextet, or -1 outside the alphabet. */
    private val SEXTETS = IntArray(128) { -1 }.also { t -> ALPHABET.forEachIndexed { i, c -> t[c.code] = i } }

    fun read(
        body: ByteArray,
        maxBytes: Long = RevoktLimits.MAX_X5U_BYTES,
    ): X5uPemRead {
        if (body.size > maxBytes) return failed(X5uPemFailure.OVERSIZE, "${body.size} bytes, cap $maxBytes")
        val lines = lines(body)
        val ders = ArrayList<ByteArray>()
        var i = 0
        while (i < lines.size) {
            if (!lines[i].isText(body, BEGIN)) return failed(X5uPemFailure.FRAMING, "line ${i + 1} is not $BEGIN")
            val first = ++i
            while (i < lines.size && !lines[i].isText(body, END)) i++
            if (i == lines.size) return failed(X5uPemFailure.FRAMING, "no $END after line $first")
            if (i == first) return failed(X5uPemFailure.FRAMING, "an empty block at line $first")
            val der =
                decode(body, lines.subList(first, i)) ?: return failed(X5uPemFailure.BASE64, "the block at line $first")
            ders.add(der)
            i++
        }
        if (ders.isEmpty()) return failed(X5uPemFailure.FRAMING, "no block")
        return X5uPemRead.Certificates(ders)
    }

    private fun failed(
        reason: X5uPemFailure,
        detail: String,
    ) = X5uPemRead.Failed(reason, detail)

    /** Each line's span without its LF or CRLF; a body that ends in a line ending has no empty last line. */
    private fun lines(body: ByteArray): List<Span> {
        val out = ArrayList<Span>()
        var start = 0
        for (i in body.indices) {
            if (body[i] == LF) {
                out.add(Span(start, if (i > start && body[i - 1] == CR) i - 1 else i))
                start = i + 1
            }
        }
        if (start < body.size) out.add(Span(start, body.size))
        return out
    }

    private fun Span.isText(
        body: ByteArray,
        text: String,
    ): Boolean = length == text.length && text.indices.all { body[start + it].toInt() == text[it].code }

    /** The octets of [lines], or null when they are not strict base64 in 64-character lines. */
    private fun decode(
        body: ByteArray,
        lines: List<Span>,
    ): ByteArray? {
        val last = lines.last()
        if (lines.dropLast(1).any { it.length != LINE }) return null
        if (last.length !in QUANTUM..LINE || last.length % QUANTUM != 0) return null
        val chars = lines.sumOf { it.length }
        val pad =
            when {
                body[last.end - 1].toInt() != PAD -> 0
                body[last.end - 2].toInt() != PAD -> 1
                else -> 2
            }
        val out = ByteArray(chars / QUANTUM * 3 - pad)
        var bits = 0
        var pending = 0
        var n = 0
        for (line in lines) {
            val end = if (line === last) line.end - pad else line.end
            for (p in line.start until end) {
                // A byte is at most 127, so only a non-ASCII octet (negative) falls outside the table.
                val code = body[p].toInt()
                val sextet = if (code >= 0) SEXTETS[code] else -1
                if (sextet < 0) return null
                bits = (bits shl SEXTET) or sextet
                pending += SEXTET
                if (pending >= OCTET) {
                    pending -= OCTET
                    out[n++] = (bits shr pending).toByte()
                    bits = bits and ((1 shl pending) - 1)
                }
            }
        }
        // The canonical encoding: the bits after the last octet are zero (RFC 4648 §3.5).
        return if (bits == 0) out else null
    }
}
