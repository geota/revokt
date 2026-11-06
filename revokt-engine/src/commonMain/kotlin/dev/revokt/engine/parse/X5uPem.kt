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

    /** No block, a block with no base64, or a block the body ends inside. */
    FRAMING,

    /** A block whose base64 is not canonical: another character, a length not a multiple of 4, misplaced padding. */
    BASE64,
}

/**
 * The x5u body as served (spec §7.1 "x5u chain", §6.5 `x5u.pem`), read as Firefox's content-signature verifier
 * (`ReadChainIntoCertList`) and `rustls-pki-types`' PEM reader read it outside a block, and strictly inside one
 * (maintainer decision on #164). The cap is checked before anything is decoded.
 *
 * - **Lines** end at LF, CR or CRLF; a blank line is skipped anywhere.
 * - **Outside a block** every line but exactly `-----BEGIN CERTIFICATE-----` is skipped: text, other labels and
 *   stray boundaries.
 * - **Inside a block** every line up to exactly `-----END CERTIFICATE-----` is base64, of any length (as both
 *   readers accept). Their concatenation is canonical base64: only the standard alphabet, a multiple of 4
 *   characters, `=` padding only at its end, the bits after the last octet zero. Both readers accept more (unpadded
 *   input, non-zero padding bits; `rustls` also whitespace); Go's `pem.Encode`, which Mozilla's signer uses, writes
 *   only this form.
 * - At least one block, none empty, and none left open at the end of the body.
 *
 * The DER is not parsed here.
 */
internal object X5uPem {
    private const val BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val END = "-----END CERTIFICATE-----"
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
        val lines = lines(body).filter { it.length > 0 }
        val ders = ArrayList<ByteArray>()
        var i = 0
        while (i < lines.size) {
            if (!lines[i++].isText(body, BEGIN)) continue
            val first = i
            while (i < lines.size && !lines[i].isText(body, END)) i++
            if (i == lines.size) return failed(X5uPemFailure.FRAMING, "no $END after block ${ders.size + 1}")
            if (i == first) return failed(X5uPemFailure.FRAMING, "block ${ders.size + 1} is empty")
            val der =
                decode(body, lines.subList(first, i)) ?: return failed(X5uPemFailure.BASE64, "block ${ders.size + 1}")
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

    /** Each line's span: a line ends at LF or CR, so CRLF ends one line and an empty one, which [read] skips. */
    private fun lines(body: ByteArray): List<Span> {
        val out = ArrayList<Span>()
        var start = 0
        for (i in body.indices) {
            if (body[i] == LF || body[i] == CR) {
                out.add(Span(start, i))
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

    /** The octets of [lines] taken as one canonical base64 text, or null when it is not one. */
    private fun decode(
        body: ByteArray,
        lines: List<Span>,
    ): ByteArray? {
        // At most the body's size, which the cap bounds.
        val text = ByteArray(lines.sumOf { it.length })
        var at = 0
        for (line in lines) {
            body.copyInto(text, at, line.start, line.end)
            at += line.length
        }
        if (text.size % QUANTUM != 0) return null
        val pad =
            when {
                text[text.size - 1].toInt() != PAD -> 0
                text[text.size - 2].toInt() != PAD -> 1
                else -> 2
            }
        val out = ByteArray(text.size / QUANTUM * 3 - pad)
        var bits = 0
        var pending = 0
        var n = 0
        for (p in 0 until text.size - pad) {
            // A byte is at most 127, so only a non-ASCII octet (negative) falls outside the table.
            val code = text[p].toInt()
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
        // The canonical encoding: the bits after the last octet are zero (RFC 4648 §3.5).
        return if (bits == 0) out else null
    }
}
