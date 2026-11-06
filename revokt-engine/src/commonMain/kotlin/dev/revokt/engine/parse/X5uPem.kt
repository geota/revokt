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
 * The x5u body as served (spec §7.1 "x5u chain", §6.5 `x5u.pem`), read as `rustls-pki-types` 1.15.1 (`pem.rs`, the
 * version upki v1.0.1 pins) reads it, with each block's base64 strict (maintainer decision on #164). The cap is checked
 * before anything is decoded.
 *
 * - **Lines** end at LF or CR (so also at CRLF).
 * - **Outside a block** every line is skipped (text, blank lines, blocks with other labels, stray boundaries) but a
 *   `BEGIN` line: exactly `-----BEGIN CERTIFICATE-----`, then nothing but spaces.
 * - **Inside a block** the first line that starts with `-----END CERTIFICATE-----` ends it, whatever follows on that
 *   line; every line before it is base64 of any length, in which whitespace (HT, LF, VT, FF, CR, space) is skipped.
 * - **The base64**, joined, is canonical: only the standard alphabet, a multiple of 4 characters, `=` padding only at
 *   its end, the bits after the last octet zero. `rustls-pki-types` also accepts unpadded input and non-zero padding
 *   bits; Go's `pem.Encode`, which Mozilla's signer uses, writes only this form.
 * - Every block is read, in order: at least one, none empty, none left open at the end of the body.
 *
 * Firefox's `ReadChainIntoCertList` (at `cac25a6`) agrees outside a block, but wants both boundary lines exact, rejects
 * whitespace in the base64 and accepts it unpadded. The DER is not parsed here.
 */
internal object X5uPem {
    private const val BEGIN = "-----BEGIN CERTIFICATE-----"
    private const val END = "-----END CERTIFICATE-----"
    private const val QUANTUM = 4
    private const val LF = '\n'.code.toByte()
    private const val CR = '\r'.code.toByte()
    private const val SPACE = ' '.code.toByte()
    private const val PAD = '='.code
    private const val SEXTET = 6
    private const val OCTET = 8
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /** HT, LF, VT, FF, CR and space: what `rustls-pki-types` skips in base64. */
    private val WHITESPACE = byteArrayOf(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20)

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
            if (!lines[i++].isBegin(body)) continue
            val first = i
            while (i < lines.size && !lines[i].startsWith(body, END)) i++
            val block = ders.size + 1
            if (i == lines.size) return failed(X5uPemFailure.FRAMING, "no $END after block $block")
            val text = base64(body, lines.subList(first, i))
            if (text.isEmpty()) return failed(X5uPemFailure.FRAMING, "block $block is empty")
            ders.add(decode(text) ?: return failed(X5uPemFailure.BASE64, "block $block"))
            i++
        }
        if (ders.isEmpty()) return failed(X5uPemFailure.FRAMING, "no block")
        return X5uPemRead.Certificates(ders)
    }

    private fun failed(
        reason: X5uPemFailure,
        detail: String,
    ) = X5uPemRead.Failed(reason, detail)

    /** Each line's span: a line ends at LF or CR, so CRLF ends one line and an empty one. */
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

    private fun Span.startsWith(
        body: ByteArray,
        text: String,
    ): Boolean = length >= text.length && text.indices.all { body[start + it].toInt() == text[it].code }

    private fun Span.isBegin(body: ByteArray): Boolean =
        startsWith(body, BEGIN) && (start + BEGIN.length until end).all { body[it] == SPACE }

    /** The characters of [lines] but whitespace, joined; at most the body's size, which the cap bounds. */
    private fun base64(
        body: ByteArray,
        lines: List<Span>,
    ): ByteArray {
        val out = ByteArray(lines.sumOf { it.length })
        var n = 0
        for (line in lines) {
            for (p in line.start until line.end) if (body[p] !in WHITESPACE) out[n++] = body[p]
        }
        return out.copyOf(n)
    }

    /** The octets of [text] as canonical base64, or null when it is not that. */
    private fun decode(text: ByteArray): ByteArray? {
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
