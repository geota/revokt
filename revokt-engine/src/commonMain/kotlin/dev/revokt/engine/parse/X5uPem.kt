// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.RevoktLimits

internal sealed class X5uPemRead {
    /** The DER of each `CERTIFICATE` block, in body order (leaf first, spec §6.5); at least one. */
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

    /** No `CERTIFICATE` block, a malformed `BEGIN` line, or a block the body ends inside. */
    FRAMING,

    /** A decoded block's base64 has another character or misplaced padding. */
    BASE64,
}

/**
 * The x5u body as served (spec §7.1 "x5u chain", §6.5 `x5u.pem`), read exactly as `rustls-pki-types` 1.15.1 reads it
 * with `CertificateDer::pem_slice_iter` (`pem.rs`, `base64.rs`; the version upki v1.0.1 pins; maintainer decision on
 * #164), the cap checked before anything is decoded. Its rules, in its order:
 *
 * - **Lines** end at LF or CR (so CRLF ends a line and an empty one).
 * - **A `BEGIN` line** starts with `-----BEGIN `; read back from its end over spaces, its last non-space characters
 *   must be exactly five `-` (spaces between them allowed), else the body fails. The label is what lies between. A
 *   `BEGIN` line starts a block even inside one, keeping the base64 read so far.
 * - **Inside a block** a line that starts with `-----END `, the block's label and `-----` ends it, whatever follows;
 *   every other line is base64. Outside a block every other line is skipped.
 * - **The block's base64** is decoded when its label is one `rustls-pki-types` knows (`CERTIFICATE`, `PUBLIC KEY`,
 *   `RSA PRIVATE KEY`, `PRIVATE KEY`, `EC PRIVATE KEY`, `X509 CRL`, `CERTIFICATE REQUEST`, `ECHCONFIG`), and skipped
 *   undecoded for any other label. Only `CERTIFICATE` blocks are returned; a decode error in any known block fails.
 * - **The decoder** skips HT, LF, VT, FF, CR and space, rejects any other character outside the standard alphabet and
 *   `=`, does not require padding, rejects `=` before the last group of four and a malformed last group, and drops
 *   the bits after the last octet unchecked. An empty block decodes to no octets.
 * - A body that ends inside a block fails; one with no `CERTIFICATE` block fails (upki's `from_pem_slice` reports
 *   `NoItemsFound`).
 *
 * The DER is not parsed here.
 */
internal object X5uPem {
    private const val BEGIN = "-----BEGIN "
    private const val END = "-----END "
    private const val BOUNDARY = "-----"
    private const val CERTIFICATE = "CERTIFICATE"
    private const val TRAILER_DASHES = 5
    private const val LF = '\n'.code.toByte()
    private const val CR = '\r'.code.toByte()
    private const val SPACE = ' '.code.toByte()
    private const val DASH = '-'.code.toByte()

    /** The labels `rustls-pki-types` 1.15.1 decodes (`SectionKind`); any other is skipped undecoded. */
    private val KNOWN =
        setOf(
            CERTIFICATE,
            "PUBLIC KEY",
            "RSA PRIVATE KEY",
            "PRIVATE KEY",
            "EC PRIVATE KEY",
            "X509 CRL",
            "CERTIFICATE REQUEST",
            "ECHCONFIG",
        )

    fun read(
        body: ByteArray,
        maxBytes: Long = RevoktLimits.MAX_X5U_BYTES,
    ): X5uPemRead {
        if (body.size > maxBytes) return failed(X5uPemFailure.OVERSIZE, "${body.size} bytes, cap $maxBytes")
        val ders = ArrayList<ByteArray>()
        // The open block's label, null outside one, and its base64 so far.
        var label: String? = null
        val base64 = ArrayList<Span>()
        for (line in lines(body)) {
            val open = label
            when {
                line.startsWith(body, BEGIN) -> {
                    label = beginLabel(body, line) ?: return failed(X5uPemFailure.FRAMING, "a malformed BEGIN line")
                }

                open == null -> {}

                !isEnd(body, line, open) -> {
                    base64.add(line)
                }

                else -> {
                    close(body, open, base64, ders)?.let { return it }
                    label = null
                }
            }
        }
        if (label != null) return failed(X5uPemFailure.FRAMING, "no END line for the $label block")
        if (ders.isEmpty()) return failed(X5uPemFailure.FRAMING, "no CERTIFICATE block")
        return X5uPemRead.Certificates(ders)
    }

    /**
     * Ends the block [label]: decodes a known label's [base64] (its octets kept in [ders] for a `CERTIFICATE`) and
     * clears it; the failure when the decode fails, else null.
     */
    private fun close(
        body: ByteArray,
        label: String,
        base64: MutableList<Span>,
        ders: MutableList<ByteArray>,
    ): X5uPemRead.Failed? {
        if (label in KNOWN) {
            val der = Base64Pem.decode(body, base64) ?: return failed(X5uPemFailure.BASE64, "the $label block")
            if (label == CERTIFICATE) ders.add(der)
        }
        base64.clear()
        return null
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

    /**
     * The label of a `BEGIN` line, or null when it is malformed: read back from the end, spaces are skipped and the
     * first other character stops the count of `-`, which must be five; the label ends at the first counted `-`.
     */
    private fun beginLabel(
        body: ByteArray,
        line: Span,
    ): String? {
        var dashes = 0
        var labelEnd = line.end
        // rustls reads on into the prefix, whose space it skips and whose `N` stops it: the same count.
        var i = line.end - 1
        while (i >= line.start + BEGIN.length && (body[i] == DASH || body[i] == SPACE)) {
            if (body[i] == DASH) {
                dashes++
                labelEnd = i
            }
            i--
        }
        if (dashes != TRAILER_DASHES) return null
        return text(body, Span(line.start + BEGIN.length, labelEnd))
    }

    private fun isEnd(
        body: ByteArray,
        line: Span,
        label: String,
    ): Boolean {
        val marker = END + label + BOUNDARY
        return line.startsWith(body, marker)
    }

    private fun Span.startsWith(
        body: ByteArray,
        text: String,
    ): Boolean = length >= text.length && text.indices.all { (body[start + it].toInt() and 0xff) == text[it].code }

    /** [span]'s octets as Latin-1 text, so that every label compares by its bytes. */
    private fun text(
        body: ByteArray,
        span: Span,
    ): String = CharArray(span.length) { (body[span.start + it].toInt() and 0xff).toChar() }.concatToString()
}

/**
 * `rustls-pki-types` 1.15.1's base64 decoder (`base64.rs`, `decode`), ported step for step: code points are read in
 * groups of eight, whitespace skipped; `=` counts as a zero sextet and is recorded in a mask; a full group with any
 * `=` that is followed by more input is premature padding; the last up to eight code points are taken as one group
 * of four then the rest, whose (count, mask) pair must be one of the five valid endings.
 */
internal object Base64Pem {
    private const val GROUP = 8
    private const val HALF = 4
    private const val SEXTET = 6
    private const val OCTET = 8
    private const val SHIFT_INITIAL = (GROUP - 1) * SEXTET
    private const val TOP_OCTET_SHIFT = GROUP * SEXTET - OCTET
    private const val FIRST_HALF_BITS = HALF * SEXTET
    private const val HALF_MASK = 0b1111
    private const val ONE_PAD = 0b1000
    private const val TWO_PADS = 0b1100
    private const val WHITESPACE = -1
    private const val PAD = -2
    private const val INVALID = -3
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /** Each octet's code point: its sextet, or [WHITESPACE], [PAD] or [INVALID]. */
    private val CODE_POINTS =
        IntArray(256) { INVALID }.also { t ->
            ALPHABET.forEachIndexed { i, c -> t[c.code] = i }
            for (c in listOf(0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20)) t[c] = WHITESPACE
            t['='.code] = PAD
        }

    /** The octets of [lines] as one base64 text, or null where `rustls-pki-types` reports an error. */
    fun decode(
        body: ByteArray,
        lines: List<Span>,
    ): ByteArray? {
        val d = Decoder(ByteArray((lines.sumOf { it.length } + 3) / 4 * 3))
        for (line in lines) {
            for (p in line.start until line.end) {
                if (!d.push(CODE_POINTS[body[p].toInt() and 0xff])) return null
            }
        }
        return d.finish()
    }

    /** `decode`'s state: up to [GROUP] code points in [buffer], from bit 47 down, and which of them were `=`. */
    private class Decoder(
        val out: ByteArray,
    ) {
        var n = 0
        var buffer = 0L
        var used = 0
        var shift = SHIFT_INITIAL
        var padMask = 0

        /** Takes one code point; false where the input is invalid. */
        fun push(point: Int): Boolean {
            if (point == WHITESPACE) return true
            if (point == INVALID) return false
            if (used == GROUP) {
                if (padMask != 0) return false
                emit(GROUP / HALF * 3)
                buffer = 0
                used = 0
                padMask = 0
                shift = SHIFT_INITIAL
            }
            val pad = if (point == PAD) 1 else 0
            buffer = buffer or ((if (point == PAD) 0 else point).toLong() shl shift)
            shift -= SEXTET
            padMask = padMask or (pad shl used)
            used++
            return true
        }

        /** The octets, or null where the last group is not one of the valid endings. */
        fun finish(): ByteArray? {
            if (used > HALF) {
                if (padMask and HALF_MASK != 0) return null
                emit(3)
                buffer = buffer shl FIRST_HALF_BITS
                padMask = padMask shr HALF
                used -= HALF
            }
            emit(tail() ?: return null)
            return out.copyOf(n)
        }

        /** How many octets the last (count, mask) pair carries, or null for an invalid one. */
        private fun tail(): Int? =
            when {
                // No code point after the last full group: its mask was reset with it.
                used == 0 -> 0

                used == HALF && padMask == 0 -> 3

                (used == HALF && padMask == ONE_PAD) || (used == 3 && padMask == 0) -> 2

                (used == HALF && padMask == TWO_PADS) || (used == 2 && padMask == 0) -> 1

                else -> null
            }

        /** Writes the top [count] octets of [buffer]. */
        private fun emit(count: Int) {
            for (k in 0 until count) out[n++] = (buffer shr (TOP_OCTET_SHIFT - OCTET * k)).toByte()
        }
    }
}
