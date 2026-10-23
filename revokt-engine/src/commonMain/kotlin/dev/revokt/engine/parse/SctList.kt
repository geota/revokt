// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import okio.ByteString
import okio.ByteString.Companion.toByteString

/** One SCT as a query uses it: the 32-byte log id and the RFC 6962 u64 timestamp carried in a `Long` (spec §6.1). */
internal data class Sct(
    val logId: ByteString,
    val timestamp: Long,
)

/**
 * The SCT-list rule of spec §9.2 (revision 33), applied to one extension value. It follows `x509-parser` 0.18.1
 * (oracle 3a) for list framing and lengths and differs at the inner identifier, which must be exactly `0x04`.
 *
 * - **Inner header:** `0x04`, then a short-form length or a long form `0x81`–`0xFE` with that many length octets
 *   (leading zeros allowed, value below 2^64), not past the end of the value. Bytes after the inner element are ignored.
 * - **List:** a `u16` length that must fit the inner content; items are read only within that region, and the bytes
 *   after it are ignored.
 * - **Item:** a `u16`-prefixed item that must fit the region, holding a version byte, a 32-byte log id, a u64
 *   timestamp, `u16`-prefixed extensions, hash and signature algorithm bytes and a `u16`-prefixed signature. Bytes
 *   after the signature are ignored.
 * - **Partial lists:** the items before the first failing item are kept. The list fails (null) when its first item
 *   fails, which includes an empty list.
 */
internal object SctList {
    private const val OCTET_STRING = 0x04
    private const val LOG_ID_BYTES = 32

    /** The SCTs of one extension value, or null when its list fails (it then contributes nothing). */
    fun parse(
        der: ByteArray,
        value: Span,
        ctx: ParseContext,
    ): List<Sct>? {
        val content = innerContent(der, value) ?: return null
        ctx.steps += content.length
        if (content.length < 2) return null
        val declared = u16(der, content.start)
        if (declared > content.length - 2) return null
        val region = Span(content.start + 2, content.start + 2 + declared)
        val out = ArrayList<Sct>()
        var pos = region.start
        while (pos < region.end) {
            val item = item(der, pos, region.end) ?: break
            out.add(item.first)
            pos = item.second
        }
        return out.ifEmpty { null }
    }

    /** The content span of the inner OCTET STRING, or null for any header the rule does not accept. */
    private fun innerContent(
        der: ByteArray,
        value: Span,
    ): Span? {
        if (value.length < 2 || der[value.start].toInt() and 0xff != OCTET_STRING) return null
        val first = der[value.start + 1].toInt() and 0xff
        var pos = value.start + 2
        val length: Long
        if (first < 0x80) {
            length = first.toLong()
        } else {
            if (first == 0x80 || first == 0xff) return null
            val count = first and 0x7f
            if (count > value.end - pos) return null
            var v = 0L
            for (i in 0 until count) {
                if (v ushr 56 != 0L) return null // the value would not fit 64 bits
                v = (v shl 8) or (der[pos + i].toLong() and 0xff)
            }
            pos += count
            length = v
        }
        if (length < 0 || length > value.end - pos) return null
        return Span(pos, pos + length.toInt())
    }

    /** One item at [start] within the region ending at [end]: the SCT and the offset after the item, or null. */
    private fun item(
        der: ByteArray,
        start: Int,
        end: Int,
    ): Pair<Sct, Int>? {
        if (end - start < 2) return null
        val itemEnd = start + 2 + u16(der, start)
        if (itemEnd > end) return null
        var p = start + 2 + 1 // the version byte: any value
        if (itemEnd - p < LOG_ID_BYTES + 8) return null
        val logId = der.toByteString(p, LOG_ID_BYTES)
        p += LOG_ID_BYTES
        var timestamp = 0L
        repeat(8) { timestamp = (timestamp shl 8) or (der[p++].toLong() and 0xff) }
        p = skipU16Prefixed(der, p, itemEnd) ?: return null // extensions
        if (itemEnd - p < 2) return null // hash and signature algorithm bytes
        p += 2
        skipU16Prefixed(der, p, itemEnd) ?: return null // the signature; bytes after it are ignored
        return Sct(logId, timestamp) to itemEnd
    }

    private fun skipU16Prefixed(
        der: ByteArray,
        p: Int,
        end: Int,
    ): Int? {
        if (end - p < 2) return null
        val next = p + 2 + u16(der, p)
        return if (next > end) null else next
    }

    private fun u16(
        der: ByteArray,
        p: Int,
    ): Int = ((der[p].toInt() and 0xff) shl 8) or (der[p + 1].toInt() and 0xff)
}

/** SKI and AKI keyIdentifier, extracted leniently: a malformed value yields null, never a failed parse (spec §5.5). */
internal object KeyIdentifiers {
    /** `SubjectKeyIdentifier ::= KeyIdentifier` (an OCTET STRING) inside the extension value. */
    fun ski(
        der: ByteArray,
        value: Span,
    ): Span? = single(der, value, 0x04)

    /** `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT … OPTIONAL, … }`: the `[0]` content. */
    fun akiKeyId(
        der: ByteArray,
        value: Span,
    ): Span? {
        val seq = single(der, value, 0x30) ?: return null
        val r = DerReader(der, seq.start, seq.end, ParseContext())
        return if (r.peekTag() == 0x80) runCatchingDer { r.readAny(HeaderSite.EXTENSION_VALUE).content } else null
    }

    /** The content of the one element of [value] if it carries [tag] and fills [value] exactly. */
    private fun single(
        der: ByteArray,
        value: Span,
        tag: Int,
    ): Span? =
        runCatchingDer {
            val r = DerReader(der, value.start, value.end, ParseContext())
            r.read(tag, HeaderSite.EXTENSION_VALUE).also { r.requireEnd("key identifier") }.content
        }

    private inline fun runCatchingDer(block: () -> Span): Span? =
        try {
            block()
        } catch (_: DerException) {
            null
        }
}
