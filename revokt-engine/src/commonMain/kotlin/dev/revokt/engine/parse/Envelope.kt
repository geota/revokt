// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/**
 * One unsigned envelope element (spec §9.2 "The unsigned headers"): [presented] is its TLV in the input, [content] its
 * content as the JDK verifies it, after `DerIndefLenConverter` when [indefinite], else the presented content.
 */
internal class UnsignedElement(
    val presented: Tlv,
    val indefinite: Boolean,
    val content: ByteArray,
) {
    /** The element under a minimal definite header: for the TBS, `Cert.tbs`. */
    fun reencoded(): ByteArray = byteArrayOf(presented.tag.toByte()) + minimalLength(content.size) + content
}

/**
 * The three headers the signature does not cover, read as the JDK reads them (spec §9.2 revision 35): `tbsCertificate`,
 * the outer `signatureAlgorithm` and `signatureValue`, each in any definite length form or indefinite (JDK 11 alone
 * verifies an indefinite `signatureValue`). A non-minimal header here is recorded but does not change what is verified.
 * Re-encoding can grow an element (a 4-octet indefinite frame becomes up to 5 octets of header), so `Cert.tbs` may
 * exceed the input by about a fifth at most, as the JDK's own message does.
 */
internal object Envelope {
    private const val INDEFINITE = 0x80
    private const val RESERVED = 0xff

    /** Reads the element at [position] of `der[position, limit)`, which must carry [tag]. */
    fun read(
        der: ByteArray,
        position: Int,
        limit: Int,
        tag: Int,
        site: HeaderSite,
        indefiniteAllowed: Boolean,
        ctx: ParseContext,
    ): UnsignedElement {
        if (position >= limit) fail("missing $site at $position")
        val actual = der[position].toInt() and 0xff
        if (actual !=
            tag
        ) {
            fail("expected tag 0x${tag.toString(16)} for $site at $position, found 0x${actual.toString(16)}")
        }
        if (position + 1 >= limit) fail("missing length for $site at $position")
        val first = der[position + 1].toInt() and 0xff
        if (first == INDEFINITE) {
            if (!indefiniteAllowed) fail("indefinite length for $site at $position")
            val (end, content) = convert(der, position + 2, limit, site, ctx)
            return UnsignedElement(Tlv(tag, Span(position, end), Span(position + 2, end - 2)), true, content)
        }
        var p = position + 2
        val length: Long
        if (first < 0x80) {
            length = first.toLong()
        } else {
            if (first == RESERVED) fail("reserved length byte for $site at $position")
            val count = first and 0x7f
            if (count > limit - p) fail("truncated length for $site at $position")
            var v = 0L
            repeat(count) {
                v = (v shl 8) or (der[p++].toLong() and 0xff)
                if (v > limit) fail("$site at $position declares more than the ${limit - position} bytes left")
            }
            length = v
            if (length < 0x80 || der[position + 2].toInt() == 0) ctx.nonMinimal.add(NonMinimalHeader(position, site))
        }
        if (length > limit - p) fail("$site at $position declares $length bytes, ${limit - p} remain")
        ctx.steps += p - position + 1
        val content = Span(p, p + length.toInt())
        return UnsignedElement(Tlv(tag, Span(position, content.end), content), false, content.bytes(der))
    }

    /**
     * Delimits the indefinite element whose content starts at [start] and re-encodes it as `DerIndefLenConverter`
     * does (spec §9.2): returns the offset after its end-of-contents octets and its re-encoded content. Each header met
     * is one tag octet, whatever its low five bits, then `80` (a nested indefinite element), a short form, or a minimal
     * `81` to `84`; any other length is a structure error. A definite element is copied whole, unread. Two linear
     * passes and no recursion (spec §9.2 D5): the first sizes each indefinite element, the second writes the result.
     */
    private fun convert(
        der: ByteArray,
        start: Int,
        limit: Int,
        site: HeaderSite,
        ctx: ParseContext,
    ): Pair<Int, ByteArray> {
        // sizes[i] is the re-encoded content length of the i-th indefinite element in opening order; sizes[0] is ours.
        val sizes = IntList()
        val open = IntList()
        sizes.add(0)
        open.add(0)
        var p = start
        while (open.size > 0) {
            val step: Int
            when {
                endOfContents(der, p, limit) -> {
                    step = 2
                    val closed = sizes[open.removeLast()]
                    if (open.size > 0) sizes[open.last()] += 1 + minimalLength(closed).size + closed
                }

                limit - p < 2 -> {
                    fail("unterminated indefinite $site at ${start - 2}")
                }

                der[p + 1].toInt() and 0xff == INDEFINITE -> {
                    step = 2
                    sizes.add(0)
                    open.add(sizes.size - 1)
                }

                else -> {
                    step = definiteEnd(der, p, limit, site) - p
                    sizes[open.last()] += step
                }
            }
            p += step
            ctx.steps += step
        }
        val end = p
        val out = ByteArray(sizes[0])
        var o = 0
        var next = 1
        p = start
        while (p < end - 2) {
            val step: Int
            if (endOfContents(der, p, limit)) {
                step = 2
            } else if (der[p + 1].toInt() and 0xff == INDEFINITE) {
                step = 2
                out[o++] = der[p]
                val header = minimalLength(sizes[next++])
                header.copyInto(out, o)
                o += header.size
            } else {
                step = definiteEnd(der, p, limit, site) - p
                der.copyInto(out, o, p, p + step)
                o += step
            }
            p += step
            ctx.steps += step
        }
        return end to out
    }

    private fun endOfContents(
        der: ByteArray,
        p: Int,
        limit: Int,
    ): Boolean = limit - p >= 2 && der[p].toInt() == 0 && der[p + 1].toInt() == 0

    /** The end of the definite element at [headerStart] met by the converter: a short form or a minimal `81` to `84`. */
    private fun definiteEnd(
        der: ByteArray,
        headerStart: Int,
        limit: Int,
        site: HeaderSite,
    ): Int {
        var p = headerStart + 1
        val first = der[p++].toInt() and 0xff
        var length = first.toLong()
        if (first >= 0x80) {
            val count = first and 0x7f
            if (count > 4) fail("length of $count bytes in indefinite $site at $headerStart")
            if (count > limit - p) fail("truncated length in indefinite $site at $headerStart")
            length = 0
            repeat(count) { length = (length shl 8) or (der[p++].toLong() and 0xff) }
            if (length < 0x80 ||
                der[headerStart + 2].toInt() == 0
            ) {
                fail("non-minimal length in indefinite $site at $headerStart")
            }
        }
        if (length > limit - p) fail("element at $headerStart in indefinite $site declares $length bytes")
        return p + length.toInt()
    }
}

/** A minimal DER definite length for [n]. */
internal fun minimalLength(n: Int): ByteArray =
    when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        n < 0x10000 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        n < 0x1000000 -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        else -> byteArrayOf(0x84.toByte(), (n shr 24).toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
    }

/**
 * Spec §5.1 `AlgorithmIdMismatch`, computed at parse time: the outer `signatureAlgorithm` matches only when it and the
 * TBS `signature` are both minimal DER `SEQUENCE { OID, parameters OPTIONAL }` and equal once NULL parameters are taken
 * as absent. Any other outer form (indefinite, a non-minimal header anywhere in it, other content) is a mismatch. A
 * non-minimal TBS `signature` is also reported as a mismatch, which is narrower than the JDK's `AlgorithmId` comparison;
 * the result is only a finding, and such a TBS is outside the keyability profile anyway (K1).
 */
internal object AlgorithmIdentifiers {
    private val NULL_PARAMETERS = byteArrayOf(0x05, 0x00)

    fun mismatch(
        der: ByteArray,
        outer: UnsignedElement,
        tbsSignature: ByteArray,
    ): Boolean {
        if (outer.indefinite) return true
        val presented = outer.presented.tlv.bytes(der)
        val a = normalised(presented) ?: return true
        val b = normalised(tbsSignature) ?: return true
        return !a.contentEquals(b)
    }

    /** The OID TLV followed by the parameters TLV unless it is NULL, or null when [tlv] is not such minimal DER. */
    private fun normalised(tlv: ByteArray): ByteArray? {
        if (tlv.size < 2 || tlv[0].toInt() != 0x30 || !isMinimalDer(tlv)) return null
        val oidStart = headerLength(tlv, 0)
        if (oidStart >= tlv.size || tlv[oidStart].toInt() != 0x06) return null
        val paramsStart = oidStart + headerLength(tlv, oidStart) + contentLength(tlv, oidStart)
        if (paramsStart == tlv.size) return tlv.copyOfRange(oidStart, paramsStart)
        if (paramsStart + headerLength(tlv, paramsStart) + contentLength(tlv, paramsStart) != tlv.size) return null
        val params = tlv.copyOfRange(paramsStart, tlv.size)
        return tlv.copyOfRange(oidStart, paramsStart) +
            if (params.contentEquals(NULL_PARAMETERS)) ByteArray(0) else params
    }

    private fun headerLength(
        b: ByteArray,
        p: Int,
    ): Int = if (b[p + 1].toInt() and 0x80 == 0) 2 else 2 + (b[p + 1].toInt() and 0x7f)

    private fun contentLength(
        b: ByteArray,
        p: Int,
    ): Int {
        val first = b[p + 1].toInt() and 0xff
        if (first < 0x80) return first
        var n = 0
        for (i in 0 until (first and 0x7f)) n = (n shl 8) or (b[p + 2 + i].toInt() and 0xff)
        return n
    }

    /** True when [b] is exactly one TLV tree with single-octet tags and minimal definite lengths throughout. */
    private fun isMinimalDer(b: ByteArray): Boolean {
        val limits = arrayListOf(b.size)
        var p = 0
        var elements = 0
        while (limits.isNotEmpty()) {
            if (p == limits.last()) {
                limits.removeAt(limits.lastIndex)
            } else {
                if (limits.size == 1 && elements++ > 0) return false // a second top-level element
                val header = minimalHeader(b, p, limits.last())
                if (header < 0) return false
                val length = contentLength(b, p)
                val constructed = b[p].toInt() and 0x20 != 0
                p += header
                if (constructed) limits.add(p + length) else p += length
            }
        }
        return true
    }

    /** The header length of a single-octet-tag, minimal definite TLV at [p] that fits before [limit], else -1. */
    private fun minimalHeader(
        b: ByteArray,
        p: Int,
        limit: Int,
    ): Int {
        if (limit - p < 2 || b[p].toInt() and 0x1f == 0x1f) return -1
        val lengthOctet = b[p + 1].toInt() and 0xff
        if (lengthOctet == 0x80 || lengthOctet > 0x83) return -1
        val header = headerLength(b, p)
        if (header > limit - p) return -1
        val length = contentLength(b, p)
        val minimal = lengthOctet < 0x80 || (length >= 0x80 && b[p + 2].toInt() != 0)
        return if (minimal && length <= limit - p - header) header else -1
    }
}

/** A growable `int` list without boxing, for the converter's per-element sizes (spec §9.2 D5 allocation). */
private class IntList {
    private var values = IntArray(INITIAL)
    var size = 0
        private set

    fun add(value: Int) {
        if (size == values.size) values = values.copyOf(size * 2)
        values[size++] = value
    }

    fun last(): Int = values[size - 1]

    fun removeLast(): Int = values[--size]

    operator fun get(index: Int): Int = values[index]

    operator fun set(
        index: Int,
        value: Int,
    ) {
        values[index] = value
    }

    private companion object {
        const val INITIAL = 16
    }
}
