// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/** A half-open byte range `[start, end)` of the certificate being parsed. */
internal class Span(
    val start: Int,
    val end: Int,
) {
    val length: Int get() = end - start

    fun bytes(der: ByteArray): ByteArray = der.copyOfRange(start, end)

    override fun equals(other: Any?): Boolean = other is Span && start == other.start && end == other.end

    override fun hashCode(): Int = start * 31 + end

    override fun toString(): String = "[$start, $end)"
}

/** One TLV: identifier byte, the whole element ([tlv]) and its content ([content]). */
internal class Tlv(
    val tag: Int,
    val tlv: Span,
    val content: Span,
)

/** The only exception the parser throws internally; [CertificateParser.parse] turns it into `ParseReason.STRUCTURE`. */
internal class DerException(
    message: String,
) : Exception(message)

/** A header whose definite length is not minimal, at [offset]; the producer-keyability table reads these (spec §9.2). */
internal class NonMinimalHeader(
    val offset: Int,
    val site: HeaderSite,
)

/** Bytes the parse skipped where the JDK's `X509CertInfo` tolerates them (spec §9.2), for the producer-keyability table. */
internal class IgnoredElement(
    val span: Span,
    val site: IgnoredSite,
)

internal enum class IgnoredSite {
    /** The first element after `subjectPublicKeyInfo` and the unique ids that is not `[3]`, and everything after it. */
    TBS_AFTER_STOP,

    /** Bytes after the `[3]` extensions element, unparsed. */
    TBS_AFTER_EXTENSIONS,

    /** Elements after the INTEGER inside `[0]`. */
    VERSION_TRAILING,

    /** Elements after the `Extensions` SEQUENCE inside `[3]`. */
    EXTENSIONS_WRAPPER_TRAILING,

    /** Elements after `extnValue` inside one `Extension`. */
    EXTENSION_TRAILING,
}

/** Which element of `Certificate` a recorded header belongs to. */
internal enum class HeaderSite {
    CERTIFICATE,
    TBS,
    VERSION,
    VERSION_INTEGER,
    SERIAL,
    TBS_SIGNATURE,
    ISSUER,
    VALIDITY,
    TBS_STOP,
    NOT_BEFORE,
    NOT_AFTER,
    SUBJECT,
    SPKI,
    ISSUER_UID,
    SUBJECT_UID,
    EXTENSIONS_WRAPPER,
    EXTENSIONS,
    EXTENSION,
    EXTENSION_OID,
    EXTENSION_CRITICAL,
    EXTENSION_VALUE,
    SIGNATURE_ALGORITHM,
    SIGNATURE_VALUE,
}

/** Per-parse state shared by every reader: the step counter (spec §9.2 D5) and the non-minimal headers seen. */
internal class ParseContext {
    var steps: Long = 0
    val nonMinimal: MutableList<NonMinimalHeader> = ArrayList()
    val ignored: MutableList<IgnoredElement> = ArrayList()
}

internal fun fail(message: String): Nothing = throw DerException(message)

/**
 * A structurally strict DER reader over `der[position, limit)`: single-byte identifiers, definite lengths only (short
 * form, or long form of 1 to 4 bytes that fits the input), and nothing read past [limit]. A non-minimal definite length
 * is accepted and recorded (spec §9.2); indefinite lengths, the reserved `0xFF` length byte and multi-byte tags at an
 * expected position are structure errors.
 */
internal class DerReader(
    private val der: ByteArray,
    start: Int,
    private val limit: Int,
    private val ctx: ParseContext,
) {
    var position: Int = start
        private set

    fun hasMore(): Boolean = position < limit

    fun peekTag(): Int = if (position < limit) der[position].toInt() and 0xff else -1

    /** Reads the next element, which must carry [tag]. */
    fun read(
        tag: Int,
        site: HeaderSite,
    ): Tlv {
        val actual = peekTag()
        if (actual !=
            tag
        ) {
            fail("expected tag 0x${tag.toString(16)} for $site at $position, found 0x${actual.toString(16)}")
        }
        return readAny(site)
    }

    /** Reads the next element whatever its single-byte tag is. */
    fun readAny(site: HeaderSite): Tlv {
        val headerStart = position
        if (position >= limit) fail("missing $site at $position")
        val tag = der[position].toInt() and 0xff
        // Reachable where the parse reads whatever comes next (the TBS stop element); the JDK rejects these too.
        if (tag and 0x1f == 0x1f) fail("multi-byte tag for $site at $position")
        position++
        val length = readLength(headerStart, site)
        if (length > limit - position) fail("$site at $headerStart declares $length bytes, ${limit - position} remain")
        ctx.steps += position - headerStart + 1
        val content = Span(position, position + length)
        position += length
        return Tlv(tag, Span(headerStart, position), content)
    }

    /** Reads the next element if it carries [tag], else returns null without moving. */
    fun readOptional(
        tag: Int,
        site: HeaderSite,
    ): Tlv? = if (peekTag() == tag) readAny(site) else null

    /** Skips the rest of this reader's range, recording it as ignored when non-empty. */
    fun ignoreRest(site: IgnoredSite) {
        if (position < limit) ctx.ignored.add(IgnoredElement(Span(position, limit), site))
        position = limit
    }

    fun requireEnd(what: String) {
        if (position != limit) fail("${limit - position} trailing bytes after $what")
    }

    private fun readLength(
        headerStart: Int,
        site: HeaderSite,
    ): Int {
        if (position >= limit) fail("missing length for $site at $headerStart")
        val first = der[position++].toInt() and 0xff
        if (first < 0x80) return first
        if (first == 0x80) fail("indefinite length for $site at $headerStart")
        val count = first and 0x7f
        if (count > 4) fail("length of $count bytes for $site at $headerStart")
        if (count > limit - position) fail("truncated length for $site at $headerStart")
        var length = 0L
        repeat(count) { length = (length shl 8) or (der[position++].toLong() and 0xff) }
        if (length > Int.MAX_VALUE) fail("length $length for $site at $headerStart")
        val minimal = length >= 0x80 && (der[headerStart + 2].toInt() and 0xff) != 0
        if (!minimal) ctx.nonMinimal.add(NonMinimalHeader(headerStart, site))
        return length.toInt()
    }

    /** A reader over the content of [tlv]. */
    fun child(tlv: Tlv): DerReader = DerReader(der, tlv.content.start, tlv.content.end, ctx)
}
