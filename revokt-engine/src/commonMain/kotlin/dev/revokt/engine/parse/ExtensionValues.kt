// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import okio.ByteString
import okio.ByteString.Companion.toByteString

/** `BasicConstraints` (RFC 5280 §4.2.1.9): [ca] is false when the BOOLEAN is omitted (its DEFAULT); [pathLen] is null when absent. */
internal class BasicConstraints(
    val ca: Boolean,
    val pathLen: Int?,
)

/** `KeyUsage` (RFC 5280 §4.2.1.3): the BIT STRING's significant bits, bit 0 (`digitalSignature`) first. */
internal class KeyUsage(
    val bits: List<Boolean>,
) {
    /** Bit [bit]; a bit past the end of the string is not set. */
    operator fun get(bit: Int): Boolean = bit < bits.size && bits[bit]

    val keyCertSign: Boolean get() = get(KEY_CERT_SIGN)

    private companion object {
        const val KEY_CERT_SIGN = 5
    }
}

/** `ExtKeyUsageSyntax` (RFC 5280 §4.2.1.12): each `KeyPurposeId`'s OID content as encoded, in certificate order. */
internal class ExtendedKeyUsage(
    val purposes: List<ByteString>,
) {
    /** True when a purpose is exactly [canonical]; a non-minimal arc spelling never matches (as [Oid.matches]). */
    fun contains(canonical: ByteArray): Boolean =
        purposes.any { it.size == canonical.size && it.rangeEquals(0, canonical, 0, canonical.size) }
}

/** One `GeneralName`: its identifier octet and content as encoded. */
internal class GeneralName(
    val tag: Int,
    val content: ByteString,
)

/** `GeneralNames` of `subjectAltName` (RFC 5280 §4.2.1.6), in certificate order; at least one name. */
internal class SubjectAltNames(
    val names: List<GeneralName>,
) {
    /** The `dNSName` entries, in order (ASCII: the reader rejects any other octet). */
    val dnsNames: List<String> get() = names.filter { it.tag == ExtensionValues.DNS_NAME }.map { it.content.utf8() }
}

/** The result of reading one extension's value. */
internal sealed class ExtensionRead<out T> {
    /** The certificate has no extension with the OID. */
    data object Absent : ExtensionRead<Nothing>()

    class Value<T>(
        val value: T,
    ) : ExtensionRead<T>()

    class Failed(
        val reason: ExtensionFailure,
        val detail: String,
    ) : ExtensionRead<Nothing>()
}

internal enum class ExtensionFailure {
    /** The value does not match the extension's grammar, or its OID is spelled with a non-minimal arc. */
    MALFORMED,

    /** The OID occurs more than once in the certificate. */
    DUPLICATE,
}

/**
 * The values the x5u chain checks read (spec §7.1: basicConstraints `cA` and `pathLenConstraint`, keyUsage
 * `keyCertSign`, the leaf's EKU and SAN `dNSName`s; §4 `PresentedChain.dnsNames`). Each reader takes an `extnValue`
 * content and returns [ExtensionRead.Value] or [ExtensionRead.Failed], never throws. They are K8's grammars
 * ([ExtensionGrammars]): keyUsage, basicConstraints and EKU read what K8 accepts, and SAN reads every `GeneralName`
 * form, K8 then holding only for the forms it lists.
 *
 * With `strict` (the default, and the certificate-level lookups) a reader also rejects what the keyability profile
 * leaves to K1 and K4, which run before K8 and which an x5u certificate never meets: a non-minimal length header in
 * the value, and an EKU purpose whose OID content does not decode. K8 reads with `strict = false`, so its verdict is
 * the 0.1 grammar's. A keyUsage whose trailing bits are zero but not trimmed (X.690 §11.2.2) is read, as the JDK and
 * Go read it.
 */
internal object ExtensionValues {
    const val BASIC_CONSTRAINTS: String = "2.5.29.19"
    const val KEY_USAGE: String = "2.5.29.15"
    const val EXT_KEY_USAGE: String = "2.5.29.37"
    const val SUBJECT_ALT_NAME: String = "2.5.29.17"

    const val RFC822_NAME = 0x81
    const val DNS_NAME = 0x82
    const val IP_ADDRESS = 0x87
    private const val REGISTERED_ID = 0x88

    /**
     * The `GeneralName` identifier octets: otherName, rfc822Name, dNSName, x400Address, directoryName, ediPartyName,
     * uniformResourceIdentifier, iPAddress and registeredID, each in its one form (the implicit tag of a primitive
     * string is primitive, an explicit or SEQUENCE alternative constructed).
     */
    private val GENERAL_NAME_TAGS =
        setOf(0xa0, RFC822_NAME, DNS_NAME, 0xa3, 0xa4, 0xa5, 0x86, IP_ADDRESS, REGISTERED_ID)
    private const val IPV4_OCTETS = 4
    private const val IPV6_OCTETS = 16
    private const val BOOLEAN = 0x01
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03
    private const val OBJECT_IDENTIFIER = 0x06
    private const val SEQUENCE = 0x30
    private const val MAX_PATH_LEN_OCTETS = 4
    private const val BITS_PER_OCTET = 8
    private const val TOP_BIT = 0x80
    private val SITE = HeaderSite.EXTENSION_VALUE

    /** `SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER (0..2^31 − 1) OPTIONAL }`, the BOOLEAN `00` or `FF`. */
    fun basicConstraints(
        b: ByteArray,
        value: Span,
        strict: Boolean = true,
    ): ExtensionRead<BasicConstraints> =
        read("basicConstraints", strict) { ctx ->
            val r = sequence(b, value, ctx)
            val ca = r.readOptional(BOOLEAN, SITE)
            val pathLen = r.readOptional(INTEGER, SITE)
            r.requireEnd("basicConstraints")
            if (ca != null && !boolean(b, ca.content)) fail("cA is not 00 or FF")
            BasicConstraints(ca != null && b[ca.content.start].toInt() != 0, pathLen?.let { pathLen(b, it.content) })
        }

    /** A BIT STRING whose padding is valid (Go's `parseBitString`, [Keyability.bitStringPadding]). */
    fun keyUsage(
        b: ByteArray,
        value: Span,
        strict: Boolean = true,
    ): ExtensionRead<KeyUsage> =
        read("keyUsage", strict) { ctx ->
            val r = DerReader(b, value.start, value.end, ctx)
            val bits = r.read(BIT_STRING, SITE).content
            r.requireEnd("keyUsage")
            if (!Keyability.bitStringPadding(b, bits)) fail("invalid BIT STRING padding")
            val count = (bits.length - 1) * BITS_PER_OCTET - (b[bits.start].toInt() and 0xff)
            KeyUsage(List(count) { bit(b, bits.start + 1, it) })
        }

    /** `SEQUENCE SIZE (1..MAX) OF KeyPurposeId`. */
    fun extendedKeyUsage(
        b: ByteArray,
        value: Span,
        strict: Boolean = true,
    ): ExtensionRead<ExtendedKeyUsage> =
        read("extKeyUsage", strict) { ctx ->
            val r = sequence(b, value, ctx)
            val purposes = ArrayList<ByteString>()
            if (!r.hasMore()) fail("no KeyPurposeId")
            while (r.hasMore()) {
                val oid = r.read(OBJECT_IDENTIFIER, SITE).content
                if (strict && Oid.dotted(b, oid) == null) fail("a KeyPurposeId that does not decode")
                purposes.add(oid.bytes(b).toByteString())
            }
            ExtendedKeyUsage(purposes)
        }

    /**
     * `GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName`: each identifier one of [GENERAL_NAME_TAGS], a `dNSName`
     * ASCII, an `iPAddress` 4 or 16 octets, a `registeredID` OID content that decodes. Other contents are kept as encoded.
     */
    fun subjectAltName(
        b: ByteArray,
        value: Span,
        strict: Boolean = true,
    ): ExtensionRead<SubjectAltNames> =
        read("subjectAltName", strict) { ctx ->
            val r = sequence(b, value, ctx)
            val names = ArrayList<GeneralName>()
            if (!r.hasMore()) fail("no GeneralName")
            while (r.hasMore()) {
                val t = r.readAny(SITE)
                generalName(b, t)
                names.add(GeneralName(t.tag, t.content.bytes(b).toByteString()))
            }
            SubjectAltNames(names)
        }

    /** [c]'s basicConstraints: absent, its one value, or why it cannot be read. */
    fun basicConstraints(c: ParsedCertificate): ExtensionRead<BasicConstraints> =
        lookup(c, BASIC_CONSTRAINTS, Oid.BASIC_CONSTRAINTS_CONTENT) { b, v -> basicConstraints(b, v) }

    fun keyUsage(c: ParsedCertificate): ExtensionRead<KeyUsage> =
        lookup(c, KEY_USAGE, Oid.KEY_USAGE_CONTENT) { b, v -> keyUsage(b, v) }

    fun extendedKeyUsage(c: ParsedCertificate): ExtensionRead<ExtendedKeyUsage> =
        lookup(c, EXT_KEY_USAGE, Oid.EXT_KEY_USAGE_CONTENT) { b, v -> extendedKeyUsage(b, v) }

    fun subjectAltName(c: ParsedCertificate): ExtensionRead<SubjectAltNames> =
        lookup(c, SUBJECT_ALT_NAME, Oid.SUBJECT_ALT_NAME_CONTENT) { b, v -> subjectAltName(b, v) }

    /**
     * The one extension of [c] whose OID reads as [dotted], read by [reader]. Every spelling of the OID counts, so a
     * second copy is [ExtensionFailure.DUPLICATE] (the JDK and mozilla::pkix reject duplicates) and a copy spelled
     * with a non-minimal arc, which [Oid.matches] would not find, is [ExtensionFailure.MALFORMED] rather than absent.
     */
    private fun <T> lookup(
        c: ParsedCertificate,
        dotted: String,
        canonical: ByteArray,
        reader: (ByteArray, Span) -> ExtensionRead<T>,
    ): ExtensionRead<T> {
        val found = c.extensions(dotted)
        return when {
            found.isEmpty() -> {
                ExtensionRead.Absent
            }

            found.size > 1 -> {
                ExtensionRead.Failed(ExtensionFailure.DUPLICATE, "$dotted occurs ${found.size} times")
            }

            !Oid.matches(c.tbsBytes, found[0].oid, canonical) -> {
                ExtensionRead.Failed(ExtensionFailure.MALFORMED, "$dotted spelled with a non-minimal arc")
            }

            else -> {
                reader(c.tbsBytes, found[0].value)
            }
        }
    }

    /** Fails unless [t] is one of the `GeneralName` forms [subjectAltName] accepts. */
    private fun generalName(
        b: ByteArray,
        t: Tlv,
    ) {
        val ok =
            when (t.tag) {
                !in GENERAL_NAME_TAGS -> false
                DNS_NAME -> ascii(b, t.content)
                IP_ADDRESS -> t.content.length == IPV4_OCTETS || t.content.length == IPV6_OCTETS
                REGISTERED_ID -> Oid.dotted(b, t.content) != null
                else -> true
            }
        if (!ok) fail("GeneralName 0x${t.tag.toString(16)} of ${t.content.length} octets")
    }

    /** [block]'s value, or [ExtensionFailure.MALFORMED]; with [strict], also when a header's length is not minimal. */
    private inline fun <T> read(
        what: String,
        strict: Boolean,
        block: (ParseContext) -> T,
    ): ExtensionRead<T> =
        try {
            val ctx = ParseContext()
            val value = block(ctx)
            if (strict && ctx.nonMinimal.isNotEmpty()) fail("a non-minimal length at ${ctx.nonMinimal[0].offset}")
            ExtensionRead.Value(value)
        } catch (e: DerException) {
            ExtensionRead.Failed(ExtensionFailure.MALFORMED, "$what: ${e.message}")
        }

    /** A reader over the content of the one SEQUENCE that fills [value]. */
    private fun sequence(
        b: ByteArray,
        value: Span,
        ctx: ParseContext,
    ): DerReader {
        val r = DerReader(b, value.start, value.end, ctx)
        val seq = r.read(SEQUENCE, SITE)
        r.requireEnd("extension value")
        return r.child(seq)
    }

    /** K3's minimal form, non-negative and at most four octets, so below 2^31. */
    private fun pathLen(
        b: ByteArray,
        content: Span,
    ): Int {
        if (!Keyability.minimalInteger(b, content)) fail("pathLen is not a minimal INTEGER")
        if (b[content.start] < 0) fail("pathLen is negative")
        if (content.length > MAX_PATH_LEN_OCTETS) fail("pathLen of ${content.length} octets")
        var v = 0
        for (i in content.start until content.end) v = (v shl BITS_PER_OCTET) or (b[i].toInt() and 0xff)
        return v
    }

    /** Named bit [i] of the octets from [first], bit 0 the top bit of the first octet. */
    private fun bit(
        b: ByteArray,
        first: Int,
        i: Int,
    ): Boolean = b[first + i / BITS_PER_OCTET].toInt() and (TOP_BIT ushr (i % BITS_PER_OCTET)) != 0

    fun boolean(
        b: ByteArray,
        content: Span,
    ): Boolean = content.length == 1 && b[content.start].toInt() and 0xff in setOf(0x00, 0xff)

    fun ascii(
        b: ByteArray,
        content: Span,
    ): Boolean = (content.start until content.end).all { b[it] >= 0 }
}
