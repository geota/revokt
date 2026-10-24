// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

/**
 * K8 (spec §9.2 revision 35): the grammar each extension ct-go parses with a fatal return must match. Narrower than
 * ct-go where the profile chooses to be (no trailing SEQUENCE elements, only the name forms listed, `pathLen` from 0 to
 * 2^31 − 1); every header inside these values is also walked by K1. An extension not on the list is opaque.
 */
internal object ExtensionGrammars {
    private const val BOOLEAN = 0x01
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03
    private const val OCTET_STRING = 0x04
    private const val OBJECT_IDENTIFIER = 0x06
    private const val SEQUENCE = 0x30
    private const val RFC822_NAME = 0x81
    private const val DNS_NAME = 0x82
    private const val URI = 0x86
    private const val IP_ADDRESS = 0x87
    private const val KEY_IDENTIFIER = 0x80
    private const val CONTEXT_0 = 0xa0
    private const val MAX_PATH_LEN_OCTETS = 4
    private const val CONSTRUCTED = 0x20

    private val KEY_USAGE = byteArrayOf(0x55, 0x1d, 0x0f)
    private val BASIC_CONSTRAINTS = byteArrayOf(0x55, 0x1d, 0x13)
    private val SUBJECT_ALT_NAME = byteArrayOf(0x55, 0x1d, 0x11)
    private val CRL_DISTRIBUTION_POINTS = byteArrayOf(0x55, 0x1d, 0x1f)
    private val EXT_KEY_USAGE = byteArrayOf(0x55, 0x1d, 0x25)
    private val CERTIFICATE_POLICIES = byteArrayOf(0x55, 0x1d, 0x20)
    private val AUTHORITY_INFO_ACCESS = byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01)
    private val NAME_CONSTRAINTS = byteArrayOf(0x55, 0x1d, 0x1e)
    private val SUBJECT_INFO_ACCESS = byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0b)

    /** Each listed OID's grammar over the `extnValue` content; nameConstraints and subjectInfoAccess have none. */
    private val GRAMMARS: List<Pair<ByteArray, (ByteArray, Span) -> Boolean>> =
        listOf(
            KEY_USAGE to { b, v -> only(b, v, BIT_STRING) { Keyability.bitStringPadding(b, it.content) } },
            BASIC_CONSTRAINTS to { b, v -> sequence(b, v) { basicConstraints(b, it) } },
            SUBJECT_ALT_NAME to { b, v -> sequence(b, v) { r -> r.hasMore() && all(r) { sanName(b, it) } } },
            CRL_DISTRIBUTION_POINTS to { b, v -> sequence(b, v) { r -> all(r) { distributionPoint(b, it) } } },
            Oid.AUTHORITY_KEY_IDENTIFIER_CONTENT to { b, v -> sequence(b, v) { keyIdentifierOnly(it) } },
            EXT_KEY_USAGE to { b, v -> sequence(b, v) { r -> r.hasMore() && all(r) { it.tag == OBJECT_IDENTIFIER } } },
            Oid.SUBJECT_KEY_IDENTIFIER_CONTENT to { b, v -> only(b, v, OCTET_STRING) { true } },
            CERTIFICATE_POLICIES to { b, v -> sequence(b, v) { r -> all(r) { policy(b, it) } } },
            AUTHORITY_INFO_ACCESS to
                { b, v -> sequence(b, v) { r -> r.hasMore() && all(r) { accessDescription(b, it) } } },
            NAME_CONSTRAINTS to { _, _ -> false },
            SUBJECT_INFO_ACCESS to { _, _ -> false },
        )

    /** K8's list: the extensions ct-go parses with a fatal return, matched on canonical OID content (K1 walks them). */
    val LISTED: List<ByteArray> = GRAMMARS.map { it.first }

    /** True when [e]'s value matches the grammar for its OID, or its OID is not on K8's list. */
    fun valid(
        b: ByteArray,
        e: Extension,
    ): Boolean {
        val grammar = GRAMMARS.firstOrNull { Oid.matches(b, e.oid, it.first) }?.second ?: return true
        return try {
            grammar(b, e.value) && booleans(b, e.value)
        } catch (_: DerException) {
            false
        }
    }

    /** The OIDs K4 reads inside K8's values: EKU purposes, policy identifiers and access methods. Lenient: shape is K8's. */
    fun oids(
        b: ByteArray,
        e: Extension,
    ): List<Span> {
        val direct = Oid.matches(b, e.oid, EXT_KEY_USAGE)
        val nested = Oid.matches(b, e.oid, CERTIFICATE_POLICIES) || Oid.matches(b, e.oid, AUTHORITY_INFO_ACCESS)
        if (!direct && !nested) return emptyList()
        val out = ArrayList<Span>()
        try {
            val r = reader(b, e.value)
            val items = r.child(r.read(SEQUENCE, SITE))
            while (items.hasMore()) {
                val item = items.readAny(SITE)
                (
                    if (direct) {
                        item.takeIf { it.tag == OBJECT_IDENTIFIER }?.content
                    } else {
                        leadingOid(
                            b,
                            item,
                        )
                    }
                )?.let { out.add(it) }
            }
        } catch (_: DerException) {
            // The value's shape is K8's to judge; K4 checks the OIDs that could be read.
        }
        return out
    }

    /** The content of the OID that opens a SEQUENCE item, if it opens with one. */
    private fun leadingOid(
        b: ByteArray,
        item: Tlv,
    ): Span? {
        if (item.tag != SEQUENCE) return null
        val inner = reader(b, item.content)
        return if (inner.peekTag() == OBJECT_IDENTIFIER) inner.readAny(SITE).content else null
    }

    private val SITE = HeaderSite.EXTENSION_VALUE

    private fun reader(
        b: ByteArray,
        span: Span,
    ) = DerReader(b, span.start, span.end, ParseContext())

    /** The value is exactly one element with [tag], and [check] holds for it. */
    private inline fun only(
        b: ByteArray,
        value: Span,
        tag: Int,
        check: (Tlv) -> Boolean,
    ): Boolean {
        val r = reader(b, value)
        val t = r.read(tag, SITE)
        r.requireEnd("extension value")
        return check(t)
    }

    /** The value is exactly one SEQUENCE, and [check] holds for a reader over its content. */
    private inline fun sequence(
        b: ByteArray,
        value: Span,
        check: (DerReader) -> Boolean,
    ): Boolean = only(b, value, SEQUENCE) { check(reader(b, it.content)) }

    private inline fun all(
        r: DerReader,
        check: (Tlv) -> Boolean,
    ): Boolean {
        while (r.hasMore()) if (!check(r.readAny(SITE))) return false
        return true
    }

    /** Every BOOLEAN anywhere in the value, policy qualifiers included, is `00` or `FF` (K8). */
    private fun booleans(
        b: ByteArray,
        value: Span,
    ): Boolean {
        val stack = arrayListOf(reader(b, value))
        while (stack.isNotEmpty()) {
            val r = stack.last()
            if (!r.hasMore()) {
                stack.removeAt(stack.lastIndex)
                continue
            }
            val t = r.readAny(SITE)
            if (t.tag == BOOLEAN && !boolean(b, t.content)) return false
            if (t.tag and CONSTRUCTED != 0) stack.add(reader(b, t.content))
        }
        return true
    }

    /** The AKI's content: exactly a primitive `[0]` keyIdentifier. */
    private fun keyIdentifierOnly(r: DerReader): Boolean {
        r.read(KEY_IDENTIFIER, SITE)
        r.requireEnd("authorityKeyIdentifier")
        return true
    }

    /** `SEQUENCE { cA BOOLEAN OPTIONAL, pathLen INTEGER (0..2^31 − 1) OPTIONAL }`, a BOOLEAN `00` or `FF`. */
    private fun basicConstraints(
        b: ByteArray,
        r: DerReader,
    ): Boolean {
        val ca = r.readOptional(BOOLEAN, SITE)
        val pathLen = r.readOptional(INTEGER, SITE)
        r.requireEnd("basicConstraints")
        val caOk = ca == null || boolean(b, ca.content)
        val pathLenOk =
            pathLen == null ||
                (
                    Keyability.minimalInteger(b, pathLen.content) && b[pathLen.content.start] >= 0 &&
                        pathLen.content.length <= MAX_PATH_LEN_OCTETS
                )
        return caOk && pathLenOk
    }

    private fun boolean(
        b: ByteArray,
        content: Span,
    ): Boolean = content.length == 1 && b[content.start].toInt() and 0xff in setOf(0x00, 0xff)

    /** A SAN entry: `dNSName` or `rfc822Name` of ASCII octets, or `iPAddress` of 4 or 16 octets. */
    private fun sanName(
        b: ByteArray,
        t: Tlv,
    ): Boolean =
        when (t.tag) {
            DNS_NAME, RFC822_NAME -> ascii(b, t.content)
            IP_ADDRESS -> t.content.length == 4 || t.content.length == 16
            else -> false
        }

    /** `SEQUENCE { [0] { [0] GeneralNames } }` holding at least one `[6]` URI of ASCII octets and nothing else. */
    private fun distributionPoint(
        b: ByteArray,
        t: Tlv,
    ): Boolean {
        if (t.tag != SEQUENCE) return false
        val point = reader(b, t.content)
        val name = reader(b, point.read(CONTEXT_0, SITE).content)
        point.requireEnd("DistributionPoint")
        val full = reader(b, name.read(CONTEXT_0, SITE).content)
        name.requireEnd("DistributionPointName")
        return full.hasMore() && all(full) { it.tag == URI && ascii(b, it.content) }
    }

    /** `SEQUENCE { OID, … }`: the qualifiers after the identifier are walked by K1 only. */
    private fun policy(
        b: ByteArray,
        t: Tlv,
    ): Boolean = t.tag == SEQUENCE && reader(b, t.content).peekTag() == OBJECT_IDENTIFIER

    /** `SEQUENCE { OID, [6] }` with ASCII octets. */
    private fun accessDescription(
        b: ByteArray,
        t: Tlv,
    ): Boolean {
        if (t.tag != SEQUENCE) return false
        val r = reader(b, t.content)
        r.read(OBJECT_IDENTIFIER, SITE)
        val location = r.read(URI, SITE)
        r.requireEnd("AccessDescription")
        return ascii(b, location.content)
    }

    private fun ascii(
        b: ByteArray,
        content: Span,
    ): Boolean = (content.start until content.end).all { b[it] >= 0 }
}
