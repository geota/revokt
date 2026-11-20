// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.ParseContext

/**
 * mozilla::pkix's `MatchPresentedDirectoryNameWithConstraint` for a permitted subtree (`pkixnames.cpp` 1405–1492 at
 * Firefox `cac25a6`). An excluded directoryName subtree never gets here: pkix refuses every name under one (1427–1431).
 *
 * The constraint's RDNs must be a prefix of the presented name's, so an empty constraint matches every name and a
 * non-empty one never matches an empty name. RDNs at the same position are compared AVA by AVA in encoded order, not
 * as sets, and must hold as many AVAs. Two AVAs match when their type OIDs and their value contents are equal byte
 * for byte and their value tags are equal, a UTF8String and a PrintableString counting as equal (bug 1150114). Both
 * names are read only as far as the comparison goes, as pkix reads them; whatever is read must be DER with minimal
 * lengths, else the comparison is an error.
 */
internal object DirectoryNameConstraint {
    private const val SEQUENCE = 0x30
    private const val SET = 0x31
    private const val OBJECT_IDENTIFIER = 0x06
    private const val UTF8_STRING = 0x0c
    private const val PRINTABLE_STRING = 0x13
    private val SITE = HeaderSite.SUBJECT

    /**
     * Whether the Name [presented] is within the permitted Name [constraint] (each a complete `SEQUENCE` TLV). Every AVA
     * pair compared consumes one unit of [budget]; [NameMatch.EXHAUSTED] when it is spent.
     */
    fun permits(
        presented: ByteArray,
        constraint: ByteArray,
        budget: ComparisonBudget,
    ): NameMatch =
        try {
            val ctx = ParseContext()
            val m = prefix(constraint, rdns(constraint, ctx), presented, rdns(presented, ctx), budget)
            // pkix's reader refuses a non-minimal length where it reads it; every header read here is one pkix reads.
            if (m != NameMatch.EXHAUSTED && ctx.nonMinimal.isNotEmpty()) NameMatch.ERROR else m
        } catch (_: DerException) {
            NameMatch.ERROR
        }

    /** The RDN sequence of the Name [name], which must be one `SEQUENCE` TLV and nothing else. */
    private fun rdns(
        name: ByteArray,
        ctx: ParseContext,
    ): DerReader {
        val r = DerReader(name, 0, name.size, ctx)
        val seq = r.read(SEQUENCE, SITE)
        r.requireEnd("Name")
        return r.child(seq)
    }

    private fun prefix(
        cb: ByteArray,
        constraint: DerReader,
        pb: ByteArray,
        presented: DerReader,
        budget: ComparisonBudget,
    ): NameMatch {
        while (true) {
            if (!constraint.hasMore()) return NameMatch.YES
            if (!presented.hasMore()) return NameMatch.NO
            val c = constraint.child(constraint.read(SET, SITE))
            val p = presented.child(presented.read(SET, SITE))
            while (c.hasMore() && p.hasMore()) {
                val a = Ava.read(cb, c)
                val b = Ava.read(pb, p)
                if (!budget.consume()) return NameMatch.EXHAUSTED
                if (!a.matches(b)) return NameMatch.NO
            }
            if (c.hasMore() || p.hasMore()) return NameMatch.NO
        }
    }

    /** One `AttributeTypeAndValue`: its type OID's content, and its value's identifier octet and content. */
    internal class Ava(
        val type: ByteArray,
        val tag: Int,
        val value: ByteArray,
    ) {
        fun matches(other: Ava): Boolean =
            type.contentEquals(other.type) &&
                value.contentEquals(other.value) &&
                (tag == other.tag || setOf(tag, other.tag) == UTF8_OR_PRINTABLE)

        companion object {
            private val UTF8_OR_PRINTABLE = setOf(UTF8_STRING, PRINTABLE_STRING)

            /** pkix's `ReadAVA` (1346–1362): `SEQUENCE { OBJECT IDENTIFIER, any one TLV }`, nothing after. */
            fun read(
                b: ByteArray,
                rdn: DerReader,
            ): Ava {
                val r = rdn.child(rdn.read(SEQUENCE, SITE))
                val type = r.read(OBJECT_IDENTIFIER, SITE)
                val value = r.readAny(SITE)
                r.requireEnd("AttributeTypeAndValue")
                return Ava(type.content.bytes(b), value.tag, value.content.bytes(b))
            }
        }
    }
}

/**
 * mozilla::pkix's rfc822Name rules in the name-constraint role (`pkixnames.cpp` at Firefox `cac25a6`):
 * `IsValidRFC822Name` (1519–1572) and `MatchPresentedRFC822NameWithReferenceRFC822Name` (1576–1651).
 */
internal object Rfc822NameConstraint {
    private const val AT = '@'.code.toByte()
    private const val ATEXT_SYMBOLS = "!#$%&'*+-/=?^_`{|}~"

    /**
     * Whether [presented], a mailbox, is within the subtree [constraint]; null when either is malformed, which fails
     * closed. A presented mailbox must be [valid]. A constraint with an `@` is one mailbox: it must be valid too, and
     * matches when the two are equal ignoring ASCII case. One without is a host: the presented mailbox's domain must
     * match it as a dNSName constraint would, except that a constraint without a leading dot matches that host only,
     * not its subdomains (`AllowDotlessSubdomainMatches::No`); an empty constraint matches every mailbox.
     */
    fun matches(
        presented: ByteArray,
        constraint: ByteArray,
        excluded: Boolean,
    ): Boolean? {
        if (!valid(presented)) return null
        if (AT in constraint) {
            if (!valid(constraint)) return null
            return presented.size == constraint.size &&
                presented.indices.all {
                    DnsNameConstraint.lower(presented[it]) ==
                        DnsNameConstraint.lower(constraint[it])
                }
        }
        val domain = presented.copyOfRange(presented.indexOf(AT) + 1, presented.size)
        return DnsNameConstraint.matches(domain, constraint, excluded, presentedWildcards = false, dotless = false)
    }

    /**
     * `IsValidRFC822Name`: a local part of dot-separated atoms of RFC 2822 `atext` (letters, digits and
     * `` !#$%&'*+-/=?^_`{|}~ ``), no atom empty and no quoted string; then `@`; then a valid presented DNS ID with no
     * wildcard.
     */
    fun valid(address: ByteArray): Boolean {
        var startOfAtom = true
        for (i in address.indices) {
            val c = address[i].toInt() and 0xff
            when {
                atext(c) -> {
                    startOfAtom = false
                }

                c == '.'.code -> {
                    if (startOfAtom) return false
                    startOfAtom = true
                }

                c == '@'.code -> {
                    if (startOfAtom) return false
                    val domain = address.copyOfRange(i + 1, address.size)
                    return DnsNameConstraint.valid(domain, constraintRole = false, wildcards = false)
                }

                else -> {
                    return false
                }
            }
        }
        return false
    }

    private fun atext(c: Int): Boolean =
        c in 'a'.code..'z'.code ||
            c in 'A'.code..'Z'.code ||
            c in '0'.code..'9'.code ||
            (c < 0x80 && c.toChar() in ATEXT_SYMBOLS)
}

/**
 * The names mozilla::pkix finds in a subject for a name constraint (`SearchNames` 446–540, `SearchWithinRDN` 549–573,
 * `MatchAVA` 589–702, `pkixnames.cpp` at Firefox `cac25a6`), beside the subject itself, which is always a directoryName:
 *
 * - **emailAddress** attributes, each an rfc822Name, when the certificate has no subjectAltName extension at all; one
 *   that is not an IA5String is an error.
 * - **The CN-ID**, for the leaf of a serverAuth request whose subjectAltName holds no dNSName and no iPAddress: the
 *   last commonName attribute of the subject. When its value is a PrintableString, UTF8String or TeletexString it is a
 *   dNSName if it is a valid presented DNS ID (a wildcard allowed), else an iPAddress if it is a dotted IPv4 address;
 *   otherwise, or when its value is of another string type, the leaf presents no CN-ID. pkix forgets an earlier CN's
 *   result at each later one (621), so only the last counts.
 *
 * Reading them walks the whole subject as pkix does: `SEQUENCE OF SET OF AttributeTypeAndValue`, the sequence possibly
 * empty and no RDN empty; anything else, or a non-minimal length, is an error.
 */
internal object SubjectNames {
    private const val SEQUENCE = 0x30
    private const val SET = 0x31
    private const val IA5_STRING = 0x16
    private const val UTF8_STRING = 0x0c
    private const val PRINTABLE_STRING = 0x13
    private const val TELETEX_STRING = 0x14
    private val SITE = HeaderSite.SUBJECT
    private val COMMON_NAME = byteArrayOf(0x55, 0x04, 0x03)
    private val EMAIL_ADDRESS =
        byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x09, 0x01)
    private const val IPV4_PARTS = 4
    private const val OCTET_MAX = 255
    private const val DECIMAL = 10

    /**
     * The names [subject] (a complete Name TLV) presents beyond itself: its emailAddress attributes when [emails], then
     * its CN-ID when [commonName]. Null when the subject must be read and does not read, or an emailAddress is not an
     * IA5String.
     */
    fun of(
        subject: ByteArray,
        emails: Boolean,
        commonName: Boolean,
    ): List<PresentedName>? {
        val avas = avas(subject) ?: return null
        val out = ArrayList<PresentedName>()
        if (emails) {
            for (a in avas) {
                if (!a.type.contentEquals(EMAIL_ADDRESS)) continue
                if (a.tag != IA5_STRING) return null
                out += PresentedName.Rfc822(a.value)
            }
        }
        if (commonName) avas.lastOrNull { it.type.contentEquals(COMMON_NAME) }?.let { cnId(it) }?.let { out += it }
        return out
    }

    private fun cnId(cn: DirectoryNameConstraint.Ava): PresentedName? {
        if (cn.tag != PRINTABLE_STRING && cn.tag != UTF8_STRING && cn.tag != TELETEX_STRING) return null
        if (DnsNameConstraint.valid(
                cn.value,
                constraintRole = false,
                wildcards = true,
            )
        ) {
            return PresentedName.Dns(cn.value)
        }
        return ipv4(cn.value)?.let { PresentedName.Ip(it) }
    }

    /** Every AVA of [subject] in encoded order, or null when it is not a well-formed Name. */
    fun avas(subject: ByteArray): List<DirectoryNameConstraint.Ava>? =
        try {
            val ctx = ParseContext()
            val r = DerReader(subject, 0, subject.size, ctx)
            val rdns = r.child(r.read(SEQUENCE, SITE))
            r.requireEnd("Name")
            val out = ArrayList<DirectoryNameConstraint.Ava>()
            while (rdns.hasMore()) {
                val rdn = rdns.child(rdns.read(SET, SITE))
                do {
                    out += DirectoryNameConstraint.Ava.read(subject, rdn)
                } while (rdn.hasMore())
            }
            if (ctx.nonMinimal.isEmpty()) out else null
        } catch (_: DerException) {
            null
        }

    /**
     * pkix's `ParseIPv4Address` (1683–1737): four decimal components separated by dots, each 0 to 255 with no leading
     * zero, nothing else.
     */
    fun ipv4(text: ByteArray): ByteArray? {
        val out = ByteArray(IPV4_PARTS)
        var at = 0
        for (part in 0 until IPV4_PARTS) {
            val last = part == IPV4_PARTS - 1
            val end = if (last) text.size else dot(text, at) ?: return null
            out[part] = component(text, at, end) ?: return null
            at = end + 1
        }
        return out
    }

    /** The index of the first `.` in [text] at or after [from]; null when there is none. */
    private fun dot(
        text: ByteArray,
        from: Int,
    ): Int? = (from until text.size).firstOrNull { text[it] == '.'.code.toByte() }

    /** `ReadIPv4AddressComponent`: the digits of [text] in `[from, to)`, 0 to 255, no leading zero, at least one. */
    private fun component(
        text: ByteArray,
        from: Int,
        to: Int,
    ): Byte? {
        if (from >= to || (to - from > 1 && text[from] == '0'.code.toByte())) return null
        var value = 0
        for (i in from until to) {
            val b = text[i].toInt() and 0xff
            if (b !in '0'.code..'9'.code) return null
            value = value * DECIMAL + (b - '0'.code)
            if (value > OCTET_MAX) return null
        }
        return value.toByte()
    }
}
