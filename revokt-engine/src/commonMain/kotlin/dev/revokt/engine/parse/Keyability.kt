// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.KeyabilityClause

/**
 * The conservative keyability profile of spec §9.2 (revision 34), read on `Cert.tbs` alone: true only when every clause
 * K1–K8 holds. It is not a model of the producer; a leaf outside it is never queried even when the producer keys it
 * (the D8 gap). Evaluated for the leaf only. K1–K4 are here; K5–K7 and a K8 that accepts no extension ct-go parses
 * fatally land with #25, and K8's grammars with #11. Until then no certificate passes K5.
 */
internal object Keyability {
    private const val SEQUENCE = 0x30
    private const val SET = 0x31
    private const val OBJECT_IDENTIFIER = 0x06
    private const val BIT_STRING = 0x03
    private const val CONSTRUCTED = 0x20
    private const val OID_ARC_LIMIT = 1L shl 31

    /** The extensions ct-go parses with a fatal return (K8's list), and the two whose presence alone is outside. */
    private val FATAL_EXTENSIONS: List<ByteArray> =
        listOf(
            byteArrayOf(0x55, 0x1d, 0x0f), // keyUsage
            byteArrayOf(0x55, 0x1d, 0x13), // basicConstraints
            byteArrayOf(0x55, 0x1d, 0x11), // subjectAltName
            byteArrayOf(0x55, 0x1d, 0x1f), // cRLDistributionPoints
            Oid.AUTHORITY_KEY_IDENTIFIER_CONTENT,
            byteArrayOf(0x55, 0x1d, 0x25), // extKeyUsage
            Oid.SUBJECT_KEY_IDENTIFIER_CONTENT,
            byteArrayOf(0x55, 0x1d, 0x20), // certificatePolicies
            byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01), // authorityInfoAccess
            byteArrayOf(0x55, 0x1d, 0x1e), // nameConstraints
            byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0b), // subjectInfoAccess
        )

    /** The first failing clause, K1 to K8 in order, or null when [c] is inside the profile (`producerKeyable`). */
    fun firstFailing(c: ParsedCertificate): KeyabilityClause? =
        when {
            !headers(c) -> KeyabilityClause.HEADER
            !shape(c) -> KeyabilityClause.TBS_SHAPE
            !minimalInteger(c.tbsBytes, c.tbs.serial) -> KeyabilityClause.INTEGER
            !oids(c) -> KeyabilityClause.OID
            else -> KeyabilityClause.NAME // K5 onward: #25
        }

    /**
     * K1: every TLV header in the TBS content has a single-octet tag and a minimal definite length. Constructed
     * elements are descended into, and so is the `extnValue` of each extension on K8's list; every other `extnValue`
     * is opaque (the SCT list, the poison, RFC 3779 and unknown extensions), as is primitive content.
     */
    private fun headers(c: ParsedCertificate): Boolean =
        derOk {
            val b = c.tbsBytes
            val ctx = ParseContext()
            val walked =
                c.tbs.extensions
                    .filter { e ->
                        FATAL_EXTENSIONS.any { Oid.matches(b, e.oid, it) }
                    }.map { it.value }
            val content = DerReader(b, 0, b.size, ctx).readAny(HeaderSite.TBS).content
            val stack = arrayListOf(DerReader(b, content.start, content.end, ctx))
            while (stack.isNotEmpty()) {
                val r = stack.last()
                if (!r.hasMore()) {
                    stack.removeAt(stack.lastIndex)
                } else {
                    val t = r.readAny(HeaderSite.TBS)
                    if (t.tag and CONSTRUCTED != 0 ||
                        t.content in walked
                    ) {
                        stack.add(DerReader(b, t.content.start, t.content.end, ctx))
                    }
                }
            }
            ctx.nonMinimal.isEmpty()
        }

    /**
     * K2: `[0]` absent or holding `00`, `01` or `02`, and `02` when `[3]` is present; no unique ids; `[3]` holding a
     * non-empty `Extensions`; no ignored element; each `AlgorithmIdentifier` an OID and at most one more TLV; names a
     * `SEQUENCE OF SET OF SEQUENCE { OID, value }`; the SPKI BIT STRING primitive with valid padding.
     */
    private fun shape(c: ParsedCertificate): Boolean =
        derOk {
            val t = c.tbs
            val b = c.tbsBytes
            val version = t.version?.let { if (it.length == 1) b[it.start].toInt() else -1 }
            val versionOk = version == null || version in 0..2
            val extensionsOk = t.tail.wrapper == null || (version == 2 && t.extensions.isNotEmpty())
            c.ignoredElements.isEmpty() && !t.tail.uniqueIds && versionOk && extensionsOk &&
                algorithm(
                    b,
                    t.signature,
                ) != null && attributes(b, t.issuer) != null && attributes(b, t.subject) != null &&
                spkiShape(b, t.spki)
        }

    /** K4: the algorithm OIDs, the EC curve, every attribute type and every extension ID. */
    private fun oids(c: ParsedCertificate): Boolean {
        val b = c.tbsBytes
        val spkiAlgorithm = spki(b, c.tbs.spki)?.first ?: return false
        val spans =
            listOfNotNull(algorithm(b, c.tbs.signature)?.first, spkiAlgorithm.first) +
                listOfNotNull(spkiAlgorithm.second?.takeIf { it.tag == OBJECT_IDENTIFIER }?.content) +
                attributes(b, c.tbs.issuer).orEmpty().map { it.first } +
                attributes(b, c.tbs.subject).orEmpty().map { it.first } +
                c.tbs.extensions.map { it.oid }
        return spans.all { minimalOid(b, it) }
    }

    /** The OID content and the optional parameters of the `AlgorithmIdentifier` at [span], or null for another shape. */
    fun algorithm(
        b: ByteArray,
        span: Span,
    ): Pair<Span, Tlv?>? =
        derOrNull {
            val r = DerReader(b, span.start, span.end, ParseContext())
            val fields = r.child(r.read(SEQUENCE, HeaderSite.TBS_SIGNATURE))
            val oid = fields.read(OBJECT_IDENTIFIER, HeaderSite.TBS_SIGNATURE).content
            val parameters = if (fields.hasMore()) fields.readAny(HeaderSite.TBS_SIGNATURE) else null
            fields.requireEnd("AlgorithmIdentifier")
            oid to parameters
        }

    /** Each attribute's type OID content and value TLV in the name at [span], or null when it is not that shape. */
    fun attributes(
        b: ByteArray,
        span: Span,
    ): List<Pair<Span, Tlv>>? =
        derOrNull {
            val out = ArrayList<Pair<Span, Tlv>>()
            val r = DerReader(b, span.start, span.end, ParseContext())
            val rdns = r.child(r.read(SEQUENCE, HeaderSite.SUBJECT))
            while (rdns.hasMore()) {
                val set = rdns.child(rdns.read(SET, HeaderSite.SUBJECT))
                while (set.hasMore()) {
                    val pair = set.child(set.read(SEQUENCE, HeaderSite.SUBJECT))
                    out.add(
                        pair.read(OBJECT_IDENTIFIER, HeaderSite.SUBJECT).content to pair.readAny(HeaderSite.SUBJECT),
                    )
                    pair.requireEnd("attribute")
                }
            }
            out
        }

    /** The SPKI's algorithm (OID content, parameters) and BIT STRING content, or null for another shape than K7's. */
    fun spki(
        b: ByteArray,
        span: Span,
    ): Pair<Pair<Span, Tlv?>, Span>? =
        derOrNull {
            val r = DerReader(b, span.start, span.end, ParseContext())
            val fields = r.child(r.read(SEQUENCE, HeaderSite.SPKI))
            val algorithm = fields.read(SEQUENCE, HeaderSite.SPKI)
            val bits = fields.read(BIT_STRING, HeaderSite.SPKI)
            fields.requireEnd("subjectPublicKeyInfo")
            (algorithm(b, algorithm.tlv) ?: return null) to bits.content
        }

    private fun spkiShape(
        b: ByteArray,
        span: Span,
    ): Boolean {
        val bits = spki(b, span)?.second ?: return false
        return bitStringPadding(b, bits)
    }

    /** Go's `parseBitString`: an unused-bits octet u ≤ 7, a further octet when u > 0, the last octet's u low bits zero. */
    fun bitStringPadding(
        b: ByteArray,
        content: Span,
    ): Boolean {
        if (content.length == 0) return false
        val unused = b[content.start].toInt() and 0xff
        if (unused == 0) return true
        return unused <= 7 && content.length > 1 && b[content.end - 1].toInt() and ((1 shl unused) - 1) == 0
    }

    /** K3: a non-empty INTEGER content with no redundant leading `00` or `FF` octet. */
    fun minimalInteger(
        b: ByteArray,
        content: Span,
    ): Boolean {
        if (content.length == 0) return false
        if (content.length == 1) return true
        val first = b[content.start].toInt() and 0xff
        val second = b[content.start + 1].toInt() and 0x80
        return !(first == 0x00 && second == 0) && !(first == 0xff && second != 0)
    }

    /** K4: non-empty, each subidentifier minimal (no leading `80`) and below 2^31, the last one terminated. */
    private fun minimalOid(
        b: ByteArray,
        content: Span,
    ): Boolean {
        if (content.length == 0) return false
        var value = 0L
        var atStart = true
        for (i in content.start until content.end) {
            val octet = b[i].toInt() and 0xff
            if (atStart && octet == 0x80) return false
            value = (value shl 7) or (octet and 0x7f).toLong()
            if (value >= OID_ARC_LIMIT) return false
            atStart = octet and 0x80 == 0
            if (atStart) value = 0
        }
        return atStart
    }

    private inline fun derOk(block: () -> Boolean): Boolean =
        try {
            block()
        } catch (_: DerException) {
            false
        }

    private inline fun <T> derOrNull(block: () -> T): T? =
        try {
            block()
        } catch (_: DerException) {
            null
        }
}
