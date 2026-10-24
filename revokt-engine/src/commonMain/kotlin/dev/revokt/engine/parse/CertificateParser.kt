// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.parse

import dev.revokt.ParseReason
import dev.revokt.RevoktLimits

/** One `Extension`: the OID content, the critical flag, the `extnValue` OCTET STRING content and the whole TLV. */
internal class Extension(
    val oid: Span,
    val oidDotted: String?,
    val critical: Boolean,
    val value: Span,
    val tlv: Span,
)

/** `Validity`: each time's TLV and its decoded epoch milliseconds, null when the text does not decode. */
internal class Validity(
    val notBefore: Span,
    val notBeforeMillis: Long?,
    val notAfter: Span,
    val notAfterMillis: Long?,
)

/**
 * The fields of `tbsCertificate` the engine reads (spec §5.5, §9.2 "Parser contract"). Spans index the input DER:
 * [serial] is the INTEGER content as encoded (sign and leading zeros preserved, the producer's `RawValue.Bytes`);
 * [signature], [issuer], [subject] and [spki] are complete TLVs. [version] is null when the `[0]` element is absent.
 */
internal class Tbs(
    val tlv: Span,
    val version: Span?,
    val serial: Span,
    val signature: Span,
    val issuer: Span,
    val validity: Validity,
    val subject: Span,
    val spki: Span,
    val extensions: List<Extension>,
)

/** A parsed `Certificate`. [der] is the caller's array, not a copy; every span indexes it. */
internal class ParsedCertificate(
    val der: ByteArray,
    val tbs: Tbs,
    val signatureAlgorithm: Span,
    val signatureValue: Span,
    val nonMinimalHeaders: List<NonMinimalHeader>,
    val ignoredElements: List<IgnoredElement>,
    val steps: Long,
) {
    fun rawSerial(): ByteArray = tbs.serial.bytes(der)

    fun rawSpki(): ByteArray = tbs.spki.bytes(der)

    fun rawSubject(): ByteArray = tbs.subject.bytes(der)

    fun rawIssuer(): ByteArray = tbs.issuer.bytes(der)

    /** Extensions with [oid], in certificate order; duplicates are reported, never rejected (spec §9.2). */
    fun extensions(oid: String): List<Extension> = tbs.extensions.filter { it.oidDotted == oid }

    /** OIDs that occur more than once. */
    fun duplicateExtensionOids(): Set<String> =
        tbs.extensions
            .mapNotNull { it.oidDotted }
            .groupingBy { it }
            .eachCount()
            .filterValues { it > 1 }
            .keys
}

internal sealed class CertificateParse {
    class Parsed(
        val certificate: ParsedCertificate,
    ) : CertificateParse()

    class Failed(
        val reason: ParseReason,
        val detail: String,
    ) : CertificateParse()
}

/**
 * The one minimal parse of `Certificate` → `tbsCertificate` (spec §5.5, §9.2). Structurally strict except where the
 * JDK's `X509CertInfo` tolerates trailing elements (after `subjectPublicKeyInfo`, inside `[3]`, after `extnValue`;
 * each recorded as an [IgnoredElement]; `[0]` stays strict because the producer flattens it): definite lengths, single-byte tags in their places, the RFC 5280
 * elements in order, nothing after `Certificate`. Semantically lenient: names, keys, algorithm parameters and extension values are not
 * descended into; unknown or critical extensions, duplicate OIDs, any INTEGER serial (negative, empty, over 20 bytes)
 * and non-DER times are accepted. Returns [CertificateParse.Failed] for every rejection; no other exception escapes.
 */
internal object CertificateParser {
    private const val SEQUENCE = 0x30
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03
    private const val OCTET_STRING = 0x04
    private const val OBJECT_IDENTIFIER = 0x06
    private const val BOOLEAN = 0x01
    private const val VERSION = 0xa0
    private const val ISSUER_UID = 0x81
    private const val SUBJECT_UID = 0x82
    private const val EXTENSIONS = 0xa3
    private const val CONSTRUCTED = 0x20

    fun parse(der: ByteArray): CertificateParse {
        if (der.size > RevoktLimits.MAX_CERT_BYTES) {
            return CertificateParse.Failed(
                ParseReason.OVERSIZE,
                "${der.size} bytes, cap ${RevoktLimits.MAX_CERT_BYTES}",
            )
        }
        val ctx = ParseContext()
        return try {
            CertificateParse.Parsed(parseCertificate(der, ctx))
        } catch (e: DerException) {
            CertificateParse.Failed(ParseReason.STRUCTURE, e.message ?: "malformed")
        }
    }

    private fun parseCertificate(
        der: ByteArray,
        ctx: ParseContext,
    ): ParsedCertificate {
        val top = DerReader(der, 0, der.size, ctx)
        val certificate = top.read(SEQUENCE, HeaderSite.CERTIFICATE)
        top.requireEnd("Certificate")
        val fields = top.child(certificate)
        val tbsTlv = fields.read(SEQUENCE, HeaderSite.TBS)
        val algorithm = fields.read(SEQUENCE, HeaderSite.SIGNATURE_ALGORITHM)
        val signature = fields.read(BIT_STRING, HeaderSite.SIGNATURE_VALUE)
        fields.requireEnd("signatureValue")
        val tbs = parseTbs(der, fields.child(tbsTlv), tbsTlv, ctx)
        return ParsedCertificate(
            der,
            tbs,
            algorithm.tlv,
            signature.content,
            ctx.nonMinimal.toList(),
            ctx.ignored.toList(),
            ctx.steps,
        )
    }

    private fun parseTbs(
        der: ByteArray,
        r: DerReader,
        tlv: Tlv,
        ctx: ParseContext,
    ): Tbs {
        val version =
            r.readOptional(VERSION, HeaderSite.VERSION)?.let { wrapper ->
                val inner = r.child(wrapper)
                // Strict, unlike the rest of the tail (spec §9.2): ct-go does not bound explicit [0], so anything after
                // the INTEGER becomes the producer's next TBS fields and it would key a different serial.
                inner.read(INTEGER, HeaderSite.VERSION_INTEGER).also { inner.requireEnd("version") }.content
            }
        val serial = r.read(INTEGER, HeaderSite.SERIAL)
        val signature = r.read(SEQUENCE, HeaderSite.TBS_SIGNATURE)
        val issuer = r.read(SEQUENCE, HeaderSite.ISSUER)
        val validity = parseValidity(der, r.child(r.read(SEQUENCE, HeaderSite.VALIDITY)), ctx)
        val subject = r.read(SEQUENCE, HeaderSite.SUBJECT)
        val spki = r.read(SEQUENCE, HeaderSite.SPKI)
        val extensions = parseTail(der, r, ctx)
        return Tbs(
            tlv.tlv,
            version,
            serial.content,
            signature.tlv,
            issuer.tlv,
            validity,
            subject.tlv,
            spki.tlv,
            extensions.orEmpty(),
        )
    }

    private fun parseValidity(
        der: ByteArray,
        r: DerReader,
        ctx: ParseContext,
    ): Validity {
        val notBefore = readTime(r, HeaderSite.NOT_BEFORE)
        val notAfter = readTime(r, HeaderSite.NOT_AFTER)
        r.requireEnd("validity")
        return Validity(
            notBefore.tlv,
            DerTime.decode(notBefore.tag, der, notBefore.content, ctx),
            notAfter.tlv,
            DerTime.decode(notAfter.tag, der, notAfter.content, ctx),
        )
    }

    private fun readTime(
        r: DerReader,
        site: HeaderSite,
    ): Tlv {
        val tag = r.peekTag()
        if (tag != DerTime.UTC_TIME && tag != DerTime.GENERALIZED_TIME) fail("$site is not UTCTime or GeneralizedTime")
        return r.readAny(site)
    }

    /**
     * The elements after `subjectPublicKeyInfo`, read in turn as the JDK's `X509CertInfo` reads them (spec §9.2):
     * `[1]` then `[2]`, each in either form, then a constructed `[3]`. The first element that does not fit ends the read;
     * it must be a well-formed TLV and is ignored with everything after it. After `[3]` the rest is ignored unparsed.
     */
    private fun parseTail(
        der: ByteArray,
        r: DerReader,
        ctx: ParseContext,
    ): List<Extension> {
        var tag = r.peekTag()
        if (tag and CONSTRUCTED.inv() == ISSUER_UID) {
            r.readAny(HeaderSite.ISSUER_UID)
            tag = r.peekTag()
        }
        if (tag and CONSTRUCTED.inv() == SUBJECT_UID) {
            r.readAny(HeaderSite.SUBJECT_UID)
            tag = r.peekTag()
        }
        if (tag == EXTENSIONS) {
            val extensions = parseExtensions(der, r.child(r.readAny(HeaderSite.EXTENSIONS_WRAPPER)), ctx)
            r.ignoreRest(IgnoredSite.TBS_AFTER_EXTENSIONS)
            return extensions
        }
        if (r.hasMore()) {
            val stop = r.readAny(HeaderSite.TBS_STOP)
            ctx.ignored.add(IgnoredElement(stop.tlv, IgnoredSite.TBS_AFTER_STOP))
            r.ignoreRest(IgnoredSite.TBS_AFTER_STOP)
        }
        return emptyList()
    }

    private fun parseExtensions(
        der: ByteArray,
        wrapper: DerReader,
        ctx: ParseContext,
    ): List<Extension> {
        val list = wrapper.read(SEQUENCE, HeaderSite.EXTENSIONS)
        wrapper.ignoreRest(IgnoredSite.EXTENSIONS_WRAPPER_TRAILING)
        val r = wrapper.child(list)
        val out = ArrayList<Extension>()
        while (r.hasMore()) {
            val ext = r.read(SEQUENCE, HeaderSite.EXTENSION)
            val e = r.child(ext)
            val oid = e.read(OBJECT_IDENTIFIER, HeaderSite.EXTENSION_OID)
            val critical = e.readOptional(BOOLEAN, HeaderSite.EXTENSION_CRITICAL)
            if (critical != null &&
                critical.content.length != 1
            ) {
                fail("critical BOOLEAN of ${critical.content.length} bytes")
            }
            val value = e.read(OCTET_STRING, HeaderSite.EXTENSION_VALUE)
            e.ignoreRest(IgnoredSite.EXTENSION_TRAILING)
            ctx.steps += oid.content.length
            val isCritical = critical != null && der[critical.content.start].toInt() != 0
            out.add(Extension(oid.content, Oid.dotted(der, oid.content), isCritical, value.content, ext.tlv))
        }
        return out
    }
}
