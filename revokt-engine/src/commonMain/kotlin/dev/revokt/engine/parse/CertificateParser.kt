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
 * The fields of `tbsCertificate` the engine reads (spec §5.5, §9.2 "Parser contract"). Spans index
 * [ParsedCertificate.tbsBytes], the re-encoded TBS: [serial] is the INTEGER content as encoded (sign and leading zeros
 * preserved, the producer's `RawValue.Bytes`); [signature], [issuer], [subject] and [spki] are complete TLVs. [version]
 * is null when the `[0]` element is absent. [tail] is what was read after the SPKI.
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
    val tail: Tail,
) {
    val extensions: List<Extension> get() = tail.extensions
}

/**
 * What the TBS tail held: the extensions, whether a unique id was read, and the `[3]` element if it was read (the
 * keyability profile's K2 reads both).
 */
internal class Tail(
    val extensions: List<Extension>,
    val uniqueIds: Boolean,
    val wrapper: Span?,
)

/**
 * What the engine reads from the extensions (spec §5.5, §9.2): the SCT union over every SCT-list extension, and the
 * SKI and AKI keyIdentifier of the first such extension that parses (null when none does).
 */
internal class ExtensionFields(
    val scts: Set<Sct>,
    val ski: Span?,
    val akiKeyId: Span?,
)

/**
 * The envelope around `Cert.tbs` (spec §9.2 "The unsigned headers"). [presentedTbs], [signatureAlgorithm] and
 * [signatureValue] (the BIT STRING content) index the input; [signature] is `Cert.sig`; [algorithmIdMismatch] is
 * spec §5.1's `AlgorithmIdMismatch`.
 */
internal class EnvelopeFields(
    val presentedTbs: Tlv,
    val tbsIndefinite: Boolean,
    val signatureAlgorithm: Span,
    val signatureValue: Span,
    val signature: ByteArray,
    val algorithmIdMismatch: Boolean,
)

/**
 * A parsed `Certificate`. [der] is the caller's array, not a copy. [tbsBytes] is `Cert.tbs` (spec §9.2): the TBS
 * re-encoded by the unsigned-header rule under a minimal header, the message the signature covers; [tbs] and every
 * [IgnoredElement] index it.
 */
internal class ParsedCertificate(
    val der: ByteArray,
    val tbsBytes: ByteArray,
    val tbs: Tbs,
    val envelope: EnvelopeFields,
    val nonMinimalHeaders: List<NonMinimalHeader>,
    val ignoredElements: List<IgnoredElement>,
    val fields: ExtensionFields,
    val steps: Long,
) {
    fun rawSerial(): ByteArray = tbs.serial.bytes(tbsBytes)

    fun rawSpki(): ByteArray = tbs.spki.bytes(tbsBytes)

    fun rawSubject(): ByteArray = tbs.subject.bytes(tbsBytes)

    fun rawIssuer(): ByteArray = tbs.issuer.bytes(tbsBytes)

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
 * The one minimal parse of `Certificate` → `tbsCertificate` (spec §5.5, §9.2). The unsigned envelope headers are read
 * as the JDK reads them ([Envelope]) and every TBS field is read from `Cert.tbs`. Structurally strict except where the
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
        val end = certificate.content.end
        val tbsElement = Envelope.read(der, certificate.content.start, end, SEQUENCE, HeaderSite.TBS, ctx)
        val algorithm =
            Envelope.read(
                der,
                tbsElement.presented.tlv.end,
                end,
                SEQUENCE,
                HeaderSite.SIGNATURE_ALGORITHM,
                ctx,
            )
        val signature =
            Envelope.read(
                der,
                algorithm.presented.tlv.end,
                end,
                BIT_STRING,
                HeaderSite.SIGNATURE_VALUE,
                ctx,
            )
        if (signature.presented.tlv.end !=
            end
        ) {
            fail("${end - signature.presented.tlv.end} trailing bytes after signatureValue")
        }
        val tbsBytes = tbsElement.reencoded()
        val tbsReader = DerReader(tbsBytes, 0, tbsBytes.size, ctx)
        val tbsTlv = tbsReader.read(SEQUENCE, HeaderSite.TBS)
        val tbs = parseTbs(tbsBytes, tbsReader.child(tbsTlv), tbsTlv, ctx)
        val extensionFields = extensionFields(tbsBytes, tbs.extensions, ctx)
        return ParsedCertificate(
            der,
            tbsBytes,
            tbs,
            EnvelopeFields(
                tbsElement.presented,
                tbsElement.indefinite,
                algorithm.presented.tlv,
                signature.presented.content,
                signatureBits(signature.content),
                AlgorithmIdentifiers.mismatch(der, algorithm, tbs.signature.bytes(tbsBytes)),
            ),
            ctx.nonMinimal.toList(),
            ctx.ignored.toList(),
            extensionFields,
            ctx.steps,
        )
    }

    /**
     * `Cert.sig` (spec §9.2): the BIT STRING content, re-encoded when indefinite (JDK 11 verifies that form), after its
     * unused-bits octet u, with the last octet's u low bits
     * cleared as `DerValue.getBitString` returns it. The forms the JDK rejects (no octet, u > 7, u > 0 with no further
     * octet) give the octets left with their padding cleared and are harmless: the platform rejects such input first.
     */
    private fun signatureBits(content: ByteArray): ByteArray {
        if (content.size < 2) return ByteArray(0)
        val bits = content.copyOfRange(1, content.size)
        val unused = minOf(content[0].toInt() and 0xff, 8)
        bits[bits.lastIndex] = (bits[bits.lastIndex].toInt() and (0xff shl unused)).toByte()
        return bits
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
        val tail = parseTail(der, r, ctx)
        return Tbs(
            tlv.tlv,
            version,
            serial.content,
            signature.tlv,
            issuer.tlv,
            validity,
            subject.tlv,
            spki.tlv,
            tail,
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
    ): Tail {
        var tag = r.peekTag()
        var uniqueIds = false
        if (tag and CONSTRUCTED.inv() == ISSUER_UID) {
            r.readAny(HeaderSite.ISSUER_UID)
            uniqueIds = true
            tag = r.peekTag()
        }
        if (tag and CONSTRUCTED.inv() == SUBJECT_UID) {
            r.readAny(HeaderSite.SUBJECT_UID)
            uniqueIds = true
            tag = r.peekTag()
        }
        if (tag == EXTENSIONS) {
            val wrapper = r.readAny(HeaderSite.EXTENSIONS_WRAPPER)
            val extensions = parseExtensions(der, r.child(wrapper), ctx)
            r.ignoreRest(IgnoredSite.TBS_AFTER_EXTENSIONS)
            return Tail(extensions, uniqueIds, wrapper.tlv)
        }
        if (r.hasMore()) {
            val stop = r.readAny(HeaderSite.TBS_STOP)
            ctx.ignored.add(IgnoredElement(stop.tlv, IgnoredSite.TBS_AFTER_STOP))
            r.ignoreRest(IgnoredSite.TBS_AFTER_STOP)
        }
        return Tail(emptyList(), uniqueIds, null)
    }

    /** Spec §9.2: the SCT pairs are the union over every SCT-list extension of the items its list keeps. */
    private fun extensionFields(
        der: ByteArray,
        extensions: List<Extension>,
        ctx: ParseContext,
    ): ExtensionFields {
        val scts = LinkedHashSet<Sct>()
        for (e in extensions) {
            if (Oid.matches(der, e.oid, Oid.SCT_LIST_CONTENT)) SctList.parse(der, e.value, ctx)?.let { scts.addAll(it) }
        }
        // The first copy that parses, not the first copy: the JDK reports a later well-formed SKI after a malformed one.
        val ski =
            extensions.firstNotNullOfOrNull {
                if (Oid.matches(
                        der,
                        it.oid,
                        Oid.SUBJECT_KEY_IDENTIFIER_CONTENT,
                    )
                ) {
                    KeyIdentifiers.ski(der, it.value, ctx)
                } else {
                    null
                }
            }
        val aki =
            extensions.firstNotNullOfOrNull {
                if (Oid.matches(
                        der,
                        it.oid,
                        Oid.AUTHORITY_KEY_IDENTIFIER_CONTENT,
                    )
                ) {
                    KeyIdentifiers.akiKeyId(der, it.value, ctx)
                } else {
                    null
                }
            }
        return ExtensionFields(scts, ski, aki)
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
