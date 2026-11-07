// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.BasicConstraints
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.DerTime
import dev.revokt.engine.parse.Extension
import dev.revokt.engine.parse.ExtensionRead
import dev.revokt.engine.parse.ExtensionValues
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.KeyUsage
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParseContext
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.Validity
import dev.revokt.engine.parse.VerifierInput
import dev.revokt.verify.verifyClassified
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString

private const val MAX_VERSION = 3

/**
 * Why [c] is not DER as mozilla::pkix's `BackCert::Init` reads it (`ERROR_BAD_DER`), or null when it is: every
 * header minimal and definite, nothing the parse skipped (an element after the SPKI or the unique ids, after
 * `Extensions` inside `[3]`, after `extnValue`), no unused bits in `signatureValue`, a version of v1 to v4
 * (`OptionalVersion`: the parser reads `[3]` whatever the version says, as Firefox does), and every critical flag `00`
 * or `FF` (`Boolean`; an explicit FALSE is accepted, as there). The times are [DerTimes]'.
 */
internal fun notDer(c: ParsedCertificate): String? = envelopeNotDer(c) ?: tbsNotDer(c)

/**
 * The envelope's part of [notDer]: minimal definite headers, a definite TBS and outer `signatureAlgorithm` (the parser
 * accepts both indefinite, as the JDK does; mozilla::pkix does not), no unused bits in `signatureValue`.
 */
private fun envelopeNotDer(c: ParsedCertificate): String? {
    val signatureValue = c.envelope.signatureValue
    return when {
        outerNonMinimal(c) != null -> "a non-minimal length at ${outerNonMinimal(c)}"
        c.envelope.tbsIndefinite -> "an indefinite-length TBS"
        c.der[c.envelope.signatureAlgorithm.start + 1].toInt() and 0xff == INDEFINITE -> "an indefinite outer algorithm"
        signatureValue.length == 0 || c.der[signatureValue.start].toInt() != 0 -> "signatureValue has unused bits"
        else -> null
    }
}

/**
 * The TBS's part of [notDer]: a minimal serial, nothing the parse skipped, unique ids only in their primitive forms
 * (mozilla::pkix's `SkipOptionalImplicitPrimitiveTag`; the parser also reads `a1` and `a2`), the version, and the
 * critical flags.
 */
private fun tbsNotDer(c: ParsedCertificate): String? {
    val version = c.tbs.version
    return when {
        !Keyability.minimalInteger(c.tbsBytes, c.tbs.serial) -> "serialNumber is not a minimal INTEGER"
        c.ignoredElements.isNotEmpty() -> "skipped bytes at ${c.ignoredElements[0].site}"
        constructedUniqueId(c) -> "a constructed unique id"
        version != null && (version.length != 1 || c.tbsBytes[version.start] !in 0..MAX_VERSION) -> "version"
        c.tbs.extensions.any { !criticalIsDer(c.tbsBytes, it) } -> "a critical flag other than 00 or FF"
        else -> null
    }
}

/**
 * The first non-minimal header of [c]'s outer structure, or null. The parser also reads inside the SKI and AKI values,
 * which revokt does not read and mozilla::pkix ignores, so headers there are not the outer structure's (revision 55).
 */
private fun outerNonMinimal(c: ParsedCertificate): HeaderSite? =
    c.nonMinimalHeaders.firstOrNull { it.site !in INNER_SITES }?.site

private val INNER_SITES = setOf(HeaderSite.SKI, HeaderSite.AKI, HeaderSite.AKI_KEY_ID)

private const val INDEFINITE = 0x80
private const val CONSTRUCTED_ISSUER_UID = 0xa1
private const val CONSTRUCTED_SUBJECT_UID = 0xa2

/** Whether a unique id after [c]'s SPKI is in its constructed form; the parser already read these elements. */
private fun constructedUniqueId(c: ParsedCertificate): Boolean {
    val r = DerReader(c.tbsBytes, c.tbs.spki.end, c.tbs.tlv.end, ParseContext())
    while (r.hasMore()) {
        val tag = r.peekTag()
        if (tag == CONSTRUCTED_ISSUER_UID || tag == CONSTRUCTED_SUBJECT_UID) return true
        r.readAny(HeaderSite.TBS_STOP)
    }
    return false
}

/** Whether [e]'s critical BOOLEAN, if written, is `00` or `FF`; the parser already read [e], so nothing here throws. */
private fun criticalIsDer(
    b: ByteArray,
    e: Extension,
): Boolean {
    val r = DerReader(b, e.tlv.start, e.tlv.end, ParseContext())
    val fields = r.child(r.read(SEQUENCE, HeaderSite.EXTENSION))
    fields.read(OBJECT_IDENTIFIER, HeaderSite.EXTENSION_OID)
    val flag = fields.readOptional(BOOLEAN, HeaderSite.EXTENSION_CRITICAL) ?: return true
    return ExtensionValues.boolean(b, flag.content)
}

private const val SEQUENCE = 0x30
private const val OBJECT_IDENTIFIER = 0x06
private const val BOOLEAN = 0x01

/**
 * A link's validity as mozilla::pkix's `TimeChoice` and `ParseValidity` read it (`ERROR_INVALID_DER_TIME`): each time
 * `YYMMDDHHMMSSZ` (`UTCTime`, years 1950 to 2049) or `YYYYMMDDHHMMSSZ` (`GeneralizedTime`), every field in range for
 * its month and year, seconds below 60, the year 1970 or later, and `notBefore ≤ notAfter`. The parser's lenient
 * [dev.revokt.engine.parse.DerTime] reads more than this; nothing it reads beyond is a DER time.
 */
@Suppress("MagicNumber") // the field positions and ranges of X.680 times, and days_from_civil's constants
internal object DerTimes {
    private const val UTC_DIGITS = 12
    private const val GENERALIZED_DIGITS = 14
    private const val UTC_PIVOT = 50
    private const val MIN_YEAR = 1970
    private const val FEBRUARY = 2
    private val THIRTY_DAYS = setOf(4, 6, 9, 11)

    /** The window `notBefore..notAfter` in epoch milliseconds, or null when it is not two DER times in order. */
    fun window(
        b: ByteArray,
        v: Validity,
    ): LongRange? {
        val notBefore = millis(b, v.notBefore) ?: return null
        val notAfter = millis(b, v.notAfter) ?: return null
        return if (notBefore <= notAfter) notBefore..notAfter else null
    }

    /** The time TLV [tlv] (UTCTime or GeneralizedTime, which the parser checked) in epoch milliseconds, or null. */
    private fun millis(
        b: ByteArray,
        tlv: Span,
    ): Long? {
        val utc = b[tlv.start].toInt() == DerTime.UTC_TIME
        val digits = if (utc) UTC_DIGITS else GENERALIZED_DIGITS
        if (tlv.length != digits + 3 || b[tlv.end - 1].toInt() != 'Z'.code) return null
        val p = pairs(b, tlv.start + 2, digits / 2) ?: return null
        val year = if (utc) (if (p[0] < UTC_PIVOT) 2000 else 1900) + p[0] else p[0] * 100 + p[1]
        val f = if (utc) 1 else 2
        val month = p[f]
        val day = p[f + 1]
        if (year < MIN_YEAR || month !in 1..12 || day !in 1..days(year, month)) return null
        val seconds = clock(p[f + 2], p[f + 3], p[f + 4]) ?: return null
        return civilDays(year, month, day) * 86_400_000L + seconds * 1000L
    }

    /** [count] two-digit decimal numbers from [from], or null when an octet is not a digit. */
    private fun pairs(
        b: ByteArray,
        from: Int,
        count: Int,
    ): IntArray? {
        val out = IntArray(count)
        for (k in 0 until count) {
            val hi = b[from + 2 * k] - '0'.code.toByte()
            val lo = b[from + 2 * k + 1] - '0'.code.toByte()
            if (hi !in 0..9 || lo !in 0..9) return null
            out[k] = hi * 10 + lo
        }
        return out
    }

    /** Seconds into the day of [hour]:[minute]:[second], or null when one is out of range (no leap second, as there). */
    private fun clock(
        hour: Int,
        minute: Int,
        second: Int,
    ): Int? = if (hour > 23 || minute > 59 || second > 59) null else (hour * 60 + minute) * 60 + second

    private fun days(
        year: Int,
        month: Int,
    ): Int =
        when (month) {
            FEBRUARY -> if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) 29 else 28
            in THIRTY_DAYS -> 30
            else -> 31
        }

    /** Days since 1970-01-01 of a Gregorian date from 1970 on (Howard Hinnant's `days_from_civil`). */
    private fun civilDays(
        year: Int,
        month: Int,
        day: Int,
    ): Long {
        val y = if (month <= FEBRUARY) year - 1 else year
        val era = y / 400
        val yoe = y - era * 400
        val doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097L + doe - 719_468
    }
}
