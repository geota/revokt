// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.canonicalSubject
import dev.revokt.engine.parse.CertificateParse
import dev.revokt.engine.parse.CertificateParser
import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.DerTime
import dev.revokt.engine.parse.Extension
import dev.revokt.engine.parse.ExtensionRead
import dev.revokt.engine.parse.ExtensionValues
import dev.revokt.engine.parse.HeaderSite
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

/** Why an x5u chain was rejected; every one is `SyncOutcome.FAILED` (spec §7.1 "x5u chain"). */
internal enum class X5uChainFailure {
    /**
     * A certificate up to the terminal does not parse ([CertificateParser]), or a link below it is not DER as
     * mozilla::pkix reads it: a non-minimal or indefinite length, bytes the parse skipped, unused bits in
     * `signatureValue`, a version above v4, a critical flag other than `00` or `FF`, or a time not in DER form or a
     * window ending before it starts.
     */
    PARSE,

    /** No certificate after the leaf has a pinned SPKI. */
    NOT_PINNED,

    /**
     * An extension OID occurs more than once, an extension the chain reads is malformed, a critical extension is not
     * one mozilla::pkix understands (or is one it enforces and revokt does not), or one it understands is empty.
     */
    EXTENSION,

    /** A link's signed TBS algorithm or its own key is below the algorithm floor, or its outer algorithm differs. */
    ALGORITHM,

    /** A non-leaf link has no basicConstraints, or `cA` is not TRUE. */
    NOT_CA,

    /** The leaf's basicConstraints has `cA = TRUE` (mozilla::pkix's `CA_CERT_USED_AS_END_ENTITY`). */
    CA_LEAF,

    /** A non-leaf link's `pathLenConstraint` is below the number of non-leaf links under it. */
    PATH_LEN,

    /** A non-leaf link has keyUsage without `keyCertSign`. */
    KEY_USAGE,

    /** A link's issuer name is empty, or a non-leaf link's subject is not its child's issuer, raw or canonical. */
    NAME,

    /** The leaf has no extKeyUsage, no codeSigning in it, or also OCSPSigning; or a CA's extKeyUsage lacks codeSigning. */
    EKU,

    /** The leaf's subjectAltName is absent or is not exactly one dNSName equal to [X5U_LEAF_NAME]. */
    SAN,

    /** A link's signature is not `VERIFIED` under its issuer's SPKI: `INVALID`, `UNSUPPORTED` or a verifier throw. */
    SIGNATURE,
}

/**
 * The x5u path up to the pinned terminal: [links] are the leaf (index 0) and every certificate below the terminal, in
 * x5u order, and [windows] their validity windows in epoch milliseconds, read but not yet checked. Only
 * [validateX5uChain] makes one, once every check but the validity periods passed. The terminal and anything after it
 * are not kept.
 */
internal class X5uPath private constructor(
    val links: List<ParsedCertificate>,
    val windows: List<LongRange>,
) {
    /** The leaf's `SubjectPublicKeyInfo` TLV, the key [ContentSignature] verifies under. */
    val leafSpki: ByteArray get() = links[0].rawSpki()

    internal companion object {
        fun validate(
            chain: List<ByteArray>,
            pinned: Set<ByteString>,
            verifier: SignatureVerifier,
        ): X5uChainResult {
            require(chain.isNotEmpty()) { "an x5u chain has at least the leaf" }
            val certs = ArrayList<ParsedCertificate>()
            parseToTerminal(chain, pinned, certs)?.let { return it }
            val terminal = certs.lastIndex
            val windows = ArrayList<LongRange>(terminal)
            for (i in 0 until terminal) {
                val c = certs[i]
                (link(c, i) ?: if (i == 0) leaf(c) else issuer(certs, i))?.let { return it }
                windows +=
                    DerTimes.window(c.tbsBytes, c.tbs.validity) ?: return failed(X5uChainFailure.PARSE, i, "times")
            }
            signatures(certs, verifier)?.let { return it }
            return X5uChainResult.Valid(X5uPath(certs.subList(0, terminal).toList(), windows))
        }
    }
}

internal sealed class X5uChainResult {
    class Valid(
        val path: X5uPath,
    ) : X5uChainResult()

    /** [certIndex] is the x5u position of the certificate that failed; [verifierError] the message of a verifier throw. */
    class Failed(
        val failure: X5uChainFailure,
        val certIndex: Int,
        val detail: String,
        val verifierError: String? = null,
    ) : X5uChainResult() {
        override fun toString(): String = "Failed($failure at $certIndex: $detail)"
    }
}

/** [checkValidity]'s answer. */
internal sealed class X5uValidity {
    data object Valid : X5uValidity()

    /** A link outside its window: `SyncOutcome.CLOCK_SKEW`, stage `X5U` (spec §7.1). */
    class ClockSkew(
        val certIndex: Int,
        val detail: String,
    ) : X5uValidity()
}

/** The one SAN the content-signature leaf carries (spec §7.1 "leaf SAN exactly `onecrl.content-signature.mozilla.org`"). */
internal const val X5U_LEAF_NAME: String = "onecrl.content-signature.mozilla.org"

/**
 * Every check of the x5u chain but the validity periods (spec §7.1 "x5u chain", §6.5): a seed runs it before its
 * `records.json` is decoded and [checkValidity] after, at the decoded `<ts>`; a live sync runs both, at the local
 * clock. [chain] is the x5u body's DER, leaf first ([dev.revokt.engine.parse.X5uPem]); [pinned] holds SPKI SHA-256s.
 *
 * - **The terminal** is the first certificate after the leaf whose SPKI SHA-256 is in [pinned]; nothing after it is
 *   parsed. Only its SPKI is read: never its validity, CA bits, key usage or subject (mozilla::pkix's trust-anchor
 *   semantics). A certificate before it that does not parse is [X5uChainFailure.PARSE].
 * - **Every link below the terminal:** no extension OID twice (maintainer decision on #164: the JDK rejects even two
 *   identical copies); the signed TBS algorithm and the link's own key in the floor ([X5uFloor]); its signature
 *   `VERIFIED` under the next certificate's SPKI through [verifier], with the signed TBS algorithm.
 * - **Every non-leaf link below the terminal:** basicConstraints `cA = TRUE`; a `pathLenConstraint` at least the number
 *   of non-leaf links under it (mozilla::pkix's and webpki's count, self-issued links included); its subject equal to
 *   its child's issuer, raw or under `canonicalSubject`; `keyCertSign` when keyUsage is present.
 * - **The leaf:** extKeyUsage present with codeSigning; subjectAltName exactly one `GeneralName`, a dNSName equal to
 *   [X5U_LEAF_NAME] (the issue's narrow reading of "exactly").
 *
 * The extension readers are the strict ones ([ExtensionValues]); one that fails is [X5uChainFailure.EXTENSION]. Checks
 * run cheapest first, the signatures last, so the failure reported is the first in [X5uChainFailure] order of the first
 * pass that fails. Nothing here throws but a fatal error (spec §5.5, [verifyClassified]).
 */
internal fun validateX5uChain(
    chain: List<ByteArray>,
    pinned: Set<ByteString>,
    verifier: SignatureVerifier,
): X5uChainResult = X5uPath.validate(chain, pinned, verifier)

/**
 * The validity periods of [path] at [at] (epoch milliseconds; spec §7.1 "validity at verification time for the leaf
 * and every non-terminal link"): each link's `notBefore ≤ at ≤ notAfter`, both inclusive (RFC 5280 §4.1.2.5). The
 * terminal is never in [path], so its validity is never read.
 */
internal fun checkValidity(
    path: X5uPath,
    at: Long,
): X5uValidity {
    for ((i, window) in path.windows.withIndex()) {
        if (at !in window) return X5uValidity.ClockSkew(i, "$at outside $window")
    }
    return X5uValidity.Valid
}

/**
 * Parses [chain] into [certs] up to and including the terminal, the first certificate after the leaf whose SPKI SHA-256
 * is in [pinned]; nothing after it is parsed. Null when the terminal was found.
 */
private fun parseToTerminal(
    chain: List<ByteArray>,
    pinned: Set<ByteString>,
    certs: MutableList<ParsedCertificate>,
): X5uChainResult.Failed? {
    for ((i, der) in chain.withIndex()) {
        val parsed =
            when (val r = CertificateParser.parse(der)) {
                is CertificateParse.Parsed -> r.certificate
                is CertificateParse.Failed -> return failed(X5uChainFailure.PARSE, i, "${r.reason}: ${r.detail}")
            }
        certs.add(parsed)
        if (i > 0 && parsed.rawSpki().toByteString().sha256() in pinned) return null
    }
    return failed(X5uChainFailure.NOT_PINNED, chain.lastIndex, "no pinned SPKI after the leaf")
}

/** Each link of [certs] below the terminal (the last) verified under the next one's SPKI, leaf first. */
private fun signatures(
    certs: List<ParsedCertificate>,
    verifier: SignatureVerifier,
): X5uChainResult.Failed? {
    for (i in 0 until certs.lastIndex) {
        val c = certs[i]
        val issuerSpki = certs[i + 1].rawSpki()
        val checked =
            verifier.verifyClassified(
                c.tbs.signature.bytes(c.tbsBytes),
                issuerSpki,
                c.tbsBytes,
                c.envelope.signature,
            )
        if (checked.result != VerifyResult.VERIFIED) {
            return failed(X5uChainFailure.SIGNATURE, i, "${checked.result} under certificate ${i + 1}", checked.error)
        }
    }
    return null
}

private fun failed(
    failure: X5uChainFailure,
    certIndex: Int,
    detail: String,
    verifierError: String? = null,
) = X5uChainResult.Failed(failure, certIndex, detail, verifierError)

/** The extension's value, or null when absent; a read that fails is passed to [reject] as [X5uChainFailure.EXTENSION]. */
private inline fun <T : Any> ExtensionRead<T>.valueOr(
    certIndex: Int,
    what: String,
    reject: (X5uChainResult.Failed) -> Nothing,
): T? =
    when (this) {
        ExtensionRead.Absent -> null
        is ExtensionRead.Value -> value
        is ExtensionRead.Failed -> reject(failed(X5uChainFailure.EXTENSION, certIndex, "$what $reason: $detail"))
    }

/**
 * The checks every link below the terminal gets before its signature: DER ([notDer]), a non-empty issuer name
 * (mozilla::pkix's `CheckIssuer`), the outer algorithm equal to the signed one (`CheckSignatureAlgorithm`, NULL and
 * absent parameters equal), unique extension OIDs, the algorithm floor.
 */
private fun link(
    c: ParsedCertificate,
    i: Int,
): X5uChainResult.Failed? {
    notDer(c)?.let { return failed(X5uChainFailure.PARSE, i, "not DER: $it") }
    if (c.tbs.issuer.length == EMPTY_NAME_TLV) return failed(X5uChainFailure.NAME, i, "empty issuer name")
    if (c.envelope.algorithmIdMismatch) {
        return failed(X5uChainFailure.ALGORITHM, i, "signatureAlgorithm is not the signed TBS algorithm")
    }
    val duplicates = c.duplicateExtensionOids()
    if (duplicates.isNotEmpty()) return failed(X5uChainFailure.EXTENSION, i, "duplicate extensions $duplicates")
    Understood.rejected(c)?.let { return failed(X5uChainFailure.EXTENSION, i, it) }
    if (!X5uFloor.signature(c.tbs.signature.bytes(c.tbsBytes))) {
        return failed(X5uChainFailure.ALGORITHM, i, "signature algorithm below the floor")
    }
    if (!X5uFloor.key(c.rawSpki())) return failed(X5uChainFailure.ALGORITHM, i, "key below the floor")
    return null
}

/**
 * The leaf rules: not a CA, a readable keyUsage if present, codeSigning in extKeyUsage without OCSPSigning, and exactly
 * one SAN, the dNSName [X5U_LEAF_NAME]. The not-a-CA, keyUsage and OCSPSigning rules are mozilla::pkix's
 * (`CheckBasicConstraints`, `CheckKeyUsage`, `CheckExtendedKeyUsage` for an end entity; maintainer decision
 * 2026-11-06, pending in the next spec revision).
 */
private fun leaf(c: ParsedCertificate): X5uChainResult.Failed? {
    val bc = ExtensionValues.basicConstraints(c).valueOr(0, "basicConstraints") { return it }
    if (bc?.ca == true) return failed(X5uChainFailure.CA_LEAF, 0, "the leaf has cA TRUE")
    ExtensionValues.keyUsage(c).valueOr(0, "keyUsage") { return it }
    val eku = ExtensionValues.extendedKeyUsage(c).valueOr(0, "extKeyUsage") { return it }
    if (eku == null || !eku.contains(CODE_SIGNING)) {
        return failed(X5uChainFailure.EKU, 0, "no codeSigning in extKeyUsage")
    }
    if (eku.contains(OCSP_SIGNING)) return failed(X5uChainFailure.EKU, 0, "OCSPSigning in extKeyUsage")
    val san = ExtensionValues.subjectAltName(c).valueOr(0, "subjectAltName") { return it }
    val names = san?.names.orEmpty()
    val only = names.singleOrNull()
    if (only == null || only.tag != ExtensionValues.DNS_NAME || only.content.utf8() != X5U_LEAF_NAME) {
        return failed(X5uChainFailure.SAN, 0, "${names.size} names, not just the dNSName $X5U_LEAF_NAME")
    }
    return null
}

/** The rules of the non-leaf link [i]: a CA within its path length, named as its child's issuer, signing certificates. */
private fun issuer(
    certs: List<ParsedCertificate>,
    i: Int,
): X5uChainResult.Failed? {
    val c = certs[i]
    val bc = ExtensionValues.basicConstraints(c).valueOr(i, "basicConstraints") { return it }
    if (bc == null) return failed(X5uChainFailure.NOT_CA, i, "no basicConstraints")
    if (!bc.ca) return failed(X5uChainFailure.NOT_CA, i, "cA is not TRUE")
    // The non-leaf links under link i are links 1 to i − 1.
    val pathLen = bc.pathLen
    if (pathLen != null && i - 1 > pathLen) {
        return failed(X5uChainFailure.PATH_LEN, i, "pathLenConstraint $pathLen with ${i - 1} CAs under it")
    }
    if (!chains(certs[i - 1].rawIssuer(), c.rawSubject())) {
        return failed(X5uChainFailure.NAME, i, "subject is not the issuer of certificate ${i - 1}")
    }
    val ku = ExtensionValues.keyUsage(c).valueOr(i, "keyUsage") { return it }
    if (ku?.keyCertSign == false) return failed(X5uChainFailure.KEY_USAGE, i, "keyUsage without keyCertSign")
    // mozilla::pkix and webpki check the required EKU on every certificate that has one (maintainer decision
    // 2026-11-06, pending in the next spec revision); the terminal is never read.
    val eku = ExtensionValues.extendedKeyUsage(c).valueOr(i, "extKeyUsage") { return it }
    if (eku?.contains(CODE_SIGNING) == false) return failed(X5uChainFailure.EKU, i, "extKeyUsage without codeSigning")
    return null
}

/** Spec §7.1 "subject name equal to the child's issuer (raw or canonical)": a null canonical form never matches. */
private fun chains(
    childIssuer: ByteArray,
    subject: ByteArray,
): Boolean {
    if (childIssuer.contentEquals(subject)) return true
    val canonical = canonicalSubject(subject) ?: return false
    return canonicalSubject(childIssuer) == canonical
}

/** `id-kp-codeSigning` (1.3.6.1.5.5.7.3.3), as OID content. */
private val CODE_SIGNING = byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03)

/** `id-kp-OCSPSigning` (1.3.6.1.5.5.7.3.9), as OID content. */
private val OCSP_SIGNING = byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09)

/** `30 00`: a `Name` with no RDN, under the minimal header [notDer] requires. */
private const val EMPTY_NAME_TLV = 2

private const val MAX_VERSION = 3

/**
 * Why [c] is not DER as mozilla::pkix's `BackCert::Init` reads it (`ERROR_BAD_DER`), or null when it is: every
 * header minimal and definite, nothing the parse skipped (an element after the SPKI or the unique ids, after
 * `Extensions` inside `[3]`, after `extnValue`), no unused bits in `signatureValue`, a version of v1 to v4
 * (`OptionalVersion`: the parser reads `[3]` whatever the version says, as Firefox does), and every critical flag `00`
 * or `FF` (`Boolean`; an explicit FALSE is accepted, as there). The times are [DerTimes]'.
 */
private fun notDer(c: ParsedCertificate): String? {
    val version = c.tbs.version
    val signatureValue = c.envelope.signatureValue
    return when {
        c.nonMinimalHeaders.isNotEmpty() -> "a non-minimal length at ${c.nonMinimalHeaders[0].site}"
        c.envelope.tbsIndefinite -> "an indefinite-length TBS"
        c.ignoredElements.isNotEmpty() -> "skipped bytes at ${c.ignoredElements[0].site}"
        signatureValue.length == 0 || c.der[signatureValue.start].toInt() != 0 -> "signatureValue has unused bits"
        version != null && (version.length != 1 || c.tbsBytes[version.start] !in 0..MAX_VERSION) -> "version"
        c.tbs.extensions.any { !criticalIsDer(c.tbsBytes, it) } -> "a critical flag other than 00 or FF"
        else -> null
    }
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

/**
 * The extensions mozilla::pkix's `BackCert::RememberExtension` understands (at `cac25a6`), so that a critical copy of any
 * other is `ERROR_UNKNOWN_CRITICAL_EXTENSION` (maintainer decision 2026-11-06, pending in the next spec revision).
 * OIDs are compared as encoded, as `MatchRest` does, so a non-minimal arc is an unknown extension.
 *
 * - Understood and checked here, or ignored by Firefox for an any-policy content signature (so a critical copy is
 *   accepted): keyUsage, subjectAltName, basicConstraints, extKeyUsage, certificatePolicies (`CheckCertificatePolicies`
 *   returns at once for anyPolicy), policyConstraints, inhibitAnyPolicy, authorityInfoAccess, the embedded SCT list,
 *   qcStatements, and a critical `id-pkix-ocsp-nocheck`.
 * - Netscape certificate type, when critical, only with basicConstraints and extKeyUsage present, as `BackCert::Init`.
 * - Understood and *enforced* by Firefox but not here: nameConstraints and the TLS feature (`CheckNameConstraints`,
 *   `CheckTLSFeatures`). A critical copy is rejected rather than ignored; a non-critical one is ignored.
 * - An understood extension with an empty value is rejected (`ERROR_EXTENSION_VALUE_INVALID`), but `ocsp-nocheck`.
 */
private object Understood {
    private val ACCEPTED =
        listOf(
            byteArrayOf(0x55, 0x1d, 0x0f), // keyUsage
            byteArrayOf(0x55, 0x1d, 0x11), // subjectAltName
            byteArrayOf(0x55, 0x1d, 0x13), // basicConstraints
            byteArrayOf(0x55, 0x1d, 0x20), // certificatePolicies
            byteArrayOf(0x55, 0x1d, 0x24), // policyConstraints
            byteArrayOf(0x55, 0x1d, 0x25), // extKeyUsage
            byteArrayOf(0x55, 0x1d, 0x36), // inhibitAnyPolicy
            pkix(0x01, 0x01), // authorityInfoAccess
            pkix(0x01, 0x03), // qcStatements
            byteArrayOf(0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6.toByte(), 0x79, 0x02, 0x04, 0x02), // embedded SCT list
        )

    /** Understood, and enforced by Firefox only: a critical copy cannot be honoured here. */
    private val ENFORCED = listOf(byteArrayOf(0x55, 0x1d, 0x1e), pkix(0x01, 0x18)) // nameConstraints, TLS feature

    private val OCSP_NOCHECK = pkix(0x30, 0x01, 0x05)
    private val NETSCAPE_CERT_TYPE =
        byteArrayOf(0x60, 0x86.toByte(), 0x48, 0x01, 0x86.toByte(), 0xf8.toByte(), 0x42, 0x01, 0x01)

    /** `id-pkix` (1.3.6.1.5.5.7) followed by [arcs], as OID content. */
    private fun pkix(vararg arcs: Int): ByteArray =
        byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07) + arcs.map { it.toByte() }

    /** Why one of [c]'s extensions fails mozilla::pkix's reading, or null. */
    fun rejected(c: ParsedCertificate): String? {
        for (e in c.tbs.extensions) {
            fun isOid(oid: ByteArray) = Oid.matches(c.tbsBytes, e.oid, oid)
            val accepted = ACCEPTED.any(::isOid)
            val enforced = ENFORCED.any(::isOid)
            if ((accepted || enforced) && e.value.length == 0) return "an empty ${e.oidDotted}"
            val alsoUnderstood = isOid(OCSP_NOCHECK) || (isOid(NETSCAPE_CERT_TYPE) && backsNetscape(c))
            if (!e.critical || accepted || alsoUnderstood) continue
            return "${if (enforced) "an unenforced" else "an unknown"} critical ${e.oidDotted}"
        }
        return null
    }

    /** `BackCert::Init`: a critical Netscape certificate type stands only beside basicConstraints and extKeyUsage. */
    private fun backsNetscape(c: ParsedCertificate): Boolean =
        c.extensions(ExtensionValues.BASIC_CONSTRAINTS).isNotEmpty() &&
            c.extensions(ExtensionValues.EXT_KEY_USAGE).isNotEmpty()
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
private object DerTimes {
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

/**
 * Spec §7.1's algorithm floor for every link below the terminal: "SHA-256 or stronger, RSA ≥ 2048, P-256 or stronger,
 * anything else `FAILED`". Read as Firefox's `AppTrustDomain` reads it (`CheckSignatureDigestAlgorithm`,
 * `CheckRSAPublicKeyModulusSizeInBits`, `CheckECDSACurveIsAcceptable` at `cac25a6`):
 *
 * - **Signatures:** RSA PKCS#1 v1.5 and ECDSA with SHA-256, SHA-384 or SHA-512, and `id-RSASSA-PSS` in exactly one
 *   of its three encodings ([PSS]): SHA-256, SHA-384 or SHA-512, MGF1 with the same hash, a salt of the hash length,
 *   the default trailer. These are the bytes of mozilla::pkix's `der::SignatureAlgorithmIdentifierValue` and
 *   rustls-pki-types' `alg_id::RSA_PSS_SHA256/384/512` (`data/alg-rsa-pss-sha*.der`). SHA-1, SHA-224, SHA-512/t,
 *   SHA-3, any other PSS encoding and every other scheme are below the floor.
 * - **Keys:** `rsaEncryption` with a modulus of at least 2048 significant bits, or `id-ecPublicKey` on P-256, P-384 or
 *   P-521 (`CheckSubjectPublicKeyInfoContents`). `id-RSASSA-PSS` keys (Firefox's `ERROR_UNSUPPORTED_KEYALG`),
 *   brainpool, P-224, EdDSA, ML-DSA and every other key are below it.
 *
 * Maintainer decision 2026-11-06, pending in the next spec revision: only this floor narrows; the walker's verifier
 * keeps its wider PSS rule (spec §3). Parameters beyond these are the verifier's to reject.
 */
internal object X5uFloor {
    private const val PKCS1 = "1.2.840.113549.1.1"
    private const val RSA_ENCRYPTION = "$PKCS1.1"
    private const val EC_PUBLIC_KEY = "1.2.840.10045.2.1"
    private const val MIN_RSA_BITS = 2048
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03

    /**
     * The three `id-RSASSA-PSS` `AlgorithmIdentifier` TLVs: SHA-256, SHA-384, SHA-512, each hash with NULL parameters,
     * MGF1 on the same hash, salt 32, 48 or 64, trailer absent.
     */
    private val PSS =
        listOf(
            // SHA-256
            "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c" +
                "301a06092a864886f70d010108300d06096086480165030402010500a203020120",
            // SHA-384
            "304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c" +
                "301a06092a864886f70d010108300d06096086480165030402020500a203020130",
            // SHA-512
            "304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c" +
                "301a06092a864886f70d010108300d06096086480165030402030500a203020140",
        ).map { it.decodeHex() }.toSet()

    /** sha256/384/512WithRSAEncryption and ecdsa-with-SHA256/384/512 (RFC 4055 §5, RFC 5758 §3.2). */
    private val SIGNATURES = (11..13).map { "$PKCS1.$it" }.toSet() + (2..4).map { "1.2.840.10045.4.3.$it" }

    /** P-256, P-384, P-521. */
    private val CURVES = setOf("1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35")

    /** Whether the signed TBS `AlgorithmIdentifier` TLV [sigAlg] is in the floor. */
    fun signature(sigAlg: ByteArray): Boolean {
        val algorithm = VerifierInput.algorithm(sigAlg) ?: return false
        return algorithm.oid in SIGNATURES || sigAlg.toByteString() in PSS
    }

    /** Whether the `SubjectPublicKeyInfo` TLV [spki] is in the floor. */
    fun key(spki: ByteArray): Boolean {
        val key = VerifierInput.spkiAlgorithm(spki) ?: return false
        return when (key.oid) {
            RSA_ENCRYPTION -> (modulusBits(spki) ?: 0) >= MIN_RSA_BITS
            EC_PUBLIC_KEY -> key.parametersOid in CURVES
            else -> false
        }
    }

    /**
     * The significant bits of `n` in the `RSAPublicKey` [spki]'s BIT STRING holds, or null when that is not a SEQUENCE
     * starting with a non-negative INTEGER behind a zero unused-bits octet; the verifier reads the rest.
     */
    private fun modulusBits(spki: ByteArray): Int? =
        try {
            val ctx = ParseContext()
            val top = DerReader(spki, 0, spki.size, ctx)
            val fields = top.child(top.read(SEQUENCE, HeaderSite.SPKI))
            fields.read(SEQUENCE, HeaderSite.SPKI)
            val bits = fields.read(BIT_STRING, HeaderSite.SPKI).content
            if (bits.length < 2 || spki[bits.start].toInt() != 0) return null
            val key = DerReader(spki, bits.start + 1, bits.end, ctx)
            val n = key.child(key.read(SEQUENCE, HeaderSite.SPKI)).read(INTEGER, HeaderSite.SPKI).content
            if (n.length == 0 || spki[n.start] < 0) return null
            var first = n.start
            while (first < n.end - 1 && spki[first].toInt() == 0) first++
            (n.end - first - 1) * Byte.SIZE_BITS +
                (Int.SIZE_BITS - (spki[first].toInt() and 0xff).countLeadingZeroBits())
        } catch (_: DerException) {
            null
        }
}
