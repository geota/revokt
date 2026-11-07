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
    LEAF_CA,

    /** A non-leaf link's `pathLenConstraint` is below the number of non-leaf links under it. */
    PATH_LEN,

    /** A non-leaf link has keyUsage without `keyCertSign`. */
    KEY_USAGE,

    /** A link's issuer name is empty, or a non-leaf link's subject is not its child's issuer, raw or canonical. */
    NAME,

    /**
     * The leaf's dNSName lies outside a CA's nameConstraints: not in its permitted dNSName subtrees, or in an excluded
     * one (mozilla::pkix's `ERROR_CERT_NOT_IN_NAME_SPACE`; spec revision 54).
     */
    NAME_CONSTRAINTS,

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
 * Every check of the x5u chain but the validity periods (spec revision 54, §7.1 "x5u chain"; §6.5): a seed runs it
 * before its `records.json` is decoded and [checkValidity] after, at the decoded `<ts>`; a live sync runs both, at the
 * local clock. [chain] is the x5u body's DER, leaf first ([dev.revokt.engine.parse.X5uPem]); [pinned] holds SPKI
 * SHA-256s. The chain follows mozilla::pkix (Firefox `cac25a6`):
 *
 * - **The terminal** is the first certificate after the leaf whose SPKI SHA-256 is in [pinned], found over the
 *   certificates as [CertificateParser] reads them leniently; nothing after it is parsed, and it is read for its SPKI
 *   alone. A certificate before it that does not parse is [X5uChainFailure.PARSE].
 * - **Every link below the terminal:** DER as mozilla::pkix reads it ([notDer], [DerTimes]); a non-empty issuer; the
 *   outer algorithm equal to the signed one; no extension OID twice; no critical extension mozilla::pkix does not
 *   understand, and no understood one empty; the algorithm floor and `CheckSubjectPublicKeyInfo` ([X5uFloor]); its
 *   signature `VERIFIED` under the next certificate's SPKI through [verifier], with the signed TBS algorithm.
 * - **The leaf:** not a CA; a well-formed basicConstraints and keyUsage if present; extKeyUsage with codeSigning and
 *   without OCSPSigning; exactly one SAN, the dNSName [X5U_LEAF_NAME]; an embedded SCT list, if any, one OCTET STRING.
 * - **Every non-leaf link below the terminal:** basicConstraints `cA = TRUE` within its `pathLenConstraint` (at most
 *   127); its subject equal to its child's issuer, raw or under `canonicalSubject`; `keyCertSign` when keyUsage is
 *   present; codeSigning when extKeyUsage is present; its TLS feature, if any, carried by its child; its
 *   nameConstraints satisfied by the leaf's dNSName ([DnsSubtrees]).
 *
 * The extension readers are the strict ones ([ExtensionValues]); anything malformed in a value they read is
 * [X5uChainFailure.EXTENSION]. The signatures are verified last. Nothing here throws but a fatal error (spec §5.5,
 * [verifyClassified]).
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
 * (`CheckBasicConstraints`, `CheckKeyUsage`, `CheckExtendedKeyUsage` for an end entity; spec revision 54).
 */
private fun leaf(c: ParsedCertificate): X5uChainResult.Failed? {
    // Every value the leaf rules read is parsed first (revision 55): a malformed one is EXTENSION, never SAN or EKU.
    val bc = basicConstraints(c, 0) { return it }
    keyUsage(c, 0) { return it }
    val eku = ExtensionValues.extendedKeyUsage(c).valueOr(0, "extKeyUsage") { return it }
    val san = ExtensionValues.subjectAltName(c).valueOr(0, "subjectAltName") { return it }
    if (!sctListIsOctetString(c)) return failed(X5uChainFailure.EXTENSION, 0, "SCT list not one OCTET STRING")
    if (bc?.ca == true) return failed(X5uChainFailure.LEAF_CA, 0, "the leaf has cA TRUE")
    if (eku == null || !eku.contains(CODE_SIGNING)) {
        return failed(X5uChainFailure.EKU, 0, "no codeSigning in extKeyUsage")
    }
    if (eku.contains(OCSP_SIGNING)) return failed(X5uChainFailure.EKU, 0, "OCSPSigning in extKeyUsage")
    val names = san?.names.orEmpty()
    val only = names.singleOrNull()
    if (only == null || only.tag != ExtensionValues.DNS_NAME || only.content.utf8() != X5U_LEAF_NAME) {
        return failed(X5uChainFailure.SAN, 0, "${names.size} names, not just the dNSName $X5U_LEAF_NAME")
    }
    return null
}

/**
 * mozilla::pkix's `ExtractSignedCertificateTimestampListFromExtension` on the leaf (`pkixbuild.cpp`): an embedded SCT
 * list extension's `extnValue` is exactly one OCTET STRING, under a minimal header, with nothing after it. Its content
 * is not read. True when the leaf has none.
 */
private fun sctListIsOctetString(c: ParsedCertificate): Boolean {
    val e = c.tbs.extensions.firstOrNull { Oid.matches(c.tbsBytes, it.oid, Oid.SCT_LIST_CONTENT) } ?: return true
    return try {
        val ctx = ParseContext()
        val r = DerReader(c.tbsBytes, e.value.start, e.value.end, ctx)
        r.read(OCTET_STRING, HeaderSite.EXTENSION_VALUE)
        r.requireEnd("SignedCertificateTimestampList")
        ctx.nonMinimal.isEmpty()
    } catch (_: DerException) {
        false
    }
}

private const val OCTET_STRING = 0x04

/** The rules of the non-leaf link [i]: a CA within its path length, named as its child's issuer, signing certificates. */
private fun issuer(
    certs: List<ParsedCertificate>,
    i: Int,
): X5uChainResult.Failed? {
    val c = certs[i]
    // Every value the CA rules read is parsed first (revision 55): a malformed one is EXTENSION.
    val bc = basicConstraints(c, i) { return it }
    val ku = keyUsage(c, i) { return it }
    val eku = ExtensionValues.extendedKeyUsage(c).valueOr(i, "extKeyUsage") { return it }
    val subtrees = nameConstraints(c, i) { return it }
    if (bc == null) return failed(X5uChainFailure.NOT_CA, i, "no basicConstraints")
    if (!bc.ca) return failed(X5uChainFailure.NOT_CA, i, "cA is not TRUE")
    // The non-leaf links under link i are links 1 to i − 1.
    val pathLen = bc.pathLen
    if (pathLen != null && i - 1 > pathLen) {
        return failed(X5uChainFailure.PATH_LEN, i, "pathLenConstraint $pathLen with ${i - 1} CAs under it")
    }
    val child = certs[i - 1]
    if (!chains(child.rawIssuer(), c.rawSubject())) {
        return failed(X5uChainFailure.NAME, i, "subject is not the issuer of certificate ${i - 1}")
    }
    if (ku?.keyCertSign == false) return failed(X5uChainFailure.KEY_USAGE, i, "keyUsage without keyCertSign")
    // mozilla::pkix and webpki check the required EKU on every certificate that has one (spec revision 54); the
    // terminal is never read.
    if (eku?.contains(CODE_SIGNING) == false) return failed(X5uChainFailure.EKU, i, "extKeyUsage without codeSigning")
    if (!tlsFeatures(c, child)) return failed(X5uChainFailure.EXTENSION, i, "the child lacks the TLS feature")
    // The leaf's one dNSName is X5U_LEAF_NAME, which leaf() required before any issuer is checked.
    if (subtrees?.permits(X5U_LEAF_NAME) == false) {
        return failed(X5uChainFailure.NAME_CONSTRAINTS, i, "the leaf is outside nameConstraints")
    }
    return null
}

/** [c]'s nameConstraints, null when absent; one revokt cannot read or evaluate is passed to [reject]. */
private inline fun nameConstraints(
    c: ParsedCertificate,
    i: Int,
    reject: (X5uChainResult.Failed) -> Nothing,
): DnsSubtrees? {
    val e = c.tbs.extensions.firstOrNull { Oid.matches(c.tbsBytes, it.oid, NAME_CONSTRAINTS) } ?: return null
    return DnsSubtrees.read(c.tbsBytes, e.value)
        ?: reject(failed(X5uChainFailure.EXTENSION, i, "nameConstraints that revokt does not evaluate"))
}

/** `id-ce-nameConstraints` (2.5.29.30), as OID content. */
private val NAME_CONSTRAINTS = byteArrayOf(0x55, 0x1d, 0x1e)

/** mozilla::pkix reads `pathLenConstraint` as `Integer` into a byte: 0 to 127 (`IntegralValueRestriction`). */
private const val MAX_PATH_LEN = 127

/** [c]'s basicConstraints, null when absent; a malformed one, or a pathLen above 127, is passed to [reject]. */
private inline fun basicConstraints(
    c: ParsedCertificate,
    i: Int,
    reject: (X5uChainResult.Failed) -> Nothing,
): BasicConstraints? {
    val bc = ExtensionValues.basicConstraints(c).valueOr(i, "basicConstraints", reject)
    if ((bc?.pathLen ?: 0) > MAX_PATH_LEN) reject(failed(X5uChainFailure.EXTENSION, i, "pathLenConstraint above 127"))
    return bc
}

/** [c]'s keyUsage, null when absent; a malformed one, or one with no bits (`CheckKeyUsage`), is passed to [reject]. */
private inline fun keyUsage(
    c: ParsedCertificate,
    i: Int,
    reject: (X5uChainResult.Failed) -> Nothing,
): KeyUsage? {
    val ku = ExtensionValues.keyUsage(c).valueOr(i, "keyUsage", reject)
    if (ku != null && ku.bits.isEmpty()) reject(failed(X5uChainFailure.EXTENSION, i, "keyUsage with no bits"))
    return ku
}

/**
 * mozilla::pkix's `CheckTLSFeatures`: when [issuer] has a TLS feature extension, [child] has one with the same value
 * bytes. Duplicates were rejected before, so each has at most one.
 */
private fun tlsFeatures(
    issuer: ParsedCertificate,
    child: ParsedCertificate,
): Boolean {
    val required =
        issuer.tbs.extensions.firstOrNull { Oid.matches(issuer.tbsBytes, it.oid, TLS_FEATURE) } ?: return true
    val carried = child.tbs.extensions.firstOrNull { Oid.matches(child.tbsBytes, it.oid, TLS_FEATURE) } ?: return false
    return required.value.bytes(issuer.tbsBytes).contentEquals(carried.value.bytes(child.tbsBytes))
}

/** `id-pe-tlsfeature` (1.3.6.1.5.5.7.1.24, RFC 7633), as OID content. */
private val TLS_FEATURE = byteArrayOf(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18)

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

/**
 * The extensions mozilla::pkix's `BackCert::RememberExtension` understands (at `cac25a6`), so that a critical copy of any
 * other is `ERROR_UNKNOWN_CRITICAL_EXTENSION` (spec revision 54).
 * OIDs are compared as encoded, as `MatchRest` does, so a non-minimal arc is an unknown extension.
 *
 * - Understood and checked here, or ignored by Firefox for an any-policy content signature (so a critical copy is
 *   accepted): keyUsage, subjectAltName, basicConstraints, extKeyUsage, certificatePolicies (`CheckCertificatePolicies`
 *   returns at once for anyPolicy), policyConstraints, inhibitAnyPolicy, authorityInfoAccess, the embedded SCT list,
 *   qcStatements, nameConstraints ([DnsSubtrees]), the TLS feature ([tlsFeatures]), and a critical
 *   `id-pkix-ocsp-nocheck`.
 * - Netscape certificate type, when critical, only with basicConstraints and extKeyUsage present, as `BackCert::Init`:
 *   its type bits are not read, and those two then decide.
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
            TLS_FEATURE, // enforced by [tlsFeatures]
            NAME_CONSTRAINTS, // enforced by [DnsSubtrees]
            byteArrayOf(0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6.toByte(), 0x79, 0x02, 0x04, 0x02), // embedded SCT list
        )

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
            // A critical Netscape certificate type is understood too, so it may not be empty either.
            val netscape = e.critical && isOid(NETSCAPE_CERT_TYPE)
            if ((accepted || netscape) && e.value.length == 0) return "an empty ${e.oidDotted}"
            val alsoUnderstood = isOid(OCSP_NOCHECK) || (isOid(NETSCAPE_CERT_TYPE) && backsNetscape(c))
            if (!e.critical || accepted || alsoUnderstood) continue
            return "an unknown critical ${e.oidDotted}"
        }
        return null
    }

    /** `BackCert::Init`: a critical Netscape certificate type stands only beside basicConstraints and extKeyUsage. */
    private fun backsNetscape(c: ParsedCertificate): Boolean =
        c.extensions(ExtensionValues.BASIC_CONSTRAINTS).isNotEmpty() &&
            c.extensions(ExtensionValues.EXT_KEY_USAGE).isNotEmpty()
}
