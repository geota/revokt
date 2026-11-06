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
import dev.revokt.engine.parse.ExtensionRead
import dev.revokt.engine.parse.ExtensionValues
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.ParseContext
import dev.revokt.engine.parse.ParsedCertificate
import dev.revokt.engine.parse.VerifierInput
import dev.revokt.verify.verifyClassified
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** Why an x5u chain was rejected; every one is `SyncOutcome.FAILED` (spec §7.1 "x5u chain"). */
internal enum class X5uChainFailure {
    /** A certificate up to the terminal does not parse ([CertificateParser]). */
    PARSE,

    /** No certificate after the leaf has a pinned SPKI. */
    NOT_PINNED,

    /** An extension OID occurs more than once, or an extension the chain reads is malformed. */
    EXTENSION,

    /** A link's signed TBS algorithm or its own key is below the algorithm floor. */
    ALGORITHM,

    /** A non-leaf link has no basicConstraints, or `cA` is not TRUE. */
    NOT_CA,

    /** A non-leaf link's `pathLenConstraint` is below the number of non-leaf links under it. */
    PATH_LEN,

    /** A non-leaf link has keyUsage without `keyCertSign`. */
    KEY_USAGE,

    /** A non-leaf link's subject is not its child's issuer, raw or under `canonicalSubject`. */
    NAME,

    /** The leaf has no extKeyUsage, or no codeSigning purpose in it. */
    EKU,

    /** The leaf's subjectAltName is absent or is not exactly one dNSName equal to [X5U_LEAF_NAME]. */
    SAN,

    /** A link's signature is not `VERIFIED` under its issuer's SPKI: `INVALID`, `UNSUPPORTED` or a verifier throw. */
    SIGNATURE,
}

/**
 * The x5u path up to the pinned terminal: [links] are the leaf (index 0) and every certificate below the terminal, in
 * x5u order, each checked by [validateX5uChain]. The terminal and anything after it are not kept.
 */
internal class X5uPath(
    val links: List<ParsedCertificate>,
) {
    /** The leaf's `SubjectPublicKeyInfo` TLV, the key [ContentSignature] verifies under. */
    val leafSpki: ByteArray get() = links[0].rawSpki()
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

    /** A link whose window does not decode or ends before it starts, so no clock is inside it: `SyncOutcome.FAILED`. */
    class Failed(
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
): X5uChainResult {
    require(chain.isNotEmpty()) { "an x5u chain has at least the leaf" }
    val certs = ArrayList<ParsedCertificate>()
    var terminal = -1
    for ((i, der) in chain.withIndex()) {
        val parsed =
            when (val r = CertificateParser.parse(der)) {
                is CertificateParse.Parsed -> r.certificate
                is CertificateParse.Failed -> return failed(X5uChainFailure.PARSE, i, "${r.reason}: ${r.detail}")
            }
        certs.add(parsed)
        if (i > 0 && parsed.rawSpki().toByteString().sha256() in pinned) {
            terminal = i
            break
        }
    }
    if (terminal < 0) return failed(X5uChainFailure.NOT_PINNED, chain.lastIndex, "no pinned SPKI after the leaf")
    for (i in 0 until terminal) {
        (link(certs, i) ?: if (i == 0) leaf(certs[0]) else issuer(certs, i))?.let { return it }
    }
    for (i in 0 until terminal) {
        val c = certs[i]
        val checked =
            verifier.verifyClassified(
                c.tbs.signature.bytes(c.tbsBytes),
                certs[i + 1].rawSpki(),
                c.tbsBytes,
                c.envelope.signature,
            )
        if (checked.result != VerifyResult.VERIFIED) {
            return failed(X5uChainFailure.SIGNATURE, i, "${checked.result} under certificate ${i + 1}", checked.error)
        }
    }
    return X5uChainResult.Valid(X5uPath(certs.subList(0, terminal).toList()))
}

/**
 * The validity periods of [path] at [at] (epoch milliseconds; spec §7.1 "validity at verification time for the leaf
 * and every non-terminal link"): each link's `notBefore ≤ at ≤ notAfter`, both inclusive (RFC 5280 §4.1.2.5), at the
 * millisecond the parser decodes. The terminal is never in [path], so its validity is never read.
 */
internal fun checkValidity(
    path: X5uPath,
    at: Long,
): X5uValidity {
    for ((i, c) in path.links.withIndex()) {
        val window = c.tbs.validity
        val notBefore = window.notBeforeMillis
        val notAfter = window.notAfterMillis
        if (notBefore == null || notAfter == null || notBefore > notAfter) {
            return X5uValidity.Failed(i, "the validity window does not decode, or ends before it starts")
        }
        if (at !in notBefore..notAfter) return X5uValidity.ClockSkew(i, "$at outside $notBefore..$notAfter")
    }
    return X5uValidity.Valid
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

/** The checks every link below the terminal gets before its signature: unique extension OIDs, the algorithm floor. */
private fun link(
    certs: List<ParsedCertificate>,
    i: Int,
): X5uChainResult.Failed? {
    val c = certs[i]
    val duplicates = c.duplicateExtensionOids()
    if (duplicates.isNotEmpty()) return failed(X5uChainFailure.EXTENSION, i, "duplicate extensions $duplicates")
    if (!X5uFloor.signature(c.tbs.signature.bytes(c.tbsBytes))) {
        return failed(X5uChainFailure.ALGORITHM, i, "signature algorithm below the floor")
    }
    if (!X5uFloor.key(c.rawSpki())) return failed(X5uChainFailure.ALGORITHM, i, "key below the floor")
    return null
}

/** The leaf rules: codeSigning in extKeyUsage, and exactly one SAN, the dNSName [X5U_LEAF_NAME]. */
private fun leaf(c: ParsedCertificate): X5uChainResult.Failed? {
    val eku = ExtensionValues.extendedKeyUsage(c).valueOr(0, "extKeyUsage") { return it }
    if (eku?.contains(CODE_SIGNING) != true) return failed(X5uChainFailure.EKU, 0, "no codeSigning in extKeyUsage")
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

/**
 * Spec §7.1's algorithm floor for every link below the terminal: "SHA-256 or stronger, RSA ≥ 2048, P-256 or stronger,
 * anything else `FAILED`". Read as Firefox's `AppTrustDomain` reads it (`CheckSignatureDigestAlgorithm`,
 * `CheckRSAPublicKeyModulusSizeInBits`, `CheckECDSACurveIsAcceptable` at `cac25a6`):
 *
 * - **Signatures:** RSA PKCS#1 v1.5 and ECDSA with SHA-256, SHA-384 or SHA-512; `id-RSASSA-PSS` whose hash and MGF1
 *   hash are each one of those three. SHA-1, SHA-224, SHA-512/t, SHA-3 and every other scheme are below the floor.
 * - **Keys:** `rsaEncryption` or `id-RSASSA-PSS` with a modulus of at least 2048 significant bits; `id-ecPublicKey` on
 *   P-256, P-384 or P-521. Brainpool, P-224, EdDSA, ML-DSA and every other key are below it.
 *
 * Parameters beyond these are the verifier's to reject; the floor only bounds what can reach it.
 */
internal object X5uFloor {
    private const val PKCS1 = "1.2.840.113549.1.1"
    private const val RSA_ENCRYPTION = "$PKCS1.1"
    private const val RSASSA_PSS = "$PKCS1.10"
    private const val EC_PUBLIC_KEY = "1.2.840.10045.2.1"
    private const val MIN_RSA_BITS = 2048
    private const val SEQUENCE = 0x30
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03

    /** SHA-256, SHA-384, SHA-512 (NIST hash arcs 1 to 3). */
    private val HASHES = (1..3).map { "2.16.840.1.101.3.4.2.$it" }.toSet()

    /** sha256/384/512WithRSAEncryption and ecdsa-with-SHA256/384/512 (RFC 4055 §5, RFC 5758 §3.2). */
    private val SIGNATURES = (11..13).map { "$PKCS1.$it" }.toSet() + (2..4).map { "1.2.840.10045.4.3.$it" }

    /** P-256, P-384, P-521. */
    private val CURVES = setOf("1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35")

    /** Whether the signed TBS `AlgorithmIdentifier` TLV [sigAlg] is in the floor. */
    fun signature(sigAlg: ByteArray): Boolean {
        val algorithm = VerifierInput.algorithm(sigAlg) ?: return false
        if (algorithm.oid in SIGNATURES) return true
        if (algorithm.oid != RSASSA_PSS) return false
        val pss = VerifierInput.pss(algorithm.parameters) ?: return false
        return pss.hashOid in HASHES && pss.mgfHashOid in HASHES
    }

    /** Whether the `SubjectPublicKeyInfo` TLV [spki] is in the floor. */
    fun key(spki: ByteArray): Boolean {
        val key = VerifierInput.spkiAlgorithm(spki) ?: return false
        return when (key.oid) {
            RSA_ENCRYPTION, RSASSA_PSS -> (modulusBits(spki) ?: 0) >= MIN_RSA_BITS
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
