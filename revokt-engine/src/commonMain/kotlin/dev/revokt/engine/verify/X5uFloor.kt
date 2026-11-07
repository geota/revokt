// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParseContext
import dev.revokt.engine.parse.Span
import dev.revokt.engine.parse.VerifierInput
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString

/**
 * Spec §7.1's algorithm floor for every link below the terminal: "SHA-256 or stronger, RSA ≥ 2048, P-256 or stronger,
 * anything else `FAILED`". It is read as Firefox's `AppTrustDomain` and mozilla::pkix read it (`cac25a6`), and it is
 * spec revision 54's:
 *
 * - **Signatures** (`der::SignatureAlgorithmIdentifierValue`, `CheckSignatureDigestAlgorithm`): RSA PKCS#1 v1.5 and
 *   ECDSA with SHA-256, SHA-384 or SHA-512, their parameters NULL or absent; `id-RSASSA-PSS` in exactly one of its
 *   three encodings ([PSS]). These are SHA-256, SHA-384 or SHA-512, MGF1 with the same hash, a salt of the hash
 *   length and the default trailer: rustls-pki-types' `alg_id::RSA_PSS_SHA256/384/512`. SHA-1, SHA-224, SHA-512/t,
 *   SHA-3, any other PSS encoding and every other scheme are below the floor.
 * - **Keys** (`CheckSubjectPublicKeyInfo`): an SPKI of an `AlgorithmIdentifier` and a BIT STRING with no unused bits,
 *   minimal headers, nothing after either. `rsaEncryption` must have NULL parameters (absent fails) and an
 *   `RSAPublicKey` of two minimal positive INTEGERs (`der::PositiveInteger`), the modulus at least 2048 significant
 *   bits (counted in bits, a maintainer decision; Firefox counts bytes). `id-ecPublicKey` must have a namedCurve of
 *   P-256, P-384 or P-521 and an uncompressed point of exactly the curve's length. `id-RSASSA-PSS` keys (Firefox's
 *   `ERROR_UNSUPPORTED_KEYALG`), brainpool, P-224, EdDSA, ML-DSA and every other key are below it.
 *
 * Only this floor narrows: the walker's verifier keeps its wider rules (spec §3).
 */
internal object X5uFloor {
    private const val PKCS1 = "1.2.840.113549.1.1"
    private const val MIN_RSA_BITS = 2048
    private const val SEQUENCE = 0x30
    private const val INTEGER = 0x02
    private const val BIT_STRING = 0x03
    private const val NULL = 0x05
    private const val OBJECT_IDENTIFIER = 0x06
    private const val UNCOMPRESSED = 0x04
    private val SITE = HeaderSite.SPKI

    private val RSA_ENCRYPTION =
        byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01)
    private val EC_PUBLIC_KEY = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01)

    /** `05 00`: the only NULL the parameters of `rsaEncryption` may be (`ExpectTagAndEmptyValue`). */
    private val NULL_TLV = byteArrayOf(NULL.toByte(), 0x00)

    /** The namedCurve OID content and field length in bytes of P-256, P-384 and P-521 (`CheckSubjectPublicKeyInfo`). */
    private val CURVES =
        listOf(
            byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07) to 32,
            byteArrayOf(0x2b, 0x81.toByte(), 0x04, 0x00, 0x22) to 48,
            byteArrayOf(0x2b, 0x81.toByte(), 0x04, 0x00, 0x23) to 66,
        )

    /** sha256/384/512WithRSAEncryption and ecdsa-with-SHA256/384/512 (RFC 4055 §5, RFC 5758 §3.2). */
    private val SIGNATURES = (11..13).map { "$PKCS1.$it" }.toSet() + (2..4).map { "1.2.840.10045.4.3.$it" }

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

    /** Whether the signed TBS `AlgorithmIdentifier` TLV [sigAlg] is in the floor. */
    fun signature(sigAlg: ByteArray): Boolean {
        if (sigAlg.toByteString() in PSS) return true
        val algorithm = VerifierInput.algorithm(sigAlg) ?: return false
        return algorithm.oid in SIGNATURES && algorithm.noParameters
    }

    /** Whether the `SubjectPublicKeyInfo` TLV [spki] passes `CheckSubjectPublicKeyInfo` and the floor. */
    fun key(spki: ByteArray): Boolean =
        try {
            val ctx = ParseContext()
            val top = DerReader(spki, 0, spki.size, ctx)
            val fields = top.child(top.read(SEQUENCE, SITE))
            top.requireEnd("subjectPublicKeyInfo")
            val algorithm = fields.child(fields.read(SEQUENCE, SITE))
            val bits = fields.read(BIT_STRING, SITE).content
            fields.requireEnd("subjectPublicKeyInfo")
            val oid = algorithm.read(OBJECT_IDENTIFIER, SITE).content
            val parameters = if (algorithm.hasMore()) algorithm.readAny(SITE) else null
            algorithm.requireEnd("AlgorithmIdentifier")
            val key = Span(bits.start + 1, bits.end)
            val inFloor =
                bits.length >= 2 && spki[bits.start].toInt() == 0 && parameters != null &&
                    when {
                        Oid.matches(spki, oid, RSA_ENCRYPTION) -> {
                            parameters.tlv.bytes(spki).contentEquals(NULL_TLV) && rsa(spki, key, ctx)
                        }

                        Oid.matches(spki, oid, EC_PUBLIC_KEY) -> {
                            parameters.tag == OBJECT_IDENTIFIER &&
                                ec(spki, parameters.content, key)
                        }

                        else -> {
                            false
                        }
                    }
            inFloor && ctx.nonMinimal.isEmpty()
        } catch (_: DerException) {
            false
        }

    /** `RSAPublicKey { n, e }` filling [key], both minimal and positive, `n` of at least [MIN_RSA_BITS] bits. */
    private fun rsa(
        b: ByteArray,
        key: Span,
        ctx: ParseContext,
    ): Boolean {
        val r = DerReader(b, key.start, key.end, ctx)
        val fields = r.child(r.read(SEQUENCE, SITE))
        r.requireEnd("RSAPublicKey")
        val n = fields.read(INTEGER, SITE).content
        val e = fields.read(INTEGER, SITE).content
        fields.requireEnd("RSAPublicKey")
        return positive(b, n) && positive(b, e) && bits(b, n) >= MIN_RSA_BITS
    }

    /** `der::PositiveInteger`: minimal, the top bit clear, not zero. */
    private fun positive(
        b: ByteArray,
        content: Span,
    ): Boolean =
        Keyability.minimalInteger(b, content) && b[content.start] >= 0 &&
            !(content.length == 1 && b[content.start].toInt() == 0)

    /** The significant bits of the minimal positive INTEGER at [content]; a `00` prefix adds none. */
    private fun bits(
        b: ByteArray,
        content: Span,
    ): Int =
        (content.length - 1) * Byte.SIZE_BITS +
            (Int.SIZE_BITS - (b[content.start].toInt() and 0xff).countLeadingZeroBits())

    /** An uncompressed point of exactly [curveOid]'s length, on P-256, P-384 or P-521. */
    private fun ec(
        b: ByteArray,
        curveOid: Span,
        key: Span,
    ): Boolean {
        val fieldBytes = CURVES.firstOrNull { Oid.matches(b, curveOid, it.first) }?.second ?: return false
        return key.length == 1 + 2 * fieldBytes && b[key.start].toInt() == UNCOMPRESSED
    }
}
