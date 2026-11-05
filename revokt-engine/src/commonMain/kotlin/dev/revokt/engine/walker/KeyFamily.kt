// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

/**
 * The key families of spec §3 "Verifier contract", used only to order candidates in [CandidateIndex.related] (§5.1): a
 * candidate whose key can have produced the child's signature algorithm is tried first. Never a filter, so a table gap
 * costs verifications, not soundness.
 *
 * - [RSA]: the keys `rsaEncryption` and `id-RSASSA-PSS`, the signatures RSA PKCS#1 v1.5 and `id-RSASSA-PSS`.
 * - [EC]: the key `id-ecPublicKey`, the ECDSA signatures.
 * - [EDDSA], [ML_DSA], [SLH_DSA]: one OID names both the key and the signature, so a key is compatible with exactly
 *   its own OID.
 * - [UNKNOWN]: any other OID, compatible with everything (composite included until spec §3's "as drafts settle").
 */
internal enum class KeyFamily {
    RSA,
    EC,
    EDDSA,
    ML_DSA,
    SLH_DSA,
    UNKNOWN,
    ;

    internal companion object {
        private const val PKCS1 = "1.2.840.113549.1.1"
        private const val NIST_SIG = "2.16.840.1.101.3.4.3"
        private const val RSASSA_PSS = "$PKCS1.10"

        private val KEYS: Map<String, KeyFamily> =
            mapOf(
                "$PKCS1.1" to RSA, // rsaEncryption
                RSASSA_PSS to RSA,
                "1.2.840.10045.2.1" to EC, // id-ecPublicKey
            )

        /** One OID for the key and the signature: Ed25519, Ed448 (RFC 8410), ML-DSA-44/65/87, the 12 SLH-DSA sets. */
        private val SAME_OID: Map<String, KeyFamily> =
            mapOf("1.3.101.112" to EDDSA, "1.3.101.113" to EDDSA) +
                (17..19).associate { "$NIST_SIG.$it" to ML_DSA } +
                (20..31).associate { "$NIST_SIG.$it" to SLH_DSA }

        private val SIGNATURES: Map<String, KeyFamily> =
            // PKCS#1 v1.5 with MD2, MD4, MD5, SHA-1, SHA-256/384/512/224, SHA-512/224 and SHA-512/256 (RFC 8017), and PSS.
            listOf(2, 3, 4, 5, 11, 12, 13, 14, 15, 16).associate { "$PKCS1.$it" to RSA } +
                mapOf(RSASSA_PSS to RSA) +
                // PKCS#1 v1.5 with SHA3-224 to SHA3-512.
                (13..16).associate { "$NIST_SIG.$it" to RSA } +
                // ECDSA with SHA-1, SHA-224 to SHA-512 (RFC 5758) and SHA3-224 to SHA3-512.
                mapOf("1.2.840.10045.4.1" to EC) +
                (1..4).associate { "1.2.840.10045.4.3.$it" to EC } +
                (9..12).associate { "$NIST_SIG.$it" to EC }

        fun ofKey(keyOid: String): KeyFamily = KEYS[keyOid] ?: SAME_OID[keyOid] ?: UNKNOWN

        fun ofSignature(signatureOid: String): KeyFamily = SIGNATURES[signatureOid] ?: SAME_OID[signatureOid] ?: UNKNOWN

        /** Whether [candidate]'s key can have produced a [signatureOid] signature, as far as ordering is concerned. */
        fun compatible(
            candidate: Cert,
            signatureOid: String,
            signatureFamily: KeyFamily = ofSignature(signatureOid),
        ): Boolean =
            when {
                signatureFamily == UNKNOWN || candidate.keyFamily == UNKNOWN -> true
                signatureFamily != candidate.keyFamily -> false
                signatureFamily == RSA || signatureFamily == EC -> true
                else -> candidate.keyOid == signatureOid
            }
    }
}
