// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.engine.parse.AlgorithmId
import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.ParseContext
import dev.revokt.engine.parse.PssParameters
import java.math.BigInteger
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

/** [JcaSignatureVerifier]'s tables (spec §3 "Verifier contract"): every OID it probes, verifies or classifies. */
internal object JcaAlgorithms {
    class Scheme(
        val jcaName: String,
        val keyOids: Set<String>,
        val pss: Boolean = false,
    ) {
        /** Whether [key] can have made this signature: its OID is one of [keyOids], and an EC key names a curve. */
        fun accepts(key: AlgorithmId): Boolean =
            key.oid in keyOids && (key.oid != EC_PUBLIC_KEY || key.parametersOid in CURVES)

        /** Whether this is ECDSA, whose `r` and `s` [ecdsaInRange] checks before the provider. */
        val ecdsa: Boolean get() = EC_PUBLIC_KEY in keyOids
    }

    /** Spec §3: the key cache's bound. */
    const val KEY_CACHE_ENTRIES = 1_024

    const val PKCS1 = "1.2.840.113549.1.1"
    const val RSA_ENCRYPTION = "$PKCS1.1"
    const val RSASSA_PSS = "$PKCS1.10"
    const val EC_PUBLIC_KEY = "1.2.840.10045.2.1"
    const val NIST_SIG = "2.16.840.1.101.3.4.3"
    const val NIST_HASH = "2.16.840.1.101.3.4.2"

    /**
     * The longest PSS salt any RSA key can take: SunRsaSign's largest modulus is 16,384 bits, and RFC 8017 §9.1.1
     * needs `emLen >= hLen + sLen + 2`. The JDK refuses a longer salt for the key anyway, except near `Int.MAX_VALUE`,
     * where its `hLen + sLen + 2` overflows into an `ArithmeticException` (found by the §9.1 target): a
     * CA-chosen length must not turn into a `VerifierError`.
     */
    const val MAX_SALT_LENGTH = 16_384 / 8

    /** DER `SEQUENCE { INTEGER 1, INTEGER 1 }`, the probe's ECDSA signature. */
    val ECDSA_ONE_ONE = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01)

    /**
     * The PSS message and MGF1 hashes: the SHA-2 family, as JCA names. SHA-1, and so all-DEFAULT parameters, are
     * `INVALID` (spec revision 51, pending: the maintainer's decision on #156).
     */
    val SHA2: Map<String, String> =
        mapOf(
            "$NIST_HASH.4" to "SHA-224",
            "$NIST_HASH.1" to "SHA-256",
            "$NIST_HASH.2" to "SHA-384",
            "$NIST_HASH.3" to "SHA-512",
            "$NIST_HASH.5" to "SHA-512/224",
            "$NIST_HASH.6" to "SHA-512/256",
        )

    /** Ed25519, Ed448 (RFC 8410), ML-DSA-44/65/87 (RFC 9881) and the SLH-DSA sets: one OID for key and signature. */
    val SAME_OID: Map<String, String> =
        mapOf("1.3.101.112" to "Ed25519", "1.3.101.113" to "Ed448") +
            mapOf("$NIST_SIG.17" to "ML-DSA-44", "$NIST_SIG.18" to "ML-DSA-65", "$NIST_SIG.19" to "ML-DSA-87") +
            listOf("SHA2", "SHAKE")
                .flatMap { h ->
                    listOf("128", "192", "256").flatMap { n ->
                        listOf("s", "f").map { "SLH-DSA-$h-$n$it" }
                    }
                }.withIndex()
                .associate { (i, name) -> "$NIST_SIG.${20 + i}" to name }

    /**
     * The composite ML-DSA signatures of draft-ietf-lamps-pq-composite-sigs (id-MLDSA44-RSA2048-PSS-SHA256 to
     * id-MLDSA87-ECDSA-P521-SHA512): not one JCA operation (Appendix A), so only a provider registering the OID
     * itself verifies one; under the JDK's providers each is unsupported.
     */
    val COMPOSITE: List<String> = (37..54).map { "1.3.6.1.5.5.7.6.$it" }

    val SIGNATURES: Map<String, Scheme> =
        mapOf(
            "$PKCS1.14" to "SHA224withRSA",
            "$PKCS1.11" to "SHA256withRSA",
            "$PKCS1.12" to "SHA384withRSA",
            "$PKCS1.13" to "SHA512withRSA",
            "$PKCS1.15" to "SHA512/224withRSA",
            "$PKCS1.16" to "SHA512/256withRSA",
        ).mapValues { Scheme(it.value, setOf(RSA_ENCRYPTION)) } +
            mapOf(RSASSA_PSS to Scheme("RSASSA-PSS", setOf(RSA_ENCRYPTION, RSASSA_PSS), pss = true)) +
            (1..4)
                .associate { "1.2.840.10045.4.3.$it" to "SHA${listOf(224, 256, 384, 512)[it - 1]}withECDSA" }
                .mapValues { Scheme(it.value, setOf(EC_PUBLIC_KEY)) } +
            SAME_OID.mapValues { (oid, name) -> Scheme(name, setOf(oid)) } +
            COMPOSITE.associateWith { Scheme(it, setOf(it)) }

    val KEYS: Map<String, String> =
        mapOf(RSA_ENCRYPTION to "RSA", RSASSA_PSS to "RSASSA-PSS", EC_PUBLIC_KEY to "EC") +
            SAME_OID + COMPOSITE.associateWith { it }

    /** secp224r1, P-256, P-384, P-521 (RFC 5480) and brainpoolP256r1/384r1/512r1 (RFC 5639). */
    val CURVES: Set<String> =
        setOf(
            "1.3.132.0.33",
            "1.2.840.10045.3.1.7",
            "1.3.132.0.34",
            "1.3.132.0.35",
            "1.3.36.3.3.2.8.1.1.7",
            "1.3.36.3.3.2.8.1.1.11",
            "1.3.36.3.3.2.8.1.1.13",
        )

    /**
     * Whether [signature] is a DER `Ecdsa-Sig-Value` with `1 ≤ r ≤ n − 1` and `1 ≤ s ≤ n − 1` for the curve order [n]:
     * step 1 of ECDSA verification (SEC 1 §4.1.4), which JDK 17.0.0 to 17.0.2 skipped (CVE-2022-21449: `r = s = 0`
     * verified for any message and key). Spec revision 54, pending. A high `s` is in range.
     */
    fun ecdsaInRange(
        signature: ByteArray,
        n: BigInteger,
    ): Boolean {
        val (r, s) = ecdsaSignature(signature) ?: return false
        return BigInteger.ONE <= r && r < n && BigInteger.ONE <= s && s < n
    }

    /**
     * The `(r, s)` of the DER `Ecdsa-Sig-Value` (RFC 3279 §2.2.3) [der], or null for anything else: a SEQUENCE of
     * exactly two INTEGERs and nothing after it, every length minimal, every INTEGER minimal. The values keep their
     * sign, so a negative one is out of [ecdsaInRange]'s range.
     */
    fun ecdsaSignature(der: ByteArray): Pair<BigInteger, BigInteger>? =
        try {
            val ctx = ParseContext()
            val outer = DerReader(der, 0, der.size, ctx)
            val fields = outer.child(outer.read(SEQUENCE, HeaderSite.SIGNATURE_VALUE))
            outer.requireEnd("Ecdsa-Sig-Value")
            val r = integer(der, fields)
            val s = integer(der, fields)
            fields.requireEnd("Ecdsa-Sig-Value")
            if (ctx.nonMinimal.isEmpty() && r != null && s != null) r to s else null
        } catch (_: DerException) {
            null
        }

    private fun integer(
        der: ByteArray,
        r: DerReader,
    ): BigInteger? {
        val content = r.read(INTEGER, HeaderSite.SIGNATURE_VALUE).content
        return if (Keyability.minimalInteger(der, content)) BigInteger(content.bytes(der)) else null
    }

    private const val SEQUENCE = 0x30
    private const val INTEGER = 0x02

    /** The JCA form of [p], or null when it is absent, malformed or outside [JcaSignatureVerifier]'s PSS rules. */
    fun pssSpec(p: PssParameters?): PSSParameterSpec? {
        if (p == null || p.trailerField != PSSParameterSpec.TRAILER_FIELD_BC ||
            p.saltLength > MAX_SALT_LENGTH
        ) {
            return null
        }
        val hash = SHA2[p.hashOid] ?: return null
        val mgfHash = SHA2[p.mgfHashOid] ?: return null
        return PSSParameterSpec(hash, "MGF1", MGF1ParameterSpec(mgfHash), p.saltLength, p.trailerField)
    }
}
