// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.engine.parse.AlgorithmId
import dev.revokt.engine.parse.VerifierInput
import dev.revokt.engine.walker.LruMap
import dev.revokt.engine.walker.isFatal
import dev.revokt.verify.JcaAlgorithms.CURVES
import dev.revokt.verify.JcaAlgorithms.ECDSA_ONE_ONE
import dev.revokt.verify.JcaAlgorithms.EC_PUBLIC_KEY
import dev.revokt.verify.JcaAlgorithms.KEYS
import dev.revokt.verify.JcaAlgorithms.KEY_CACHE_ENTRIES
import dev.revokt.verify.JcaAlgorithms.SIGNATURES
import dev.revokt.verify.JcaAlgorithms.pssSpec
import okio.ByteString.Companion.toByteString
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.Provider
import java.security.ProviderException
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Collections

/**
 * The JCA [SignatureVerifier] (spec §3 "Verifier contract"), over [provider] or, when null, the installed providers in
 * preference order.
 *
 * - The tables: the signature OIDs RSA PKCS#1 v1.5 with SHA-2, `id-RSASSA-PSS`, ECDSA with SHA-2, Ed25519/448,
 *   ML-DSA-44/65/87 (RFC 9881), the 12 SLH-DSA sets and the composite ML-DSA OIDs (draft-ietf-lamps-pq-composite-sigs);
 *   the key OIDs `rsaEncryption`, `id-RSASSA-PSS`, `id-ecPublicKey` and the same-OID keys; the named curves P-224,
 *   P-256, P-384, P-521 and brainpoolP256r1/384r1/512r1.
 * - [unsupportedOids] is the startup probe over those tables against the provider, run once at construction: a
 *   signature OID needs a `Signature` and a key OID a `KeyFactory` (a composite OID needs both, under the OID itself:
 *   only a provider owning it verifies it); a curve needs an encoded key on it that the provider's `KeyFactory` decodes
 *   and its ECDSA `Signature` runs over.
 * - [verify] classifies by the probe, never by a server-chosen exception: a signature, key or curve OID in
 *   [unsupportedOids], each in its own role, is [VerifyResult.UNSUPPORTED]. Everything else that fails is
 *   [VerifyResult.INVALID]: an input that is not an `AlgorithmIdentifier` or an SPKI (an OID arc padded with `0x80`
 *   included), an OID outside the tables, a key that cannot have made the
 *   signature (an `id-RSASSA-PSS` key signs PSS only, RFC 4055 §1.2), parameters other than absent or NULL outside
 *   PSS, PSS parameters other than SHA-2 message and MGF1 hashes, trailer field 1 and a salt length some key has room
 *   for (spec revision 51, pending), and any `GeneralSecurityException`. A `RuntimeException` from the provider
 *   propagates, wrapped in a [ProviderException], so the caller records it as `INVALID` plus `Finding.VerifierError`
 *   (spec §5.1 decision list; [verifyClassified]).
 * - `KeyFactory` is selected by the SPKI key OID; `Signature` and `KeyFactory` are created per call. Parsed keys are
 *   cached by SPKI SHA-256 in an LRU of [KEY_CACHE_ENTRIES] that holds only keys whose verification was `VERIFIED`, so
 *   a presented junk key (server-chosen) never takes an entry; [cachedKeyCount] is its entry count.
 */
public class JcaSignatureVerifier
    @JvmOverloads
    constructor(
        private val provider: Provider? = null,
    ) : SignatureVerifier {
        private val keys = LruMap<okio.ByteString, PublicKey>(KEY_CACHE_ENTRIES)
        private val unsupported: Set<String> = probe()

        /** The number of parsed keys in the cache: at most 1,024, each one that produced `VERIFIED`. */
        public val cachedKeyCount: Int get() = keys.size

        override fun unsupportedOids(): Set<String> = unsupported

        override fun verify(
            sigAlg: ByteArray,
            spki: ByteArray,
            message: ByteArray,
            signature: ByteArray,
        ): VerifyResult {
            val algorithm = VerifierInput.algorithm(sigAlg) ?: return VerifyResult.INVALID
            val key = VerifierInput.spkiAlgorithm(spki) ?: return VerifyResult.INVALID
            if (unsupportedIn(algorithm, key)) return VerifyResult.UNSUPPORTED
            val scheme = SIGNATURES[algorithm.oid]?.takeIf { it.accepts(key) } ?: return VerifyResult.INVALID
            val keyFactory = KEYS[key.oid] ?: return VerifyResult.INVALID
            val pss =
                if (scheme.pss) {
                    pssSpec(
                        VerifierInput.pss(algorithm.parameters),
                    ) ?: return VerifyResult.INVALID
                } else {
                    null
                }
            if (!scheme.pss && !algorithm.noParameters) return VerifyResult.INVALID
            return run(scheme, algorithm.oid, keyFactory, spki, message, signature, pss)
        }

        /** The JCA calls, once [verify]'s checks passed: a `GeneralSecurityException` is `INVALID`. */
        @Suppress("TooGenericExceptionCaught") // §3: a provider's RuntimeException is rethrown wrapped, never swallowed
        private fun run(
            scheme: JcaAlgorithms.Scheme,
            oid: String,
            keyFactory: String,
            spki: ByteArray,
            message: ByteArray,
            signature: ByteArray,
            pss: PSSParameterSpec?,
        ): VerifyResult =
            try {
                val hash = spki.toByteString().sha256()
                val publicKey = keys[hash] ?: keyFactory(keyFactory).generatePublic(X509EncodedKeySpec(spki))
                val verifier = signature(scheme.jcaName)
                verifier.initVerify(publicKey)
                pss?.let { verifier.setParameter(it) }
                verifier.update(message)
                if (verifier.verify(signature)) {
                    keys.put(hash, publicKey)
                    VerifyResult.VERIFIED
                } else {
                    VerifyResult.INVALID
                }
            } catch (_: GeneralSecurityException) {
                VerifyResult.INVALID
            } catch (e: RuntimeException) {
                throw ProviderException("${scheme.jcaName} on $oid threw ${e::class.java.name}", e)
            }

        private fun signature(name: String): Signature =
            if (provider == null) Signature.getInstance(name) else Signature.getInstance(name, provider)

        private fun keyFactory(name: String): KeyFactory =
            if (provider == null) KeyFactory.getInstance(name) else KeyFactory.getInstance(name, provider)

        /**
         * Whether a probe-unsupported OID sits in its own role: the signature OID among the signature OIDs, the key OID
         * among the key OIDs, and an `id-ecPublicKey` key's curve among the curves. A curve OID in the `sigAlg`, or an
         * OID parameter on any other key, is no table entry in that role, so it is `INVALID`, never `UNSUPPORTED`.
         */
        private fun unsupportedIn(
            algorithm: AlgorithmId,
            key: AlgorithmId,
        ): Boolean =
            (algorithm.oid in unsupported && algorithm.oid in SIGNATURES) ||
                (key.oid in unsupported && key.oid in KEYS) ||
                (key.oid == EC_PUBLIC_KEY && key.parametersOid in unsupported && key.parametersOid in CURVES)

        /** The startup probe; any throw but a fatal error (spec §5.5) marks the OID unsupported. */
        private fun probe(): Set<String> {
            val out = LinkedHashSet<String>()
            for ((oid, scheme) in SIGNATURES) if (!probes { signature(scheme.jcaName) }) out += oid
            for ((oid, name) in KEYS) if (!probes { keyFactory(name) }) out += oid
            for (oid in CURVES) if (!probes { curve(oid) }) out += oid
            return Collections.unmodifiableSet(out)
        }

        /**
         * Whether ECDSA over [curveOid] runs: the curve's base point as an SPKI (private key 1; the domain parameters and
         * the encoding are public data, from the installed providers) decodes through the provider's `KeyFactory` as
         * [verify] decodes a key, and checks the signature `(r, s) = (1, 1)` to `false`. A provider without the curve
         * throws; one that answers `true` is broken and gets no curve either.
         */
        private fun curve(curveOid: String): Boolean {
            val parameters = AlgorithmParameters.getInstance("EC")
            parameters.init(ECGenParameterSpec(curveOid))
            val spec = parameters.getParameterSpec(ECParameterSpec::class.java)
            val spki = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(spec.generator, spec)).encoded
            val key = keyFactory("EC").generatePublic(X509EncodedKeySpec(spki))
            val verifier = signature("SHA256withECDSA")
            verifier.initVerify(key)
            verifier.update(ByteArray(1))
            return !verifier.verify(ECDSA_ONE_ONE)
        }

        @Suppress("TooGenericExceptionCaught") // §5.5's rule: a provider's LinkageError is "unsupported", not a crash
        private fun probes(block: () -> Any): Boolean =
            try {
                block() != false
            } catch (t: Throwable) {
                if (isFatal(t)) throw t
                false
            }
    }
