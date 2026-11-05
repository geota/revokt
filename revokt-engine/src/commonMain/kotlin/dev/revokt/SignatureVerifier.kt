// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

/**
 * The signature seam the path walker verifies every link through (spec §3, "Verifier contract"). The engine never hands
 * it a non-X.509 encoding and always passes the signed TBS `signature` field. An implementation classifies by its
 * startup probe: an OID in [unsupportedOids] (the signature, key or curve OID) is [VerifyResult.UNSUPPORTED]; any
 * other failure is [VerifyResult.INVALID]. The walk never throws: it treats a throw from [verify] as `INVALID` and
 * records a `Finding.VerifierError` (spec §5.1, §3). An implementation must not modify its arguments: the engine passes
 * a certificate's own arrays, shared by every handshake on the anchor snapshot, without copying them.
 */
public interface SignatureVerifier {
    /**
     * Verifies [signature] over [message] (the certificate's TBS) under [spki] (the candidate issuer's
     * `SubjectPublicKeyInfo` TLV). [sigAlg] is the signed TBS `AlgorithmIdentifier` TLV.
     */
    public fun verify(
        sigAlg: ByteArray,
        spki: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): VerifyResult

    /** The startup probe over the signature, key and curve OID tables: dotted OIDs this verifier cannot verify. */
    public fun unsupportedOids(): Set<String>
}
