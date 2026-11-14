// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.verify

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.engine.walker.absorb

/**
 * One verification as every caller of a [SignatureVerifier] records it (spec §5.1 decision list, §3): [result], and
 * [error] when the verifier threw, the message of the `Finding.VerifierError` the caller records with the signature
 * OID it verified.
 */
internal class Classified(
    val result: VerifyResult,
    val error: String?,
)

/**
 * [SignatureVerifier.verify] with spec §5.1's rule for a throw: a verifier throw is `INVALID` plus `VerifierError`, for
 * any verifier, so a provider's `RuntimeException` (which `JcaSignatureVerifier` wraps and rethrows) never escapes the
 * walk. A fatal error (§5.5) is rethrown, and an `InterruptedException` keeps the thread's interrupt flag. The walker and the verifier's other callers (the content signature, the seed
 * signature) share it, so the mapping is the same everywhere.
 */
@Suppress("TooGenericExceptionCaught") // §5.5's rule: every throwable but a fatal error is caught
internal fun SignatureVerifier.verifyClassified(
    sigAlg: ByteArray,
    spki: ByteArray,
    message: ByteArray,
    signature: ByteArray,
): Classified =
    try {
        Classified(verify(sigAlg, spki, message, signature), null)
    } catch (t: Throwable) {
        absorb(t)
        Classified(VerifyResult.INVALID, t.message ?: t::class.simpleName ?: "verifier threw")
    }
