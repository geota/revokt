// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.testing

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.engine.parse.DerException
import dev.revokt.engine.parse.DerReader
import dev.revokt.engine.parse.HeaderSite
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParseContext
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** A certificate's identity for [SymVerifier]: SHA-256 of its TBS, the verified message (spec §9.1). */
@JvmInline
internal value class CertId(
    val sha256: ByteString,
) {
    companion object {
        fun of(tbs: ByteArray): CertId = CertId(tbs.toByteString().sha256())
    }
}

/** A key's identity for [SymVerifier]: SHA-256 of its `SubjectPublicKeyInfo` TLV (spec §9.1). */
@JvmInline
internal value class KeyId(
    val sha256: ByteString,
) {
    companion object {
        fun of(spki: ByteArray): KeyId = KeyId(spki.toByteString().sha256())
    }
}

/**
 * The §9.1 symbolic verifier: crypto replaced by a set of links. A link verifies exactly when its `(CertId, KeyId)`
 * pair is in [ok]; the signature bytes are never read, so a recovered or duplicate-signature key is one more pair.
 * [unsupported] (dotted OIDs) is matched as the startup probe matches it: the TBS signature OID ([verify]'s `sigAlg`),
 * the key OID and the curve OID (the SPKI `AlgorithmIdentifier`'s parameters when they are an OID) each make the link
 * [VerifyResult.UNSUPPORTED], checked before [ok]. An input that is not an `AlgorithmIdentifier` or an SPKI carries no
 * OID and is looked up in [ok] as it is; the verifier never throws.
 */
internal class SymVerifier(
    private val ok: Set<Pair<CertId, KeyId>>,
    private val unsupported: Set<String>,
) : SignatureVerifier {
    override fun verify(
        sigAlg: ByteArray,
        spki: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): VerifyResult {
        val oids = listOfNotNull(algorithmOid(sigAlg)?.first) + spkiOids(spki)
        if (oids.any { it in unsupported }) return VerifyResult.UNSUPPORTED
        return if (CertId.of(message) to KeyId.of(spki) in ok) VerifyResult.VERIFIED else VerifyResult.INVALID
    }

    override fun unsupportedOids(): Set<String> = unsupported

    companion object {
        private const val SEQUENCE = 0x30
        private const val OBJECT_IDENTIFIER = 0x06
        private const val BIT_STRING = 0x03

        /** The key OID and, when the parameters are an OID, the curve OID of an SPKI TLV; empty when it is not one. */
        fun spkiOids(spki: ByteArray): List<String> =
            read(spki) { r ->
                val outer = r.child(r.read(SEQUENCE, HeaderSite.SPKI))
                r.requireEnd("SubjectPublicKeyInfo")
                val algorithm = outer.readAny(HeaderSite.SPKI)
                outer.read(BIT_STRING, HeaderSite.SPKI)
                outer.requireEnd("SubjectPublicKeyInfo")
                if (algorithm.tag != SEQUENCE) return@read null
                algorithmOid(spki.copyOfRange(algorithm.tlv.start, algorithm.tlv.end))?.toList()?.filterNotNull()
            } ?: emptyList()

        /** An `AlgorithmIdentifier` TLV's OID and its parameters' OID if they are one; null for any other input. */
        fun algorithmOid(der: ByteArray): Pair<String?, String?>? =
            read(der) { r ->
                val a = r.child(r.read(SEQUENCE, HeaderSite.TBS_SIGNATURE))
                r.requireEnd("AlgorithmIdentifier")
                val oid = a.read(OBJECT_IDENTIFIER, HeaderSite.TBS_SIGNATURE)
                val parameters = if (a.hasMore()) a.readAny(HeaderSite.TBS_SIGNATURE) else null
                a.requireEnd("AlgorithmIdentifier")
                Oid.dotted(der, oid.content) to
                    parameters?.takeIf { it.tag == OBJECT_IDENTIFIER }?.let { Oid.dotted(der, it.content) }
            }

        private fun <T> read(
            der: ByteArray,
            block: (DerReader) -> T?,
        ): T? =
            try {
                block(DerReader(der, 0, der.size, ParseContext()))
            } catch (_: DerException) {
                null
            }
    }
}
