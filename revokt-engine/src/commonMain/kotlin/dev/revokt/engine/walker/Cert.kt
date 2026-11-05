// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.walker

import dev.revokt.CrliteSct
import dev.revokt.KeyabilityClause
import dev.revokt.engine.parse.Keyability
import dev.revokt.engine.parse.Oid
import dev.revokt.engine.parse.ParsedCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * One certificate as the walker sees it (spec §5.1 declarations), presented or in the store. Every field comes from the
 * one parse of [tbs] (§5.5); [der] is the caller's array, not a copy.
 *
 * - [tbsSigOid] and [keyOid] are the dotted OIDs of the TBS `signature` and the SPKI algorithm, or `""` when that
 *   `AlgorithmIdentifier` is not an OID with at most one parameter or the OID does not decode: no family and no
 *   probe entry matches `""`. [curveOid] is the SPKI parameters' OID when they are one (the named curve of
 *   `id-ecPublicKey`).
 * - [canonicalSubject] is computed once, at construction, and [canonicalIssuer] at most once, on first use (§5.1
 *   "Caches"); a canonicaliser that returns null or throws gives null, which matches nothing, so raw-byte and SKI
 *   matching still apply (§5.1 decision list); only a fatal error ([isFatal], §5.5) is rethrown. The canonicaliser
 *   gets a copy of the name.
 * - [algorithmIdMismatch] is §5.1's per-certificate `AlgorithmIdMismatch`, computed by the parser after NULL/absent
 *   normalisation. §5.1 declares `findings: List<Finding>` here; decide turns this flag into that finding.
 * - [producerKeyable] and [keyabilityClause] are §9.2's keyability profile; only the leaf's are read (decision step 3).
 */
internal class Cert private constructor(
    p: ParsedCertificate,
    canonicaliser: (ByteArray) -> String?,
) {
    val der: ByteArray = p.der
    val bytesHash: ByteString = der.toByteString().sha256()
    val tbs: ByteArray = p.tbsBytes
    val sig: ByteArray = p.envelope.signature
    val tbsSigAlg: ByteArray = p.tbs.signature.bytes(tbs)
    val tbsSigOid: String = Keyability.algorithm(tbs, p.tbs.signature)?.let { Oid.dotted(tbs, it.first) }.orEmpty()
    val spki: ByteArray = p.rawSpki()
    val spkiHash: ByteString = spki.toByteString().sha256()
    private val keyAlgorithm = Keyability.spki(tbs, p.tbs.spki, exact = false)?.first
    val keyOid: String = keyAlgorithm?.let { Oid.dotted(tbs, it.first) }.orEmpty()
    val curveOid: String? =
        keyAlgorithm
            ?.second
            ?.takeIf {
                it.tag == OBJECT_IDENTIFIER
            }?.let { Oid.dotted(tbs, it.content) }
    val keyFamily: KeyFamily = KeyFamily.ofKey(keyOid)
    val subjectRaw: ByteArray = p.rawSubject()
    val issuerRaw: ByteArray = p.rawIssuer()
    val canonicalSubject: String? = canonical(canonicaliser, subjectRaw)
    val canonicalIssuer: String? by lazy {
        if (issuerRaw.contentEquals(subjectRaw)) canonicalSubject else canonical(canonicaliser, issuerRaw)
    }
    val ski: ByteArray? = p.fields.ski?.bytes(tbs)
    val akiKeyId: ByteArray? = p.fields.akiKeyId?.bytes(tbs)
    val serial: ByteArray = p.rawSerial()

    /** §6.1: the union over every SCT-list extension of the items §9.2 keeps, in first-seen order. */
    val scts: List<CrliteSct> = p.fields.scts.map { CrliteSct.of(it.logId, it.timestamp) }
    val notBefore: Long? = p.tbs.validity.notBeforeMillis
    val notAfter: Long? = p.tbs.validity.notAfterMillis
    val keyabilityClause: KeyabilityClause? = Keyability.firstFailing(p)
    val producerKeyable: Boolean = keyabilityClause == null
    val algorithmIdMismatch: Boolean = p.envelope.algorithmIdMismatch

    override fun toString(): String = "Cert(${bytesHash.hex()})"

    internal companion object {
        private const val OBJECT_IDENTIFIER = 0x06

        /** The walker's view of [p], canonicalised by [canonicaliser] (the index's, so presented and store agree). */
        fun of(
            p: ParsedCertificate,
            canonicaliser: (ByteArray) -> String?,
        ): Cert = Cert(p, canonicaliser)

        @Suppress("TooGenericExceptionCaught") // §5.5's rule: every throwable but a fatal error is caught
        private fun canonical(
            canonicaliser: (ByteArray) -> String?,
            name: ByteArray,
        ): String? =
            try {
                canonicaliser(name.copyOf())
            } catch (t: Throwable) {
                // §5.1 decision list: a canonicaliser throw is "no canonical match", for any canonicaliser, so a custom
                // delegate's NotImplementedError or a StackOverflowError on a crafted name cannot reach the boundary.
                if (isFatal(t)) throw t
                null
            }
    }
}
