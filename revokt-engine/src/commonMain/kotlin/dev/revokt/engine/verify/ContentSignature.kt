// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.engine.json.CanonicalJson
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonBoolean
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonString
import dev.revokt.verify.verifyClassified

/** Why a content signature failed; every one is `SyncOutcome.FAILED` at stage `SIGNATURE` (spec §7.1). */
internal enum class ContentSignatureFailure {
    /** `metadata.signature.mode` is absent or not [ContentSignature.MODE]. */
    MODE,

    /** The `signature` field is absent or not the base64url text of 96 bytes ([RawSignature.decode]). */
    ENCODING,

    /** A record has no string `id`, or two records share one, so there is no payload to verify. */
    RECORDS,

    /** The verifier answered `INVALID`, or threw ([ContentSignatureResult.verifierError]). */
    INVALID,

    /** The verifier answered `UNSUPPORTED`: its startup probe excludes ECDSA, SHA-384 or the leaf's curve. */
    UNSUPPORTED,
}

/** One content-signature check: verified when [failure] is null; [verifierError] is the message of a verifier throw. */
internal class ContentSignatureResult private constructor(
    val failure: ContentSignatureFailure?,
    val verifierError: String?,
) {
    val verified: Boolean get() = failure == null

    override fun toString(): String =
        "ContentSignatureResult(${failure ?: "VERIFIED"}${verifierError?.let { ", $it" } ?: ""})"

    companion object {
        val VERIFIED = ContentSignatureResult(null, null)

        fun failed(
            failure: ContentSignatureFailure,
            verifierError: String? = null,
        ): ContentSignatureResult = ContentSignatureResult(failure, verifierError)
    }
}

/**
 * The Remote Settings content signature (spec §7.1 "Verify" and "Content signature"). The signed bytes are
 * `"Content-Signature:\0"` followed by the canonical JSON ([CanonicalJson], `canonical_json` 0.7.0) of
 * `{"data": records sorted by id (deleted removed), "last_modified": "<ts>"}`; the bytes after the prefix are the
 * `records.json` a `SIGNED` generation stores and a seed ships (spec §6.5). The signature is checked as
 * `ecdsa-with-SHA384` under the x5u leaf's SPKI through the given [SignatureVerifier], whatever `mode` says beyond
 * equalling [MODE]: the algorithm is never derived from it. Nothing here throws but a fatal error (spec §5.5,
 * [verifyClassified]).
 */
internal object ContentSignature {
    /** The one `mode` accepted (spec §7.1). */
    const val MODE = "p384ecdsa"

    private val PREFIX = "Content-Signature:\u0000".encodeToByteArray()

    /** `AlgorithmIdentifier { ecdsa-with-SHA384 }` (1.2.840.10045.4.3.3), parameters absent (RFC 5758 §3.2). */
    private val ECDSA_WITH_SHA384 =
        byteArrayOf(0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x03)

    /**
     * The full record set after a `_since` changeset (spec §7.1 "merge `_since` tombstones first", §6.5): [stored]
     * keyed by `id`, then each of [changes] in order, a `deleted: true` change removing its id and any other replacing
     * or adding it. In id order, deleted records removed; null when a record has no string `id`. A full changeset is
     * merged over no stored records, so the same rule (the last record of an id wins) applies to both.
     */
    fun merge(
        stored: List<JsonObject>,
        changes: List<JsonObject>,
    ): List<JsonObject>? {
        val byId = LinkedHashMap<String, JsonObject>()
        for (record in stored) byId[id(record) ?: return null] = record
        for (change in changes) {
            val id = id(change) ?: return null
            if (deleted(change)) byId.remove(id) else byId[id] = change
        }
        return sortedOrNull(byId.values.filterNot(::deleted))
    }

    /**
     * The signed payload without its prefix, which is `records.json` (spec §6.5): [records] sorted by `id` in code
     * point order, deleted records removed, under `data`, and [lastModified] as a decimal string under
     * `last_modified`. Null when a record has no string `id` or two share one.
     */
    fun recordsJson(
        records: List<JsonObject>,
        lastModified: Long,
    ): ByteArray? {
        val sorted = sortedOrNull(records.filterNot(::deleted)) ?: return null
        for (i in 1 until sorted.size) if (id(sorted[i - 1]) == id(sorted[i])) return null
        val payload = JsonObject.of("data" to JsonArray(sorted), "last_modified" to JsonString(lastModified.toString()))
        return CanonicalJson.write(payload)
    }

    /**
     * Verifies [signature] over the payload of [records] at [lastModified] (a live sync, after [merge]) under
     * [leafSpki], the x5u leaf's `SubjectPublicKeyInfo`. [signature] and [mode] are `metadata.signature`'s fields
     * (spec §4), null when absent.
     */
    fun verifyRecords(
        verifier: SignatureVerifier,
        records: List<JsonObject>,
        lastModified: Long,
        signature: String?,
        mode: String?,
        leafSpki: ByteArray,
    ): ContentSignatureResult =
        verify(verifier, signature, mode, leafSpki) {
            recordsJson(records, lastModified)
        }

    /**
     * Verifies [signature] over [recordsJson] exactly as given, never decoded or re-serialised: a seed's or a stored
     * generation's `records.json` is checked as raw bytes before the JSON decoder sees it (spec §6.5).
     */
    fun verifyRawPayload(
        verifier: SignatureVerifier,
        recordsJson: ByteArray,
        signature: String?,
        mode: String?,
        leafSpki: ByteArray,
    ): ContentSignatureResult = verify(verifier, signature, mode, leafSpki) { recordsJson }

    private inline fun verify(
        verifier: SignatureVerifier,
        signature: String?,
        mode: String?,
        leafSpki: ByteArray,
        payload: () -> ByteArray?,
    ): ContentSignatureResult {
        if (mode != MODE) return ContentSignatureResult.failed(ContentSignatureFailure.MODE)
        val raw =
            signature?.let(RawSignature::decode)
                ?: return ContentSignatureResult.failed(ContentSignatureFailure.ENCODING)
        val body = payload() ?: return ContentSignatureResult.failed(ContentSignatureFailure.RECORDS)
        val checked = verifier.verifyClassified(ECDSA_WITH_SHA384, leafSpki, PREFIX + body, RawSignature.toDer(raw))
        return when (checked.result) {
            VerifyResult.VERIFIED -> ContentSignatureResult.VERIFIED
            VerifyResult.INVALID -> ContentSignatureResult.failed(ContentSignatureFailure.INVALID, checked.error)
            VerifyResult.UNSUPPORTED -> ContentSignatureResult.failed(ContentSignatureFailure.UNSUPPORTED)
        }
    }

    private fun id(record: JsonObject): String? = (record["id"] as? JsonString)?.value

    private fun deleted(record: JsonObject): Boolean = record["deleted"] == JsonBoolean.TRUE

    /** [records] in code point order of `id`, or null when one has no string `id`. */
    private fun sortedOrNull(records: List<JsonObject>): List<JsonObject>? {
        val keyed = records.map { (id(it) ?: return null) to it }
        return keyed.sortedWith { a, b -> JsonObject.compareCodePoints(a.first, b.first) }.map { it.second }
    }
}
