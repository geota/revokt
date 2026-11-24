// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// detekt 1.23 cannot read the 2.4 stdlib's metadata and reports the code after a non-local return in a lambda as
// unreachable (as in SeedLoader); kotlinc's own check holds.
@file:Suppress("UnreachableCode")
@file:OptIn(dev.revokt.RevoktInternalApi::class, dev.revokt.clubcard.RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.RevoktLimits
import dev.revokt.SignatureVerifier
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.clubcard.api.ClubcardFormatException
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.fetch.ChangesetVerification
import dev.revokt.engine.fetch.CrliteRecord
import dev.revokt.engine.fetch.CrliteSchema
import dev.revokt.engine.fetch.RecordCheck
import dev.revokt.engine.seed.parse.SeedArchive
import dev.revokt.engine.update.FilterRecord
import dev.revokt.engine.update.IndexBuild
import dev.revokt.engine.update.PlacedFilter
import dev.revokt.engine.update.Placement
import dev.revokt.engine.update.buildIndex
import dev.revokt.engine.update.placeFilters
import dev.revokt.engine.update.toFilterFormat
import dev.revokt.engine.update.toFilterRecord
import dev.revokt.engine.verify.ContentSignature
import okio.ByteString

/** What [buildSeed] produced. */
internal sealed interface SeedBuild {
    /**
     * The seed archive's [bytes]: the generation `"<ts>/<last placed record id>"` ([generationId]) at the signed
     * [timestampMillis], whose full filter is in [filterFormat] and whose [index] is the archive's `index.bin`.
     */
    class Built(
        val bytes: ByteArray,
        val timestampMillis: Long,
        val generationId: String,
        val filterFormat: FilterFormat,
        val index: ByteArray,
    ) : SeedBuild {
        override fun toString(): String = "Built($generationId, $filterFormat, ${bytes.size} bytes)"
    }

    /** No archive: [detail] says why. Nothing is written. */
    class Refused(
        val detail: String,
    ) : SeedBuild {
        override fun toString(): String = "Refused($detail)"
    }
}

/**
 * The seed archive of [verified], a changeset [dev.revokt.engine.fetch.ChangesetVerifier] verified, for [channel] (spec
 * §6.5 "Seed archive", the writer side; #145). [bodies] are the placed records' attachments by record id, as fetched;
 * [formats] are the filter encodings the engine lists, and [verifier] checks the signature once more over the
 * `records.json` written.
 *
 * The entries, in this order: `seed.json` (stored; [header]), `records.json` (the canonical signed payload of the
 * verified records at the verified `<ts>`, every channel's, as the signature covers them), `signature` (the verified
 * entry's `signature` as served), `x5u.pem` (the x5u body as served), `index.bin` ([buildIndex]), then
 * `attachments/<filename>` for each placed record in placement order, each under its attachment filename. Every entry but
 * `seed.json` is deflated ([SeedZip]).
 *
 * It refuses, writing nothing, whatever the loader would refuse: records that fail the schema or the record cap; a
 * placement that is not exactly one full filter; a placed record with no body, an extra body, or a body whose size or
 * SHA-256 differs from the signed record; a declared size over `MAX_FILTER_BYTES`; a filter that does not decode, or
 * whose encoding [formats] does not list (a delta may be in another listed encoding than the full, as a sync installs
 * it; `filterFormat` is the full's); an entry over its loader cap; a `records.json` the signature does not verify over;
 * and an archive over [SeedArchive.MAX_BYTES].
 */
internal fun buildSeed(
    verified: ChangesetVerification.Verified,
    channel: CrliteChannel,
    bodies: Map<String, ByteString>,
    formats: Set<FilterFormat>,
    verifier: SignatureVerifier,
): SeedBuild =
    try {
        val (records, signed) = placed(verified, channel)
        checkBodies(signed, bodies)
        val index =
            when (val build = buildIndex(records, channel) { bodies.getValue(it.id).toByteArray() }) {
                is IndexBuild.Built -> build.index
                is IndexBuild.Refused -> refuse("index.bin cannot be built: $build")
            }
        val filterFormat = filterFormat(signed, bodies, formats)
        val recordsJson =
            ContentSignature.recordsJson(verified.records, verified.timestamp)
                ?: refuse("the records have no canonical payload")
        val signature = verified.entry.signature ?: refuse("the verified entry has no signature")
        val x5u = verified.x5uBody.toByteArray()
        caps(recordsJson, signature.encodeToByteArray(), x5u, index)?.let { refuse(it) }
        val check =
            ContentSignature.verifyRawPayload(
                verifier,
                recordsJson,
                signature,
                ContentSignature.MODE,
                verified.path.leafSpki,
            )
        if (!check.verified) refuse("the signature does not verify over the records.json written: $check")
        val fixed =
            listOf(
                SeedZipEntry(SeedArchive.SEED_JSON, header(channel, filterFormat, verified.timestamp), stored = true),
                SeedZipEntry(SeedArchive.RECORDS, recordsJson),
                SeedZipEntry(SeedArchive.SIGNATURE, signature.encodeToByteArray()),
                SeedZipEntry(SeedArchive.X5U, x5u),
                SeedZipEntry(SeedArchive.INDEX, index),
            )
        val attachments =
            signed.map {
                SeedZipEntry(
                    SeedArchive.ATTACHMENTS + it.attachment.filename,
                    bodies.getValue(it.id).toByteArray(),
                )
            }
        val bytes =
            try {
                SeedZip.write(fixed + attachments)
            } catch (e: IllegalArgumentException) {
                refuse("the zip writer refuses the entries: ${e.message}")
            }
        if (bytes.size > SeedArchive.MAX_BYTES) refuse("the archive is ${bytes.size} bytes, over SeedArchive.MAX_BYTES")
        val generationId = "${verified.timestamp}/${signed.last().id}"
        SeedBuild.Built(bytes, verified.timestamp, generationId, filterFormat, index)
    } catch (r: Refusal) {
        SeedBuild.Refused(r.detail)
    }

/** One of [buildSeed]'s refusals, thrown by its steps and caught once. */
private class Refusal(
    val detail: String,
) : Exception(detail)

private fun refuse(detail: String): Nothing = throw Refusal(detail)

/** [verified]'s schema-checked records of [channel] as filter records, and the placed ones' signed records in order. */
private fun placed(
    verified: ChangesetVerification.Verified,
    channel: CrliteChannel,
): Pair<List<FilterRecord>, List<CrliteRecord>> {
    val crlite =
        when (val check = CrliteSchema.check(verified.records, channel, RevoktLimits.MAX_CHANGESET_RECORDS)) {
            is RecordCheck.Passed -> check.records
            is RecordCheck.Rejected -> refuse("the records fail the schema: ${check.detail}")
        }
    val records = crlite.map { it.toFilterRecord() }
    val placed: List<PlacedFilter> =
        when (val placement = placeFilters(records, channel)) {
            is Placement.Placed -> placement.filters
            is IndexBuild.Refused -> refuse("the records place no generation: $placement")
        }
    val byId = crlite.associateBy { it.id }
    return records to placed.map { byId.getValue(it.record.id) }
}

/** Every placed record has exactly its signed body in [bodies], within `MAX_FILTER_BYTES`, and nothing else is there. */
private fun checkBodies(
    signed: List<CrliteRecord>,
    bodies: Map<String, ByteString>,
) {
    val ids = signed.mapTo(HashSet()) { it.id }
    bodies.keys.firstOrNull { it !in ids }?.let { refuse("a body for $it, which the generation does not place") }
    for (r in signed) {
        if (r.attachment.size > RevoktLimits.MAX_FILTER_BYTES) {
            refuse("${r.id} declares ${r.attachment.size} bytes, over MAX_FILTER_BYTES")
        }
        val body = bodies[r.id] ?: refuse("no body for ${r.id}")
        if (body.size.toLong() !=
            r.attachment.size
        ) {
            refuse("${r.id}: ${body.size} bytes, signed size ${r.attachment.size}")
        }
        if (body.sha256() != r.attachment.sha256) refuse("${r.id}: the SHA-256 differs from the signed hash")
    }
}

/**
 * The full's encoding, `seed.json`'s `filterFormat`, once every placed filter's encoding is in [formats]: a delta may be
 * in another listed encoding, as a sync installs it (the maintainer's decision on #137).
 */
private fun filterFormat(
    signed: List<CrliteRecord>,
    bodies: Map<String, ByteString>,
    formats: Set<FilterFormat>,
): FilterFormat {
    val encodings =
        signed.associate { r ->
            val encoding =
                try {
                    ClubcardFilters.encodingOf(bodies.getValue(r.id).toByteArray())
                } catch (e: ClubcardFormatException) {
                    refuse("${r.id} does not decode: ${e.message}")
                }
            r.id to encoding.toFilterFormat()
        }
    signed.firstOrNull { encodings.getValue(it.id) !in formats }?.let {
        refuse("${it.id} is ${encodings.getValue(it.id)}, which the engine does not list ($formats)")
    }
    return encodings.getValue(signed.single { !it.incremental }.id)
}

/**
 * `seed.json` (spec §6.5; #145's comment on #138's reader): compact JSON with no whitespace, its members in this order,
 * the enum values as names. [timestampMillis] is the verified `<ts>`, the unsigned header's hint.
 */
internal fun header(
    channel: CrliteChannel,
    filterFormat: FilterFormat,
    timestampMillis: Long,
): ByteArray =
    (
        "{\"seedFormat\":${SeedLoader.SEED_FORMAT},\"channel\":\"${channel.name}\"," +
            "\"dataset\":\"${Dataset.CRLITE.name}\"," +
            "\"filterFormat\":\"${filterFormat.name}\",\"recordsLastModified\":$timestampMillis," +
            "\"engineFloor\":${SeedLoader.ENGINE_LEVEL}}"
    ).encodeToByteArray()

/** The first loader cap (spec §6.5 "Entry caps") an entry is over, or null. `seed.json` is a few dozen bytes. */
private fun caps(
    recordsJson: ByteArray,
    signature: ByteArray,
    x5u: ByteArray,
    index: ByteArray,
): String? =
    when {
        recordsJson.size > RevoktLimits.MAX_JSON_BYTES -> "records.json is ${recordsJson.size} bytes, over the cap"
        signature.size > SeedLoader.MAX_SIGNATURE_BYTES -> "the signature is ${signature.size} bytes, over 64 KiB"
        x5u.size > RevoktLimits.MAX_X5U_BYTES -> "x5u.pem is ${x5u.size} bytes, over MAX_X5U_BYTES"
        index.size > C2spIndex.MAX_BYTES -> "index.bin is ${index.size} bytes, over C2spIndex.MAX_BYTES"
        else -> null
    }
