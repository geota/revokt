// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.engine.seed.parse.SeedArchive
import dev.revokt.engine.seed.parse.SeedFormatException
import dev.revokt.engine.seed.parse.SeedHeader
import java.io.IOException

/** What [verifySeedSignature] found. */
internal sealed interface SeedSignature {
    /** The seed's content signature verifies, at its signed `<ts>`, [timestampMillis]. */
    class Verified(
        val timestampMillis: Long,
    ) : SeedSignature {
        override fun toString(): String = "Verified($timestampMillis)"
    }

    /** It does not, for [detail]. */
    class Refused(
        val detail: String,
    ) : SeedSignature {
        override fun toString(): String = "Refused($detail)"
    }
}

/**
 * The weekly job's floor check of the last released seed (#308; `seedTimestamp<Channel>` in data/seed): only the
 * parts of a seed load that do not depend on the seed format, as Firefox's `RemoteSettingsClient` re-verifies its local
 * data before it ignores an older changeset (`_importChanges`), so that a `seedFormat` bump, a stricter schema or a new
 * `filterFormat` never strands the job, which needs only a trusted `<ts>`:
 * - `seed.json`'s `channel` is [channel] ([SeedHeader.read]; no other header member is checked);
 * - `records.json`, `signature` and `x5u.pem` under the loader's caps, then [verifySignedRecords], the loader's own
 *   steps 2 to 4: the x5u chain inside the archive validated to [source]'s pins, the raw content signature over
 *   `records.json`, the canonical payload, which gives the `<ts>`, and the x5u validity at that `<ts>`.
 *
 * The archive is read by [SeedArchive], which every seed load reads it with, without [SeedArchive.requireFixed]'s
 * layout check. No clock is read. Every refusal, a read that throws included, is [SeedSignature.Refused].
 */
internal fun verifySeedSignature(
    seed: SeedSource,
    channel: CrliteChannel,
    source: MozillaRemoteSettings,
    verifier: SignatureVerifier,
): SeedSignature {
    val caps =
        listOf(
            SeedArchive.SEED_JSON to SeedHeader.MAX_BYTES,
            SeedArchive.RECORDS to RevoktLimits.MAX_JSON_BYTES,
            SeedArchive.SIGNATURE to SeedLoader.MAX_SIGNATURE_BYTES,
            SeedArchive.X5U to RevoktLimits.MAX_X5U_BYTES,
        )
    return try {
        val archive = SeedArchive.open(seed::open) ?: return SeedSignature.Refused("there is no archive")
        val missing = caps.firstOrNull { archive.entry(it.first) == null }
        if (missing != null) return SeedSignature.Refused("the archive holds no ${missing.first}")
        val bytes = HashMap<String, ByteArray>()
        archive.read(caps.map { (name, cap) -> checkNotNull(archive.entry(name)) to cap }) { e, b -> bytes[e.name] = b }
        val header = SeedHeader.read(bytes.getValue(SeedArchive.SEED_JSON))
        if (header.channel != channel.name) {
            return SeedSignature.Refused("the seed is for ${header.channel}, not ${channel.name}")
        }
        val signed =
            verifySignedRecords(
                bytes.getValue(SeedArchive.RECORDS),
                bytes.getValue(SeedArchive.SIGNATURE),
                bytes.getValue(SeedArchive.X5U),
                source.pinnedRootSpkis,
                verifier,
            )
        SeedSignature.Verified(signed.timestamp)
    } catch (e: SeedFormatException) {
        SeedSignature.Refused(e.message ?: e.toString())
    } catch (e: IOException) {
        SeedSignature.Refused("reading the archive failed: $e")
    }
}
