// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

// detekt 1.23 cannot read the 2.4 stdlib's metadata and reports the code after a non-local return in a lambda as
// unreachable (as in SeedLoader); kotlinc's own check holds.
@file:Suppress("UnreachableCode")
@file:OptIn(dev.revokt.RevoktInternalApi::class, dev.revokt.clubcard.RevoktInternalApi::class)

package dev.revokt.engine.seed

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.HttpFetcher
import dev.revokt.KotlinRevocationEngine
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLogger
import dev.revokt.RevoktPolicy
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.SyncFailure
import dev.revokt.engine.fetch.ChangesetVerification
import dev.revokt.engine.fetch.ChangesetVerifier
import dev.revokt.engine.fetch.ClientResult
import dev.revokt.engine.fetch.RemoteSettingsClient
import dev.revokt.engine.update.FilterRecord
import dev.revokt.engine.update.IndexBuild
import dev.revokt.engine.update.Placement
import dev.revokt.engine.update.placeFilters
import dev.revokt.engine.verify.ContentSignature
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import okio.ByteString
import java.io.ByteArrayInputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.format.ResolverStyle

/** What [SeedJob] ended with. */
internal sealed interface SeedJobResult {
    /** [build] passed its self-load; [path] holds it when the job wrote it ([SeedJob.write]). */
    class Built(
        val build: SeedBuild.Built,
        val path: Path? = null,
    ) : SeedJobResult {
        override fun toString(): String = "Built($build${path?.let { " at $it" } ?: ""})"
    }

    /** Nothing written: [failure] is the fetch's or the verification's `SyncFailure` (null for a writer refusal). */
    class Failed(
        val failure: SyncFailure?,
        val detail: String,
    ) : SeedJobResult {
        override fun toString(): String = "Failed(${failure ?: "SEED"}: $detail)"
    }
}

/**
 * The seed job's core (#145; spec §6.5, §7.2): the current `cert-revocations` changeset of [source] for [channel],
 * fetched with the engine's own client over [fetcher] and verified exactly as a live sync verifies a whole collection
 * (`CrliteSync`: `monitor/changes`, the changeset at that `_expected` with no `_since`, one [ChangesetVerifier], the
 * schema, the placement, the server root's attachment base, and each placed attachment by size and SHA-256), then
 * [buildSeed], then loaded once by [SeedLoader] from the bytes in memory under [source]'s pins into a fresh in-memory
 * store and a [KotlinRevocationEngine]. Only an archive that installs is returned, and [write] writes nothing before
 * that.
 *
 * No `_since`, no reset-and-retry, no backoff: one attempt, and any failure ends the job. The clock is the caller's
 * ([build]'s `nowMillis`, the x5u validity of the fetch); the self-load checks the x5u at the seed's signed `<ts>`, as
 * any seed load does.
 */
internal class SeedJob(
    private val source: MozillaRemoteSettings,
    private val fetcher: HttpFetcher,
    private val verifier: SignatureVerifier,
    private val channel: CrliteChannel,
    private val logger: RevoktLogger = RevoktLogger { _, _, _ -> },
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val maxAgeMillis: Long = checkNotNull(RevoktPolicy.DEFAULT.staleness(Dataset.CRLITE)).staleAfterMillis,
    private val writeFile: (Path, ByteArray) -> Unit = { path, bytes -> Files.write(path, bytes) },
) {
    /** The archive, built and self-loaded; nothing is written. */
    fun build(nowMillis: Long): SeedJobResult {
        val client = RemoteSettingsClient(source, Dataset.CRLITE, fetcher, io)
        val expected = client.pollChanges().ok { return it }
        val changeset = client.fetchChangeset(expected, since = null).ok { return it }
        // The whole collection merges over nothing, as the sync's does; a record with no string id is verified as served.
        val records = ContentSignature.merge(emptyList(), changeset.changes) ?: changeset.changes
        val verified =
            when (val verification = ChangesetVerifier(client, verifier, nowMillis).verify(changeset, records)) {
                is ChangesetVerification.Verified -> verification

                is ChangesetVerification.Failed -> return SeedJobResult.Failed(
                    verification.failure,
                    verification.detail,
                )
            }
        val crlite = client.checkRecords(verified.records, channel).ok { return it }
        val filters =
            crlite.map {
                FilterRecord(it.id, it.channel, it.incremental, it.effectiveTimestamp, it.attachment.filename)
            }
        val placed =
            when (val placement = placeFilters(filters, channel)) {
                is Placement.Placed -> placement.filters
                is IndexBuild.Refused -> return SeedJobResult.Failed(placement.failure, placement.detail)
            }
        val byId = crlite.associateBy { it.id }
        val base = client.attachmentBase().ok { return it }
        val bodies = LinkedHashMap<String, ByteString>()
        for (p in placed) {
            bodies[p.record.id] =
                client.fetchAttachment(byId.getValue(p.record.id), base).ok { return it }
        }
        KotlinRevocationEngine().use { engine ->
            val build =
                when (val built = buildSeed(verified, channel, bodies, engine.formats, verifier)) {
                    is SeedBuild.Built -> built
                    is SeedBuild.Refused -> return SeedJobResult.Failed(null, built.detail)
                }
            selfLoad(build, engine)?.let { return SeedJobResult.Failed(null, "the self-load fails: $it") }
            return SeedJobResult.Built(build)
        }
    }

    /**
     * [build], then the archive written to [out] under [version] (`YYYY.MM.DD`, the run's UTC date, spec §7.2 "date-
     * versioned"). The version's shape is checked before any fetch. The signed `<ts>` must fall in the window from
     * [maxAgeMillis] before that UTC day starts (the default policy's CRLite `staleAfter`, 3 days: an older changeset is
     * a frozen or stale source, or a version from the future) to that day's end (a later one means the run's clock is
     * wrong). The archive goes to a temporary file in [out]'s directory, through [writeFile], and is moved over [out]
     * only once the self-load passed and the write completed, so [out] is either the previous file or the new archive
     * whole; a write that fails leaves no temporary file.
     */
    fun write(
        nowMillis: Long,
        version: String,
        out: Path,
    ): SeedJobResult {
        val day =
            dateOf(version) ?: return SeedJobResult.Failed(null, "the version '$version' is not a YYYY.MM.DD date")
        val result = build(nowMillis)
        if (result !is SeedJobResult.Built) return result
        dateProblem(result.build.timestampMillis, version, day)?.let { return SeedJobResult.Failed(null, it) }
        val directory = out.toAbsolutePath().parent
        Files.createDirectories(directory)
        val temporary = Files.createTempFile(directory, out.fileName.toString(), ".tmp")
        try {
            writeFile(temporary, result.build.bytes)
            Files.move(temporary, out, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: IOException) {
            return SeedJobResult.Failed(null, "writing $out failed: $e")
        } finally {
            Files.deleteIfExists(temporary)
        }
        return SeedJobResult.Built(result.build, out)
    }

    /** Why the signed [ts] does not belong under [version] (the UTC [day]), or null. */
    private fun dateProblem(
        ts: Long,
        version: String,
        day: LocalDate,
    ): String? {
        val start = startOf(day)
        val end = startOf(day.plusDays(1))
        return when {
            ts >= end -> "the signed <ts> $ts is after $version ends (UTC): check the run's clock"
            ts < start - maxAgeMillis -> "the signed <ts> $ts is over ${maxAgeMillis}ms before $version: $STALE"
            else -> null
        }
    }

    /**
     * Why [build] does not install as a seed of [channel] under [source]'s pins, or null when it does: [loadInMemory]
     * over the bytes in memory must install exactly [build]'s generation at its `<ts>`.
     */
    private fun selfLoad(
        build: SeedBuild.Built,
        engine: KotlinRevocationEngine,
    ): String? {
        val bytes = build.bytes
        val load =
            loadInMemory(
                SeedSource.of { ByteArrayInputStream(bytes) },
                channel,
                source,
                verifier,
                engine,
                logger,
                build.timestampMillis,
            )
        return when (load) {
            is SeedLoad.Installed -> {
                when {
                    load.generationId != build.generationId -> {
                        "installed ${load.generationId}, not ${build.generationId}"
                    }

                    load.timestampMillis != build.timestampMillis -> {
                        "installed at ${load.timestampMillis}, not ${build.timestampMillis}"
                    }

                    else -> {
                        null
                    }
                }
            }

            else -> {
                "$load"
            }
        }
    }

    private inline fun <T> ClientResult<T>.ok(fail: (SeedJobResult.Failed) -> Nothing): T =
        when (this) {
            is ClientResult.Ok -> {
                value
            }

            is ClientResult.Failed -> {
                fail(SeedJobResult.Failed(failure, detail))
            }

            is ClientResult.Unchanged -> {
                fail(
                    SeedJobResult.Failed(SyncFailure.CHANGESET_FETCH, "304 to a request with no cursor"),
                )
            }
        }

    private fun startOf(day: LocalDate): Long =
        day
            .atStartOfDay(ZoneOffset.UTC)
            .toInstant()
            .toEpochMilli()

    companion object {
        private const val STALE = "a stale source, or a wrong version"

        private val VERSION: DateTimeFormatter =
            DateTimeFormatter.ofPattern("uuuu.MM.dd").withResolverStyle(ResolverStyle.STRICT)

        /** The UTC date [version] names (`YYYY.MM.DD`, a real date), or null. */
        fun dateOf(version: String): LocalDate? =
            if (!Regex("""\d{4}\.\d{2}\.\d{2}""").matches(version)) {
                null
            } else {
                try {
                    LocalDate.parse(version, VERSION)
                } catch (ignored: DateTimeParseException) {
                    null
                }
            }
    }
}
