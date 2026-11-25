// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.seed

import dev.revokt.CrliteChannel
import dev.revokt.KotlinRevocationEngine
import dev.revokt.MozillaRemoteSettings
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.engine.seed.SeedLoad
import dev.revokt.engine.seed.loadInMemory
import dev.revokt.verify.JcaSignatureVerifier
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.zip.ZipException
import java.util.zip.ZipFile
import kotlin.system.exitProcess

/**
 * The floor check's re-verification of a released seed jar (#308; `seedTimestamp<Channel>`): `--channel
 * compat|default --jar <file> --out <file>`. Loads the jar's `revokt/seed-<channel>.zip` as an app's start would, under
 * [MozillaRemoteSettings.DEFAULT]'s pins and with the x5u valid at the signed `<ts>` ([verifiedTimestamp]), and writes
 * that `<ts>` to `--out`, one decimal line. No network: the x5u chain is inside the archive. Exit 0 when verified, 1
 * otherwise (nothing written; an earlier `--out` is deleted first), 2 on a usage error. An object, since [main] in
 * SeedMain.kt is the package's top-level `main`.
 */
object SeedTimestampMain {
    @JvmStatic
    fun main(args: Array<String>) {
        val parsed = SeedArgs.parse(args, setOf("--channel", "--jar", "--out")) ?: timestampUsage()
        val channel = SeedArgs.channel(parsed.getValue("--channel")) ?: timestampUsage()
        exitProcess(
            writeTimestamp(
                Path.of(parsed.getValue("--jar")),
                channel,
                MozillaRemoteSettings.DEFAULT,
                JcaSignatureVerifier(),
                Path.of(parsed.getValue("--out")),
                System.currentTimeMillis(),
            ),
        )
    }
}

/** What [verifiedTimestamp] found: the signed `<ts>` of a seed that installs, or why there is none. */
internal sealed interface SeedTimestampResult {
    /** The seed installs, at [timestampMillis]. */
    class Verified(
        val timestampMillis: Long,
    ) : SeedTimestampResult

    /** The seed does not install, for [detail]. */
    class Refused(
        val detail: String,
    ) : SeedTimestampResult
}

/**
 * The signed `<ts>` of [jar]'s seed of [channel] when it installs under [source]'s pins ([loadInMemory], the load an
 * app's start runs and the seed job's self-load), else why not: a file that is not a zip, no
 * `revokt/seed-<channel>.zip` entry, or any load other than [SeedLoad.Installed]. [nowMillis] reaches only the
 * in-memory store's bookkeeping; no check reads it.
 */
internal fun verifiedTimestamp(
    jar: Path,
    channel: CrliteChannel,
    source: MozillaRemoteSettings,
    verifier: SignatureVerifier,
    nowMillis: Long,
): SeedTimestampResult {
    val resource = "revokt/seed-${channel.name.lowercase()}.zip"
    return try {
        ZipFile(jar.toFile()).use { verifiedEntry(it, resource, channel, source, verifier, nowMillis) }
    } catch (e: ZipException) {
        SeedTimestampResult.Refused("$jar is not a jar: $e")
    } catch (e: IOException) {
        SeedTimestampResult.Refused("reading $jar failed: $e")
    }
}

/** [verifiedTimestamp] of [zip]'s [resource]. */
private fun verifiedEntry(
    zip: ZipFile,
    resource: String,
    channel: CrliteChannel,
    source: MozillaRemoteSettings,
    verifier: SignatureVerifier,
    nowMillis: Long,
): SeedTimestampResult {
    val entry = zip.getEntry(resource) ?: return SeedTimestampResult.Refused("${zip.name} holds no $resource")
    val seed = SeedSource.of { zip.getInputStream(entry) }
    val load =
        KotlinRevocationEngine().use { engine ->
            loadInMemory(seed, channel, source, verifier, engine, STDERR, nowMillis)
        }
    return when (load) {
        is SeedLoad.Installed -> SeedTimestampResult.Verified(load.timestampMillis)
        else -> SeedTimestampResult.Refused("$resource does not install: $load")
    }
}

/**
 * [verifiedTimestamp], with the `<ts>` written to [out] through a temporary file beside it: 0 when written, 1 otherwise.
 * [out] is deleted first, so a refusal never leaves an earlier run's `<ts>` behind.
 */
internal fun writeTimestamp(
    jar: Path,
    channel: CrliteChannel,
    source: MozillaRemoteSettings,
    verifier: SignatureVerifier,
    out: Path,
    nowMillis: Long,
): Int {
    Files.deleteIfExists(out)
    val ts =
        when (val result = verifiedTimestamp(jar, channel, source, verifier, nowMillis)) {
            is SeedTimestampResult.Verified -> {
                result.timestampMillis
            }

            is SeedTimestampResult.Refused -> {
                System.err.println("seed: not verified: ${result.detail}")
                return 1
            }
        }
    val directory = out.toAbsolutePath().parent
    Files.createDirectories(directory)
    val temporary = Files.createTempFile(directory, out.fileName.toString(), ".tmp")
    try {
        Files.writeString(temporary, "$ts\n")
        Files.move(temporary, out, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    } catch (e: IOException) {
        System.err.println("seed: writing $out failed: $e")
        return 1
    } finally {
        Files.deleteIfExists(temporary)
    }
    System.err.println("seed: $jar verified: the signed <ts> is $ts")
    return 0
}

private fun timestampUsage(): Nothing {
    System.err.println("usage: --channel compat|default --jar <file> --out <file>")
    exitProcess(2)
}
