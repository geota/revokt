// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.seed

import dev.revokt.CrliteChannel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.SeedSource
import dev.revokt.SignatureVerifier
import dev.revokt.engine.seed.SeedSignature
import dev.revokt.engine.seed.verifySeedSignature
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
 * compat|default --jar <file> --out <file>`. Verifies the content signature of the jar's `revokt/seed-<channel>.zip`
 * under [MozillaRemoteSettings.DEFAULT]'s pins, with the x5u valid at the signed `<ts>` ([verifiedTimestamp]), and
 * writes that `<ts>` to `--out`, one decimal line. No network: the x5u chain is inside the archive. Exit 0 when
 * verified, 1 otherwise (nothing written; an earlier `--out` is deleted first), 2 on a usage error. An object, since
 * [main] in SeedMain.kt is the package's top-level `main`.
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
            ),
        )
    }
}

/**
 * [jar]'s `revokt/seed-<channel>.zip` through the engine's [verifySeedSignature] under [source]'s pins: its signed
 * `<ts>`, or why not (also a file that is not a zip, or no such entry). Only the format-independent parts are checked,
 * as Firefox re-verifies its local data; the seed is not installed.
 */
internal fun verifiedTimestamp(
    jar: Path,
    channel: CrliteChannel,
    source: MozillaRemoteSettings,
    verifier: SignatureVerifier,
): SeedSignature {
    val resource = "revokt/seed-${channel.name.lowercase()}.zip"
    return try {
        ZipFile(jar.toFile()).use { zip ->
            val entry = zip.getEntry(resource) ?: return SeedSignature.Refused("$jar holds no $resource")
            verifySeedSignature(SeedSource.of { zip.getInputStream(entry) }, channel, source, verifier)
        }
    } catch (e: ZipException) {
        SeedSignature.Refused("$jar is not a jar: $e")
    } catch (e: IOException) {
        SeedSignature.Refused("reading $jar failed: $e")
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
): Int {
    Files.deleteIfExists(out)
    val ts =
        when (val result = verifiedTimestamp(jar, channel, source, verifier)) {
            is SeedSignature.Verified -> {
                result.timestampMillis
            }

            is SeedSignature.Refused -> {
                System.err.println("seed: not verified: ${result.detail}")
                return 1
            }
        }
    var temporary: Path? = null
    try {
        val directory = out.toAbsolutePath().parent
        Files.createDirectories(directory)
        temporary = Files.createTempFile(directory, out.fileName.toString(), ".tmp")
        Files.writeString(temporary, "$ts\n")
        Files.move(temporary, out, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    } catch (e: IOException) {
        System.err.println("seed: writing $out failed: $e")
        return 1
    } finally {
        temporary?.let { Files.deleteIfExists(it) }
    }
    System.err.println("seed: $jar verified: the signed <ts> is $ts")
    return 0
}

private fun timestampUsage(): Nothing {
    System.err.println("usage: --channel compat|default --jar <file> --out <file>")
    exitProcess(2)
}
