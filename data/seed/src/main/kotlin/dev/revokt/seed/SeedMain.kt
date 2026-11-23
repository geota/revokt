// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.seed

import dev.revokt.CrliteChannel
import dev.revokt.LogLevel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLogger
import dev.revokt.engine.seed.SeedJob
import dev.revokt.engine.seed.SeedJobResult
import dev.revokt.jsse.JdkHttpFetcher
import dev.revokt.verify.JcaSignatureVerifier
import java.nio.file.Path
import kotlin.system.exitProcess

/**
 * The seed job's entry (#145; `writeSeed<Channel>`): `--channel compat|default --version YYYY.MM.DD --out <file>`.
 * Fetches Mozilla's production `cert-revocations` changeset with [JdkHttpFetcher] under [MozillaRemoteSettings.DEFAULT]
 * (its hosts, x5u rules and pinned root), verifies it as a live sync does, builds the archive, self-loads it, and only
 * then writes it ([SeedJob.write]). The wall clock is read here, once, for the fetch's x5u validity. Exit 0 when
 * written, 1 when the job failed (nothing written), 2 on a usage error.
 */
fun main(args: Array<String>) {
    val parsed = SeedArgs.parse(args, setOf("--channel", "--version", "--out")) ?: usage()
    val channel = SeedArgs.channel(parsed.getValue("--channel")) ?: usage()
    exitProcess(
        run(
            SeedJob(MozillaRemoteSettings.DEFAULT, JdkHttpFetcher(), JcaSignatureVerifier(), channel, STDERR),
            System.currentTimeMillis(),
            parsed.getValue("--version"),
            Path.of(parsed.getValue("--out")),
        ),
    )
}

/** Runs [job] and reports its outcome on stderr: 0 when the archive is written, 1 otherwise. */
internal fun run(
    job: SeedJob,
    nowMillis: Long,
    version: String,
    out: Path,
): Int =
    when (val result = job.write(nowMillis, version, out)) {
        is SeedJobResult.Built -> {
            System.err.println(
                "seed: wrote ${result.path} (${result.build.generationId}, ${result.build.filterFormat}, ${result.build.bytes.size} bytes)",
            )
            0
        }

        is SeedJobResult.Failed -> {
            System.err.println("seed: nothing written: ${result.failure ?: "refused"}: ${result.detail}")
            1
        }
    }

/** The job's log lines, on stderr. */
internal val STDERR: RevoktLogger =
    RevoktLogger { level: LogLevel, message: String, cause: Throwable? ->
        System.err.println("seed: $level $message" + (cause?.let { ": $it" } ?: ""))
    }

/** The entries' argument parsing: `--name value` pairs, each of [names] exactly once, nothing else. */
internal object SeedArgs {
    /** [args] as name to value, or null when a name is unknown, missing, repeated or has no value. */
    fun parse(
        args: Array<String>,
        names: Set<String>,
    ): Map<String, String>? {
        if (args.size != 2 * names.size) return null
        val out = LinkedHashMap<String, String>()
        for (i in args.indices step 2) {
            val name = args[i]
            if (name !in names || name in out) return null
            out[name] = args[i + 1]
        }
        return out
    }

    /** The channel whose wire name is [name] (`compat`, `default`), or null. */
    fun channel(name: String): CrliteChannel? = CrliteChannel.entries.firstOrNull { it.name.lowercase() == name }
}

private fun usage(): Nothing {
    System.err.println("usage: --channel compat|default --version YYYY.MM.DD --out <file>")
    exitProcess(2)
}
