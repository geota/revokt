// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class, dev.revokt.RevoktTestingApi::class)

package dev.revokt.seed

import dev.revokt.CrliteChannel
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.MozillaRemoteSettings
import dev.revokt.engine.seed.SeedJob
import dev.revokt.verify.JcaSignatureVerifier
import java.nio.file.Files
import java.nio.file.Path
import kotlin.system.exitProcess

/**
 * The check path's job (`writeTestSeed`, #145): `--fixture <dir> --corpus <corpus/clubcard> --out <file>`. The same
 * [SeedJob.write] and [run] as `writeSeed<Channel>`, over [FixtureFetcher] instead of the network and under the
 * fixture's test pin instead of Mozilla's, at the fixture's clock and version. The fixture is test-signed
 * (`SeedCheckFixtureWriter` in revokt-engine's tests): no real or Mozilla key.
 */
fun main(args: Array<String>) {
    val parsed = SeedArgs.parse(args, setOf("--fixture", "--corpus", "--out")) ?: exitProcess(2)
    val fixture = Path.of(parsed.getValue("--fixture"))
    val fetcher = FixtureFetcher(fixture, Path.of(parsed.getValue("--corpus")))
    val pin = hex(Files.readString(fixture.resolve("pin.txt")).trim())
    val source =
        MozillaRemoteSettings.DEFAULT
            .newBuilder()
            .pinnedRootSpkiSha256s(listOf(pin))
            .build()
    val job = SeedJob(source, fetcher, JcaSignatureVerifier(), CrliteChannel.COMPAT, STDERR)
    val now = Files.readString(fixture.resolve("now.txt")).trim().toLong()
    val version = Files.readString(fixture.resolve("version.txt")).trim()
    val status = run(job, now, version, Path.of(parsed.getValue("--out")))
    if (status == 0 && fetcher.unanswered.isNotEmpty()) {
        System.err.println("seed: the job asked for URLs the fixture does not hold: ${fetcher.unanswered}")
        exitProcess(1)
    }
    exitProcess(status)
}

/**
 * Answers each request from the fixture's `routes.tsv` (`<url>\t<file>`, the file under the fixture, or `corpus:<path>`
 * under [corpus]); any other URL is a 404, recorded in [unanswered].
 */
class FixtureFetcher(
    private val fixture: Path,
    private val corpus: Path,
) : HttpFetcher {
    private val routes: Map<String, String> =
        Files
            .readAllLines(fixture.resolve("routes.tsv"))
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .associate { it.substringBefore('\t') to it.substringAfter('\t') }

    val unanswered: MutableList<String> = mutableListOf()

    override fun fetch(request: FetchRequest): FetchResponse {
        val file = routes[request.url]
        if (file == null) {
            unanswered += request.url
            return FetchResponse.Builder().status(NOT_FOUND).build()
        }
        val path = if (file.startsWith(CORPUS)) corpus.resolve(file.removePrefix(CORPUS)) else fixture.resolve(file)
        return FetchResponse
            .Builder()
            .status(OK)
            .body(Files.readAllBytes(path))
            .build()
    }

    private companion object {
        const val CORPUS = "corpus:"
        const val OK = 200
        const val NOT_FOUND = 404
    }
}

private fun hex(text: String): ByteArray = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
