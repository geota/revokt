// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed

import dev.revokt.ClubcardCorpus
import dev.revokt.CrliteChannel
import dev.revokt.engine.fetch.ScriptedFetcher
import dev.revokt.engine.update.UpdateFixtures
import java.io.File
import kotlin.test.Test
import kotlin.test.assertIs

/**
 * Writes data/seed's `check` fixture (#145): a Remote Settings exchange signed under this suite's **test** keys (the
 * x5u chain of [dev.revokt.engine.verify.X5uChainFixture], never a real or Mozilla key), recorded from [SeedJob] over the
 * scripted server, so the data/seed build runs its write, pack and smoke-load tasks with no network. Run only to
 * regenerate it: `./gradlew :revokt-engine:jvmTest --tests '*SeedCheckFixtureWriter*' -Drevokt.writeSeedFixture=$PWD/data/seed/src/test/resources/fixture`.
 * The attachments are routed to the committed `corpus/clubcard` filters rather than copied.
 *
 * Files: `routes.tsv` (each URL the job fetched and the file that answers it, `corpus:<path>` for a corpus filter),
 * one `<n>.body` per other response, `pin.txt` (the test root's SPKI SHA-256), `now.txt` (the fetch clock) and
 * `version.txt` (the date version of `<ts>`).
 */
internal class SeedCheckFixtureWriter : SeedFixture() {
    @Test
    fun `writes data seed's check fixture when asked`() {
        val dir = System.getProperty("revokt.writeSeedFixture")?.let(::File) ?: return
        dir.mkdirs()
        dir.listFiles().orEmpty().forEach { it.delete() }
        val server = Server()
        val routes = StringBuilder("# url\tfile (written by SeedCheckFixtureWriter; test keys only)\n")
        var n = 0
        val corpus =
            mapOf(
                UpdateFixtures.FULL_PATH to ClubcardCorpus.file(UpdateFixtures.FULL_PATH).readBytes(),
                UpdateFixtures.DELTA_PATH to ClubcardCorpus.file(UpdateFixtures.DELTA_PATH).readBytes(),
            )
        val recording =
            ScriptedFetcher { request ->
                val response = server.fetcher.fetch(request)
                check(response.status == 200) { "${request.url}: ${response.status}" }
                val body = response.body
                val file =
                    corpus.entries.firstOrNull { it.value.contentEquals(body) }?.let { "corpus:${it.key}" }
                        ?: "${n++}.body".also { File(dir, it).writeBytes(body) }
                routes
                    .append(request.url)
                    .append('\t')
                    .append(file)
                    .append('\n')
                response
            }
        val now = ts + hour
        assertIs<SeedJobResult.Built>(SeedJob(source, recording, verifier, CrliteChannel.COMPAT).build(now))
        File(dir, "routes.tsv").writeText(routes.toString())
        File(dir, "pin.txt").writeText(pinned.single().hex() + "\n")
        File(dir, "now.txt").writeText("$now\n")
        File(dir, "version.txt").writeText("2026.10.21\n")
    }
}
