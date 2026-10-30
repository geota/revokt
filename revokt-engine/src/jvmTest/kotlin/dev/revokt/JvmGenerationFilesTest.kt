// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString.Companion.toByteString
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * `JvmGenerationFiles.fromDirectory` (spec §3.2, #87) over a real C2SP directory image: upki 1.0.1's own `index.bin`
 * for the corpus/clubcard filters (#86's golden) and those filters under their mirror names, plus a `manifest.json` a
 * mirror would serve, which is not part of the generation.
 */
@OptIn(RevoktTestingApi::class)
class JvmGenerationFilesTest {
    private fun resource(name: String): ByteArray =
        checkNotNull(
            javaClass.getResourceAsStream("/dev/revokt/engine/c2sp/$name"),
        ) { "missing $name" }.use { it.readBytes() }

    private val corpus =
        File(checkNotNull(System.getProperty("revokt.clubcardCorpus")) { "revokt.clubcardCorpus not set" })

    /** Mirror name to source path, from the golden's provenance. */
    private val filters: Map<String, File> =
        resource(
            "upki-index.tsv",
        ).decodeToString().lines().filter { it.isNotBlank() && !it.startsWith("#") }.associate { line ->
            val (name, path) = line.split("\t")
            name to File(corpus, path.removePrefix("corpus/clubcard/"))
        }

    private fun image(withFilters: Map<String, File> = filters): Path {
        val dir = Files.createTempDirectory("c2sp-image")
        Files.write(dir.resolve("index.bin"), resource("upki-index.bin"))
        Files.setLastModifiedTime(dir.resolve("index.bin"), FileTime.fromMillis(1_793_318_400_000))
        Files.write(dir.resolve("manifest.json"), "{}".toByteArray())
        withFilters.forEach { (name, file) -> Files.copy(file.toPath(), dir.resolve(name)) }
        return dir
    }

    @Test
    fun `a C2SP directory image reads as its index and the files it names`() {
        val g = JvmGenerationFiles.fromDirectory(image(), Dataset.CRLITE, TrustClass.SYSTEM, FilterFormat.V3)
        assertEquals(filters.keys + "index.bin", g.names, "manifest.json is not part of the generation")
        assertEquals("sha256:" + resource("upki-index.bin").toByteString().sha256().hex(), g.generationId)
        assertEquals(1_793_318_400_000, g.sourceTimestampMillis)
        assertEquals(TrustClass.SYSTEM, g.trustClass)
        for ((name, file) in filters) {
            assertContentEquals(file.readBytes(), g.bytes(name))
            assertContentEquals(
                file
                    .readBytes()
                    .toByteString()
                    .sha256()
                    .toByteArray(),
                g.sha256(name),
            )
        }
    }

    @Test
    fun `the image from disk equals the same image built in memory`() {
        val fromDisk = JvmGenerationFiles.fromDirectory(image(), Dataset.CRLITE, TrustClass.SYSTEM, FilterFormat.V3)
        val built =
            GenerationFiles
                .Builder()
                .generationId(fromDisk.generationId)
                .trustClass(TrustClass.SYSTEM)
                .format(FilterFormat.V3)
                .sourceTimestampMillis(fromDisk.sourceTimestampMillis)
                .file("index.bin", resource("upki-index.bin"))
                .also { b -> filters.forEach { (name, file) -> b.file(name, file.readBytes()) } }
                .build()
        assertEquals(built, fromDisk)
    }

    @Test
    fun `a named file missing from the directory, or no index, is rejected`() {
        val missing =
            assertFailsWith<IllegalArgumentException> {
                JvmGenerationFiles.fromDirectory(
                    image(filters - "delta-v4"),
                    Dataset.CRLITE,
                    TrustClass.SYSTEM,
                    FilterFormat.V3,
                )
            }
        assertTrue("delta-v4" in missing.message!!, missing.message)
        val empty = Files.createTempDirectory("c2sp-empty")
        assertFailsWith<java.nio.file.NoSuchFileException> {
            JvmGenerationFiles.fromDirectory(empty, Dataset.CRLITE, TrustClass.SYSTEM, FilterFormat.V3)
        }
    }
}
