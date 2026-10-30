// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import okio.ByteString.Companion.toByteString
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * `JvmGenerationFiles.fromDirectory` (spec §3.2, #87) over real C2SP directory images: upki 1.0.1's own `index.bin`
 * for the corpus/clubcard filters (#86's golden), and the v3 corpus filters indexed by revokt's own writer. A mirror's
 * `manifest.json` sits beside them, which is not part of the generation.
 */
@OptIn(RevoktTestingApi::class, RevoktInternalApi::class)
class JvmGenerationFilesTest {
    private fun resource(name: String): ByteArray =
        checkNotNull(
            javaClass.getResourceAsStream("/dev/revokt/engine/c2sp/$name"),
        ) { "missing $name" }.use { it.readBytes() }

    private val corpus =
        File(checkNotNull(System.getProperty("revokt.clubcardCorpus")) { "revokt.clubcardCorpus not set" })

    private val mtime = 1_793_318_400_000

    /** Mirror name to bytes, from the golden's provenance, each checked against its recorded SHA-256. */
    private val filters: Map<String, ByteArray> =
        resource(
            "upki-index.tsv",
        ).decodeToString().lines().filter { it.isNotBlank() && !it.startsWith("#") }.associate { line ->
            val (name, path, sha256) = line.split("\t")
            val bytes = File(corpus, path.removePrefix("corpus/clubcard/")).readBytes()
            assertEquals(sha256, bytes.toByteString().sha256().hex(), "$path changed since the golden was recorded")
            name to bytes
        }

    /** Runs [block] on a temporary C2SP image of [index] and [files], deleted afterwards. */
    private fun <T> withImage(
        index: ByteArray,
        files: Map<String, ByteArray>,
        block: (Path) -> T,
    ): T {
        val dir = Files.createTempDirectory("c2sp-image")
        try {
            Files.write(dir.resolve("index.bin"), index)
            Files.setLastModifiedTime(dir.resolve("index.bin"), FileTime.fromMillis(mtime))
            Files.write(dir.resolve("manifest.json"), "{}".toByteArray())
            files.forEach { (name, bytes) -> Files.write(dir.resolve(name), bytes) }
            return block(dir)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    private fun read(dir: Path): GenerationFiles =
        JvmGenerationFiles.fromDirectory(dir, Dataset.CRLITE, TrustClass.SYSTEM, FilterFormat.V3)

    /** The id `fromDirectory` derives: the SHA-256 of every file's name and content hash, in name order. */
    private fun expectedId(files: Map<String, ByteArray>): String {
        val digest =
            files.keys.sorted().joinToString(
                "\n",
            ) {
                "$it\t" +
                    files
                        .getValue(it)
                        .toByteString()
                        .sha256()
                        .hex()
            }
        return "files-sha256:" +
            digest
                .encodeToByteArray()
                .toByteString()
                .sha256()
                .hex()
    }

    @Test
    fun `upki's image reads as its index and the files it names`() {
        val index = resource("upki-index.bin")
        val g = withImage(index, filters, ::read)
        assertEquals(filters.keys + "index.bin", g.names, "manifest.json is not part of the generation")
        assertEquals(expectedId(filters + ("index.bin" to index)), g.generationId)
        assertEquals(mtime, g.sourceTimestampMillis)
        assertEquals(TrustClass.SYSTEM, g.trustClass)
        for ((name, bytes) in filters) {
            assertContentEquals(bytes, g.bytes(name))
            assertContentEquals(bytes.toByteString().sha256().toByteArray(), g.sha256(name))
        }
    }

    @Test
    fun `any changed filter byte changes the generation id`() {
        val index = resource("upki-index.bin")
        val good = withImage(index, filters, ::read)
        val flipped = filters.getValue("full-v3").copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        val corrupt = withImage(index, filters + ("full-v3" to flipped), ::read)
        assertNotEquals(good.generationId, corrupt.generationId)
        assertNotEquals(good, corrupt)
    }

    @Test
    fun `the v3 corpus indexed by revokt's writer round trips from disk and through newBuilder`() {
        val v3 = filters.filterKeys { it.endsWith("-v3") }
        val coverage =
            v3.map { (name, bytes) ->
                val logs = ClubcardFilters.decode(bytes).universe.logs
                name to
                    logs.map { (log, w) -> log.bytes to Window(w.low.value.toULong(), w.high.value.toULong()) }.toMap()
            }
        val index = C2spIndex.write(C2spIndex.index(coverage))
        val fromDisk = withImage(index, v3, ::read)
        val built =
            GenerationFiles
                .Builder()
                .generationId(expectedId(v3 + ("index.bin" to index)))
                .trustClass(TrustClass.SYSTEM)
                .format(FilterFormat.V3)
                .sourceTimestampMillis(mtime)
                .file("index.bin", index)
                .also { b -> v3.forEach { (name, bytes) -> b.file(name, bytes) } }
                .build()
        assertEquals(built, fromDisk)
        assertEquals(fromDisk, fromDisk.newBuilder().build())
    }

    @Test
    fun `a named file missing or not a regular file, or no index, is rejected`() {
        val index = resource("upki-index.bin")
        val missing = assertFailsWith<IllegalArgumentException> { withImage(index, filters - "delta-v4", ::read) }
        assertTrue("delta-v4" in missing.message!!, missing.message)
        val directory =
            assertFailsWith<IllegalArgumentException> {
                withImage(index, filters - "delta-v4") { dir ->
                    Files.createDirectory(dir.resolve("delta-v4"))
                    read(dir)
                }
            }
        assertTrue("not a regular file" in directory.message!!, directory.message)
        val empty = Files.createTempDirectory("c2sp-empty")
        try {
            assertFailsWith<java.nio.file.NoSuchFileException> { read(empty) }
        } finally {
            empty.toFile().deleteRecursively()
        }
    }
}
