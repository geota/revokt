// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt

import okio.ByteString.Companion.toByteString
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * Reads [GenerationFiles] from disk (spec §3.2), so an engine can be tested against a C2SP directory image.
 * `@RevoktInternalApi` with the engine seam it feeds (#221).
 */
@RevoktInternalApi
public object JvmGenerationFiles {
    private const val INDEX = "index.bin"

    /**
     * Reads the C2SP directory image in [dir]: `index.bin` and the filter files it names. Other files in [dir], such as a
     * mirror's `manifest.json`, are not part of the generation.
     *
     * Spec §3.2 gives this helper no generation id or timestamp, so both are derived. The id is `files-sha256:` and the
     * hex SHA-256 of every file's name and content hash in name order, so any changed byte changes it; it is not the
     * loader's generation id. The source timestamp is `index.bin`'s last-modified time, which a fresh git checkout does
     * not reproduce.
     *
     * @throws java.io.IOException when [dir] has no readable `index.bin` or a named file cannot be read.
     * @throws IllegalArgumentException when `index.bin` is malformed, or a file it names is not a regular file in [dir]
     *   (a symbolic link is not one, so a named file is never read from outside [dir]).
     */
    @JvmStatic
    public fun fromDirectory(
        dir: Path,
        dataset: Dataset,
        format: FilterFormat,
    ): GenerationFiles {
        val indexPath = dir.resolve(INDEX)
        val files = linkedMapOf(INDEX to Files.readAllBytes(indexPath))
        for (name in GenerationFiles.filenamesIn(files.getValue(INDEX))) {
            val path = dir.resolve(name)
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                "$indexPath names $name, which is not a regular file in $dir"
            }
            files[name] = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { it.readBytes() }
        }
        val digest = files.keys.sorted().joinToString("\n") { "$it\t" + sha256Hex(files.getValue(it)) }
        return GenerationFiles
            .Builder()
            .generationId("files-sha256:" + sha256Hex(digest.encodeToByteArray()))
            .dataset(dataset)
            .format(format)
            .sourceTimestampMillis(Files.getLastModifiedTime(indexPath).toMillis())
            .also { b -> files.forEach { (name, bytes) -> b.file(name, bytes) } }
            .build()
    }

    /**
     * Writes [files] to [dir] as a C2SP directory image, the inverse of [fromDirectory]: `index.bin` and every file it
     * names, under the generation's names. [dir] is created when absent, and followed when it is itself a link; a file
     * already there is never overwritten, and a link at a file's name is never followed (each file is created new). A
     * failure part-way through leaves the files written before it. For an engine that reads a directory, such as the
     * upki engine (spec §3.2), and for the corpus tests: the store keeps no directory image (§6.5).
     *
     * @throws java.nio.file.FileAlreadyExistsException when [dir] already holds one of the names.
     */
    @RevoktTestingApi
    @JvmStatic
    public fun toDirectory(
        files: GenerationFiles,
        dir: Path,
    ) {
        Files.createDirectories(dir)
        // Every name is index.bin or a C2SP filename index.bin names (GenerationFiles checks it), so none leaves dir.
        for (name in files.names) {
            Files.write(dir.resolve(name), files.bytes(name), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        }
    }

    private fun sha256Hex(bytes: ByteArray): String = bytes.toByteString().sha256().hex()
}
