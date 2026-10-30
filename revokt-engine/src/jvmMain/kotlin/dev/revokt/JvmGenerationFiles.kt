// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString.Companion.toByteString
import java.nio.file.Files
import java.nio.file.Path

/** Reads [GenerationFiles] from disk (spec §3.2), so a third-party engine can be tested against a C2SP directory image. */
public object JvmGenerationFiles {
    private const val INDEX = "index.bin"

    /**
     * Reads the C2SP directory image in [dir]: `index.bin` and the filter files it names. Other files in [dir], such as a
     * mirror's `manifest.json`, are not part of the generation.
     *
     * Spec §3.2 gives this helper no generation id or timestamp, so both are derived. The id is `files-sha256:` and the
     * hex SHA-256 of every file's name and content hash in name order, so any changed byte changes it; it is not the
     * loader's MIRROR/SYSTEM id (§4: the manifest hash). The source timestamp is `index.bin`'s last-modified time, which a
     * fresh git checkout does not reproduce.
     *
     * @throws java.io.IOException when [dir] has no readable `index.bin` or a named file cannot be read.
     * @throws IllegalArgumentException when `index.bin` is malformed, or a file it names is not a regular file in [dir].
     */
    @RevoktTestingApi
    @JvmStatic
    public fun fromDirectory(
        dir: Path,
        dataset: Dataset,
        trustClass: TrustClass,
        format: FilterFormat,
    ): GenerationFiles {
        val indexPath = dir.resolve(INDEX)
        val files = linkedMapOf(INDEX to Files.readAllBytes(indexPath))
        for (name in GenerationFiles.filenamesIn(files.getValue(INDEX))) {
            val path = dir.resolve(name)
            require(Files.isRegularFile(path)) { "$indexPath names $name, which is not a regular file in $dir" }
            files[name] = Files.readAllBytes(path)
        }
        val digest = files.keys.sorted().joinToString("\n") { "$it\t" + sha256Hex(files.getValue(it)) }
        return GenerationFiles
            .Builder()
            .generationId("files-sha256:" + sha256Hex(digest.encodeToByteArray()))
            .dataset(dataset)
            .trustClass(trustClass)
            .format(format)
            .sourceTimestampMillis(Files.getLastModifiedTime(indexPath).toMillis())
            .also { b -> files.forEach { (name, bytes) -> b.file(name, bytes) } }
            .build()
    }

    private fun sha256Hex(bytes: ByteArray): String = bytes.toByteString().sha256().hex()
}
