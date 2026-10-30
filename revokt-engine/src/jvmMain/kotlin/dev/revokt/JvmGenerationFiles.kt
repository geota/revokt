// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import okio.ByteString.Companion.toByteString
import java.nio.file.Files
import java.nio.file.Path

/** Reads [GenerationFiles] from disk (spec §3.2), so a third-party engine can be tested against a C2SP directory image. */
public object JvmGenerationFiles {
    /**
     * Reads the C2SP directory image in [dir]: `index.bin` and the filter files it names. Other files in [dir], such as a
     * mirror's `manifest.json`, are not part of the generation. Spec §3.2 gives no generation id or timestamp here, so
     * the generation's id is `sha256:` and the hex SHA-256 of its `index.bin`, and its source timestamp is the
     * `index.bin` file's last-modified time.
     */
    @RevoktTestingApi
    @JvmStatic
    public fun fromDirectory(
        dir: Path,
        dataset: Dataset,
        trustClass: TrustClass,
        format: FilterFormat,
    ): GenerationFiles {
        val indexPath = dir.resolve("index.bin")
        val index = Files.readAllBytes(indexPath)
        val names = GenerationFiles.filenamesIn(index)
        val builder =
            GenerationFiles
                .Builder()
                .generationId("sha256:" + index.toByteString().sha256().hex())
                .dataset(dataset)
                .trustClass(trustClass)
                .format(format)
                .sourceTimestampMillis(Files.getLastModifiedTime(indexPath).toMillis())
                .file("index.bin", index)
        for (name in names) {
            val path = dir.resolve(name)
            require(Files.isRegularFile(path)) { "$indexPath names $name, which is not a file in $dir" }
            builder.file(name, Files.readAllBytes(path))
        }
        return builder.build()
    }
}
