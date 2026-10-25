// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.buildlogic

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals

class CorpusFilesTest {
    @Test
    fun `only the root's manifest, README and git directory are skipped`() {
        val dir = Files.createTempDirectory("corpus").toFile()
        try {
            for (path in listOf(
                "manifest.sha256",
                "README.md",
                ".git/config",
                "a/data.bin",
                "a/README.md",
                "a/manifest.sha256",
                "a/.git/hidden",
            )) {
                dir.resolve(path).apply { parentFile.mkdirs() }.writeText(path)
            }
            assertEquals(
                listOf("a/.git/hidden", "a/README.md", "a/data.bin", "a/manifest.sha256"),
                corpusFiles(dir).map { it.relativeTo(dir).invariantSeparatorsPath }.sorted().toList(),
            )
        } finally {
            dir.deleteRecursively()
        }
    }
}
