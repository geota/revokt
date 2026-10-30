// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.c2sp

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/**
 * Spec §9 "`index.bin` byte comparison" (#86): revokt's writer reproduces, byte for byte, the `index.bin` upki 1.0.1
 * wrote for the corpus/clubcard filters (native/revokt-oracle/record-upki-index.sh), and its reader reads it back to
 * the same tables, consistent with the filters' own coverage.
 */
@OptIn(RevoktInternalApi::class)
class C2spIndexUpkiTest {
    private fun resource(name: String): ByteArray =
        checkNotNull(
            javaClass.getResourceAsStream("/dev/revokt/engine/c2sp/$name"),
        ) { "missing $name" }.use { it.readBytes() }

    /** The mirror's filters in the recorded order: name, source path (from the repository root), SHA-256. */
    private val recorded: List<List<String>> =
        resource("upki-index.tsv")
            .decodeToString()
            .lines()
            .filter {
                it.isNotBlank() && !it.startsWith("#")
            }.map { it.split("\t") }

    /** The repository root, from the test's working directory (the module). */
    private val root = File("..")

    private fun coverage(path: String): Map<okio.ByteString, Window> =
        ClubcardFilters
            .decode(File(root, path).readBytes())
            .universe.logs
            .map { (log, interval) -> log.bytes to Window(interval.low.value.toULong(), interval.high.value.toULong()) }
            .toMap()

    @Test
    fun `revokt writes upki's index byte for byte`() {
        val filters = recorded.map { (name, path, _) -> name to coverage(path) }
        assertContentEquals(resource("upki-index.bin"), C2spIndex.write(C2spIndex.index(filters)))
    }

    @Test
    fun `upki's index reads back to tables consistent with the filters' coverage`() {
        val index = C2spIndex.read(resource("upki-index.bin"))
        assertEquals(recorded.map { it[0] }, index.filenames)
        assertEquals(
            emptyList(),
            C2spIndex.inconsistencies(
                index,
                recorded.associate { (name, path, _) ->
                    name to
                        coverage(path)
                },
            ),
        )
    }
}
