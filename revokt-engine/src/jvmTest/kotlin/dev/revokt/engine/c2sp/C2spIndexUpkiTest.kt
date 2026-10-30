// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.c2sp

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import okio.ByteString
import okio.ByteString.Companion.toByteString
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

    private val corpus =
        File(checkNotNull(System.getProperty("revokt.clubcardCorpus")) { "revokt.clubcardCorpus not set" })

    /** One mirrored filter as recorded: its mirror name and its bytes, checked against the recorded SHA-256. */
    private class Filter(
        val name: String,
        val bytes: ByteArray,
    )

    private val recorded: List<Filter> =
        rows(resource("upki-index.tsv")).map { line ->
            val (name, path, sha256) = line.split("\t")
            val bytes = File(corpus, path.removePrefix("corpus/clubcard/")).readBytes()
            assertEquals(sha256, bytes.toByteString().sha256().hex(), "$path changed since the golden was recorded")
            Filter(name, bytes)
        }

    private fun rows(tsv: ByteArray): List<String> =
        tsv.decodeToString().lines().filter {
            it.isNotBlank() &&
                !it.startsWith("#")
        }

    private fun coverage(bytes: ByteArray): Map<ByteString, Window> =
        ClubcardFilters
            .decode(bytes)
            .universe.logs
            .map { (log, interval) ->
                log.bytes to Window(interval.low.value.toULong(), interval.high.value.toULong())
            }.toMap()

    @Test
    fun `revokt writes upki's index byte for byte`() {
        val filters = recorded.map { it.name to coverage(it.bytes) }
        assertContentEquals(resource("upki-index.bin"), C2spIndex.write(C2spIndex.index(filters)))
    }

    @Test
    fun `upki's index reads back to tables consistent with the filters' coverage`() {
        val index = C2spIndex.read(resource("upki-index.bin"))
        assertEquals(recorded.map { it.name }, index.filenames)
        assertEquals(
            emptyList(),
            C2spIndex.inconsistencies(index, recorded.associate { it.name to coverage(it.bytes) }),
        )
    }
}
