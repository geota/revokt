// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.clubcard.RevoktInternalApi
import dev.revokt.clubcard.api.ClubcardFilters
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.Window
import okio.ByteString
import java.io.File

/** The committed `corpus/clubcard` filters (docs/dev/corpus.md), and C2SP generation images built from them. */
@OptIn(RevoktInternalApi::class, RevoktTestingApi::class)
internal object ClubcardCorpus {
    val dir = File(checkNotNull(System.getProperty("revokt.clubcardCorpus")) { "revokt.clubcardCorpus not set" })

    fun file(path: String): File = File(dir, path).also { check(it.isFile) { "missing $it" } }

    /** A filter's coverage, from its decoded universe, as the C2SP index writer takes it. */
    fun coverage(bytes: ByteArray): Map<ByteString, Window> =
        ClubcardFilters
            .decode(bytes)
            .universe.logs
            .map { (log, interval) -> log.bytes to Window(interval.low.value.toULong(), interval.high.value.toULong()) }
            .toMap()

    /** A generation of [filters] (name to bytes) with an `index.bin` written by revokt's own writer. */
    fun generation(
        id: String,
        format: FilterFormat,
        filters: Map<String, ByteArray>,
        sourceTimestampMillis: Long = 1_793_318_400_000,
    ): GenerationFiles {
        val index = C2spIndex.write(C2spIndex.index(filters.map { (name, bytes) -> name to coverage(bytes) }))
        return GenerationFiles
            .Builder()
            .generationId(id)
            .trustClass(TrustClass.SYSTEM)
            .format(format)
            .sourceTimestampMillis(sourceTimestampMillis)
            .file("index.bin", index)
            .also { b -> filters.forEach { (name, bytes) -> b.file(name, bytes) } }
            .build()
    }

    /**
     * A generation of the corpus files at [paths] (relative to the corpus), named `filter0`, `filter1`, … in order: some
     * corpus file names are longer than C2SP's 32 bytes.
     */
    fun generation(
        id: String,
        format: FilterFormat,
        vararg paths: String,
    ): GenerationFiles =
        generation(id, format, paths.withIndex().associate { (i, path) -> "filter$i" to file(path).readBytes() })
}
