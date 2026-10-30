// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.IndexFormatException
import okio.ByteString
import okio.ByteString.Companion.toByteString

/**
 * One data generation as a C2SP directory image (spec §3.2): `index.bin` plus exactly the filter files it names, so
 * any C2SP reader accepts it. A `RevocationEngine` receives it whatever its source; [format] is the only
 * engine-specific property. Construction validates the image: `index.bin` must parse and must not name itself, and
 * the names must be exactly `index.bin` and the filters it names. The constructor is internal; tests and fakes build
 * one with the [Builder] (`@RevoktTestingApi`), or from disk with `JvmGenerationFiles.fromDirectory`.
 */
public class GenerationFiles internal constructor(
    public val generationId: String,
    public val dataset: Dataset,
    public val trustClass: TrustClass,
    public val format: FilterFormat,
    files: Map<String, ByteArray>,
    public val sourceTimestampMillis: Long,
) {
    private val files: Map<String, ByteArray> = files.mapValues { it.value.copyOf() }

    init {
        require(generationId.isNotEmpty()) { "generationId is empty" }
        val index = requireNotNull(this.files[INDEX]) { "the generation has no $INDEX" }
        val named = filenamesIn(index)
        require(INDEX !in named) { "$INDEX names itself as a filter" }
        val missing = named - this.files.keys
        val extra = this.files.keys - named - INDEX
        require(missing.isEmpty()) { "$INDEX names ${missing.sorted()}, which the generation does not hold" }
        require(extra.isEmpty()) { "the generation holds ${extra.sorted()}, which $INDEX does not name" }
    }

    /** The SHA-256 of each file's content, computed once, after the image is validated. */
    private val hashes: Map<String, ByteString> = this.files.mapValues { it.value.toByteString().sha256() }

    /** `index.bin` and the filter files it names; read-only. */
    public val names: Set<String> = buildSet { addAll(this@GenerationFiles.files.keys) }

    /** A fresh copy of [name]'s content. */
    public fun bytes(name: String): ByteArray =
        requireNotNull(files[name]) { "the generation holds no file named $name" }.copyOf()

    /** The SHA-256 of [name]'s content, as a fresh array. */
    public fun sha256(name: String): ByteArray =
        requireNotNull(hashes[name]) { "the generation holds no file named $name" }.toByteArray()

    /** A builder holding this generation's values. */
    @RevoktTestingApi
    public fun newBuilder(): Builder =
        Builder()
            .generationId(generationId)
            .dataset(dataset)
            .trustClass(trustClass)
            .format(format)
            .sourceTimestampMillis(sourceTimestampMillis)
            .also { b -> files.forEach { (name, bytes) -> b.file(name, bytes) } }

    /** Equal when every field is and every file's content is, compared by SHA-256. */
    override fun equals(other: Any?): Boolean =
        other is GenerationFiles &&
            generationId == other.generationId &&
            dataset == other.dataset &&
            trustClass == other.trustClass &&
            format == other.format &&
            sourceTimestampMillis == other.sourceTimestampMillis &&
            hashes == other.hashes

    override fun hashCode(): Int =
        listOf(generationId, dataset, trustClass, format, sourceTimestampMillis, hashes).hashCode()

    override fun toString(): String =
        "GenerationFiles(generationId=$generationId, dataset=$dataset, trustClass=$trustClass, format=$format, " +
            "files=${names.sorted().map { "$it:${hashes.getValue(it).hex().take(HASH_PREFIX)}" }}, " +
            "sourceTimestampMillis=$sourceTimestampMillis)"

    /** Builds a [GenerationFiles] for tests and fakes; [build] validates the image as the constructor does. */
    @RevoktTestingApi
    public class Builder {
        private var generationId: String? = null
        private var dataset: Dataset = Dataset.CRLITE
        private var trustClass: TrustClass? = null
        private var format: FilterFormat? = null
        private var sourceTimestampMillis: Long? = null
        private val files = LinkedHashMap<String, ByteArray>()

        public fun generationId(id: String): Builder = apply { generationId = id }

        public fun dataset(dataset: Dataset): Builder = apply { this.dataset = dataset }

        public fun trustClass(trustClass: TrustClass): Builder = apply { this.trustClass = trustClass }

        public fun format(format: FilterFormat): Builder = apply { this.format = format }

        public fun sourceTimestampMillis(millis: Long): Builder = apply { sourceTimestampMillis = millis }

        /** Adds or replaces the file [name] with a copy of [bytes]. */
        public fun file(
            name: String,
            bytes: ByteArray,
        ): Builder = apply { files[name] = bytes.copyOf() }

        public fun build(): GenerationFiles =
            GenerationFiles(
                generationId = requireNotNull(generationId) { "generationId is not set" },
                dataset = dataset,
                trustClass = requireNotNull(trustClass) { "trustClass is not set" },
                format = requireNotNull(format) { "format is not set" },
                files = files,
                sourceTimestampMillis = requireNotNull(sourceTimestampMillis) { "sourceTimestampMillis is not set" },
            )
    }

    internal companion object {
        private const val INDEX = "index.bin"
        private const val HASH_PREFIX = 12

        /** The filter names [index] lists; a malformed index is an [IllegalArgumentException]. */
        fun filenamesIn(index: ByteArray): Set<String> =
            try {
                C2spIndex.read(index).filenames.toSet()
            } catch (e: IndexFormatException) {
                throw IllegalArgumentException("malformed $INDEX: ${e.message}", e)
            }
    }
}
