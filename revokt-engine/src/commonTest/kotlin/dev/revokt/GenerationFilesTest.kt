// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt

import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.c2sp.IndexEntry
import dev.revokt.engine.c2sp.IndexFile
import dev.revokt.engine.c2sp.Window
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** `GenerationFiles` as spec §3.2 declares it (#87): the C2SP image it holds and the checks construction makes. */
@OptIn(RevoktTestingApi::class)
class GenerationFilesTest {
    private val logId = ByteArray(32) { 7 }.toByteString()
    private val full = byteArrayOf(1, 2, 3)
    private val delta = byteArrayOf(4, 5)

    private val index =
        C2spIndex.write(
            C2spIndex.index(
                listOf(
                    "full" to mapOf(logId to Window(1u, 5u)),
                    "delta" to mapOf(logId to Window(5u, 9u)),
                ),
            ),
        )

    /** A builder with every field set and [files] (by default index.bin, full and delta). */
    private fun builder(
        files: Map<String, ByteArray> = mapOf("index.bin" to index, "full" to full, "delta" to delta),
    ): GenerationFiles.Builder =
        GenerationFiles
            .Builder()
            .generationId("g1")
            .trustClass(TrustClass.SIGNED)
            .format(FilterFormat.V3)
            .sourceTimestampMillis(1_793_000_000_000)
            .also { b -> files.forEach { (name, bytes) -> b.file(name, bytes) } }

    @Test
    fun `a generation holds index_bin and the files it names, with their hashes`() {
        val g = builder().build()
        assertEquals(setOf("index.bin", "full", "delta"), g.names)
        assertEquals(Dataset.CRLITE, g.dataset)
        assertContentEquals(full, g.bytes("full"))
        assertContentEquals(full.toByteString().sha256().toByteArray(), g.sha256("full"))
        assertContentEquals(index.toByteString().sha256().toByteArray(), g.sha256("index.bin"))
    }

    @Test
    fun `bytes and hashes are fresh copies, and the builder copies what it is given`() {
        val given = full.copyOf()
        val g = builder().file("full", given).build()
        given[0] = 99
        assertEquals(1, g.bytes("full")[0])
        g.bytes("full")[0] = 99
        g.sha256("full")[0] = 0
        assertEquals(1, g.bytes("full")[0])
        assertContentEquals(full.toByteString().sha256().toByteArray(), g.sha256("full"))
    }

    @Test
    fun `an unknown name is an error, not a null`() {
        val g = builder().build()
        assertFailsWith<IllegalArgumentException> { g.bytes("other") }
        assertFailsWith<IllegalArgumentException> { g.sha256("other") }
    }

    @Test
    fun `a missing, unnamed or malformed file is rejected`() {
        fun message(b: GenerationFiles.Builder): String =
            assertFailsWith<IllegalArgumentException> { b.build() }.message!!
        assertTrue("[delta]" in message(builder(mapOf("index.bin" to index, "full" to full))))
        assertTrue("[stray]" in message(builder().file("stray", byteArrayOf(0))))
        assertTrue("malformed" in message(builder().file("index.bin", byteArrayOf(1, 2))))
        assertTrue("has no index.bin" in message(builder(mapOf("full" to full, "delta" to delta))))
        val selfNamed = C2spIndex.write(C2spIndex.index(listOf("index.bin" to mapOf(logId to Window(1u, 5u)))))
        assertTrue("names itself" in message(builder(mapOf("index.bin" to selfNamed))))
    }

    @Test
    fun `names is read-only`() {
        val g = builder().build()
        assertFailsWith<UnsupportedOperationException> { (g.names as MutableSet<String>).remove("full") }
        assertContentEquals(full, g.bytes("full"))
    }

    @Test
    fun `an index that names a file twice holds it once`() {
        val twice =
            C2spIndex.write(
                IndexFile(
                    listOf("full", "full"),
                    linkedMapOf(logId to listOf(IndexEntry(0, Window(1u, 5u)), IndexEntry(1, Window(1u, 5u)))),
                ),
            )
        assertEquals(setOf("index.bin", "full"), builder(mapOf("index.bin" to twice, "full" to full)).build().names)
    }

    @Test
    fun `every required field must be set`() {
        fun missing(
            field: String,
            b: GenerationFiles.Builder,
        ) {
            val e = assertFailsWith<IllegalArgumentException> { b.build() }
            assertTrue(field in e.message!!, "${e.message}")
        }
        val files = mapOf("index.bin" to index, "full" to full, "delta" to delta)

        fun bare(): GenerationFiles.Builder =
            GenerationFiles.Builder().also { b -> files.forEach { (n, v) -> b.file(n, v) } }
        missing("generationId", bare().trustClass(TrustClass.SIGNED).format(FilterFormat.V3).sourceTimestampMillis(1))
        missing("trustClass", bare().generationId("g").format(FilterFormat.V3).sourceTimestampMillis(1))
        missing("format", bare().generationId("g").trustClass(TrustClass.SIGNED).sourceTimestampMillis(1))
        missing("sourceTimestampMillis", bare().generationId("g").trustClass(TrustClass.SIGNED).format(FilterFormat.V3))
        missing("generationId", builder().generationId(""))
    }

    @Test
    fun `equality is by value, and newBuilder round trips`() {
        val g = builder().build()
        assertEquals(g, builder().build())
        assertEquals(g.hashCode(), builder().build().hashCode())
        assertEquals(g, g.newBuilder().build())
        assertNotEquals(g, g.newBuilder().format(FilterFormat.V4).build())
        assertNotEquals(g, g.newBuilder().file("full", byteArrayOf(9)).build())
        assertTrue("files=[delta:" in g.toString())
        assertNotEquals(
            g.toString(),
            g
                .newBuilder()
                .file("full", byteArrayOf(9))
                .build()
                .toString(),
            "toString shows content",
        )
    }
}
