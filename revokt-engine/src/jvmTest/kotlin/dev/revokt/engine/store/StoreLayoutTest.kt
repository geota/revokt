// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.store

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import dev.revokt.RevoktStorage
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonObject
import okio.ByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * Spec §6.5's content-addressed key layout over a `RevoktStorage` (#109, #287): the keys, the blobs, the generation
 * file's write and Load step 1, the pointer and `updater.json`. Load's later steps and prune are `StoreLoadTest`'s.
 */
class StoreLayoutTest {
    private val storage = StoreFixtures.Recording()
    private val layout = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
    private val fullBytes = byteArrayOf(3, 0, 1, 2, 3)

    @Test
    fun `the keys sit under the lowercase dataset and channel`() {
        assertEquals("crlite/compat", layout.root)
        assertEquals("crlite/default", StoreLayout(storage, Dataset.CRLITE, CrliteChannel.DEFAULT).root)
        val sha = StoreFixtures.sha256(fullBytes)
        assertEquals("crlite/compat/blobs/${sha.hex()}", layout.blobKey(sha))
        assertEquals("crlite/compat/generations/${"a".repeat(64)}", layout.generationKey("a".repeat(64)))
        for (bad in listOf("../x", "A".repeat(64), "a".repeat(63), "gen-0000000000001-711430f6164e9380")) {
            assertFailsWith<IllegalArgumentException>(bad) { layout.generationKey(bad) }
        }
        assertFailsWith<IllegalArgumentException> { layout.blobKey(ByteString.EMPTY) }
        assertFailsWith<IllegalArgumentException> { layout.deleteBlob("../x") }
        assertEquals(listOf("COMPAT", "DEFAULT"), CrliteChannel.entries.map { it.name })
    }

    @Test
    fun `an existing matching blob is reused, not rewritten`() {
        assertEquals(BlobState.ABSENT, layout.blob(StoreFixtures.sha256(fullBytes)))
        assertEquals(BlobWrite.WRITTEN, layout.putBlob(fullBytes))
        assertEquals(BlobState.MATCH, layout.blob(StoreFixtures.sha256(fullBytes)))
        val writes = storage.writes.size
        assertEquals(BlobWrite.REUSED, layout.putBlob(fullBytes.copyOf()))
        assertEquals(writes, storage.writes.size)
    }

    @Test
    fun `a corrupted blob is rewritten and reported`() {
        val sha = StoreFixtures.sha256(fullBytes)
        layout.putBlob(fullBytes)
        storage.write(layout.blobKey(sha), byteArrayOf(3, 0, 1, 2, 4))
        assertEquals(BlobState.MISMATCH, layout.blob(sha))
        val writes = storage.writes.size
        assertEquals(BlobWrite.REWRITTEN, layout.putBlob(fullBytes))
        assertEquals(writes + 1, storage.writes.size)
        assertContentEquals(fullBytes, storage.read(layout.blobKey(sha)))
        assertEquals(BlobState.MATCH, layout.blob(sha))
    }

    @Test
    fun `readBlob returns a blob's bytes only when they re-hash to its key`() {
        val sha = StoreFixtures.sha256(fullBytes)
        assertNull(layout.readBlob(sha))
        layout.putBlob(fullBytes)
        assertContentEquals(fullBytes, layout.readBlob(sha))
        storage.write(layout.blobKey(sha), byteArrayOf(3, 0, 1, 2, 4))
        assertNull(layout.readBlob(sha))
    }

    @Test
    fun `a generation file is stored under the hash of its bytes, and not written again when it re-hashes`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        val name = layout.putGeneration(bytes)
        assertEquals(GenerationFileJson.name(bytes), name)
        assertEquals(listOf(layout.generationKey(name)), storage.writes)
        layout.putGeneration(bytes)
        assertEquals(1, storage.writes.size, "a stored file that re-hashes is not written again")
        storage.write(layout.generationKey(name), "{}".encodeToByteArray())
        layout.putGeneration(bytes)
        assertContentEquals(bytes, storage.read(layout.generationKey(name)), "one that does not is rewritten")
        assertEquals(setOf(name), layout.generationNames())
    }

    @Test
    fun `putGeneration refuses a file over the cap, which the install checks first`() {
        val small = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT, maxJsonBytes = 1)
        assertEquals(1 + GenerationFileJson.ENVELOPE_BYTES, small.generationCap)
        assertEquals(RevoktLimits.MAX_JSON_BYTES + GenerationFileJson.ENVELOPE_BYTES, layout.generationCap)
        assertFailsWith<IllegalArgumentException> { small.putGeneration(ByteArray(small.generationCap.toInt() + 1)) }
        assertEquals(emptyList(), storage.writes)
    }

    @Test
    fun `Load step 1 tells an absent file from one that does not read, re-hash and channel included`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        val name = layout.putGeneration(bytes)
        assertIs<StoreRead.Found<GenerationFile>>(layout.readGeneration(name))
        assertEquals(StoreRead.Absent, layout.readGeneration("0".repeat(64)))
        // The other channel's generation, stored under its own name here: a channel mismatch is no generation.
        val other = GenerationFileJson.write(Generations.sync(channel = CrliteChannel.DEFAULT))
        val otherName = layout.putGeneration(other)
        assertEquals(StoreRead.Malformed, layout.readGeneration(otherName))
        // A flipped byte that still parses: the re-hash refuses it.
        val flipped =
            bytes
                .decodeToString()
                .replace(
                    "\"incremental\":true",
                    "\"incremental\":false",
                ).encodeToByteArray()
        storage.write(layout.generationKey(name), flipped)
        assertEquals(StoreRead.Malformed, layout.readGeneration(name))
        // Over the reading process's cap: a file written under a higher cap is a failed load in a process with a lower one.
        val pad = "x".repeat(70_000)
        val records = listOf(Json.parse("""{"id":"a","pad":"$pad"}""".encodeToByteArray()) as JsonObject)
        val big = layout.putGeneration(GenerationFileJson.write(Generations.sync(records = records)))
        val tiny = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT, maxJsonBytes = 1)
        assertIs<StoreRead.Found<GenerationFile>>(layout.readGeneration(big))
        assertEquals(StoreRead.Malformed, tiny.readGeneration(big))
    }

    @Test
    fun `generationNames and blobNames list only content-addressed names`() {
        layout.putBlob(fullBytes)
        val name = layout.putGeneration(GenerationFileJson.write(Generations.sync()))
        storage.write("crlite/compat/generations/stray", byteArrayOf(1))
        storage.write("crlite/compat/blobs/stray", byteArrayOf(1))
        storage.write("crlite/default/generations/${"b".repeat(64)}", byteArrayOf(1))
        assertEquals(setOf(name), layout.generationNames())
        assertEquals(setOf(StoreFixtures.sha256(fullBytes).hex()), layout.blobNames())
    }

    @Test
    fun `the pointer round-trips through current, and an absent pointer is not a malformed one`() {
        assertEquals(StoreRead.Absent, layout.pointer())
        val older = "a".repeat(64)
        val newer = "b".repeat(64)
        layout.point(Pointer(newer, older))
        assertEquals(StoreRead.Found(Pointer(newer, older)), layout.pointer())
        layout.point(Pointer(newer, null))
        assertEquals(StoreRead.Found(Pointer(newer, null)), layout.pointer())
        for (bad in listOf("{\"live\":\"../x\"}", "", "[]", "{")) {
            storage.write("crlite/compat/current", bad.encodeToByteArray())
            assertEquals(StoreRead.Malformed, layout.pointer(), bad)
        }
        assertFailsWith<IllegalArgumentException> { Pointer("gen-0000000000001-711430f6164e9380", null) }
        assertFailsWith<IllegalArgumentException> { Pointer(newer, newer) }
    }

    @Test
    fun `updater json round-trips through the store, clamped, and an absent file is not a malformed one`() {
        val now = 1_762_430_400_000L
        assertEquals(StoreRead.Absent, layout.updater(now))
        val record =
            UpdaterRecord(
                watermarkMillis = 5,
                sources =
                    mapOf("rs" to SourceRecord(backoffUntilMillis = Long.MAX_VALUE)),
            )
        layout.writeUpdater(record, now)
        assertEquals("crlite/compat/updater.json", storage.writes.last())
        val read = assertIs<StoreRead.Found<UpdaterRead>>(layout.updater(now)).value.record
        assertEquals(5, read.watermarkMillis)
        assertEquals(now + RevoktLimits.MAX_BACKOFF, read.sources.getValue("rs").backoffUntilMillis)
        for (bad in listOf("[]", "", "{\"watermarkMillis\":\"5\"}")) {
            storage.write("crlite/compat/updater.json", bad.encodeToByteArray())
            assertEquals(StoreRead.Malformed, layout.updater(now), bad)
        }
    }

    @Test
    fun `deleteGeneration and deleteBlob remove exactly their key`() {
        layout.putBlob(fullBytes)
        val name = layout.putGeneration(GenerationFileJson.write(Generations.sync()))
        layout.deleteGeneration(name)
        layout.deleteBlob(StoreFixtures.sha256(fullBytes).hex())
        assertEquals(emptySet(), storage.names())
    }

    @Test
    fun `the layout reads and writes through any RevoktStorage`() {
        val plain = StoreLayout(RevoktStorage.inMemory(), Dataset.CRLITE, CrliteChannel.COMPAT)
        val bytes = GenerationFileJson.write(Generations.sync())
        val read = assertIs<StoreRead.Found<GenerationFile>>(plain.readGeneration(plain.putGeneration(bytes)))
        assertContentEquals(bytes, GenerationFileJson.write(read.value))
    }
}
