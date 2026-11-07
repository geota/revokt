// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.Dataset
import dev.revokt.RevoktStorage
import dev.revokt.TrustClass
import okio.ByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Spec §6.5's key layout over `RevoktStorage.inMemory()` (#109). */
class StoreLayoutTest {
    private val storage = StoreFixtures.Recording()
    private val layout = StoreLayout(storage, Dataset.CRLITE, "COMPAT")

    private val fullBytes = byteArrayOf(3, 0, 1, 2, 3)
    private val deltaBytes = byteArrayOf(3, 0, 9)

    /** A 64-character full filter and a 33-character delta, as their attachments name them. */
    private val fullAttachment = "compat-2026-11-06-full-filter-with-a-very-long-name-012345678.ff"
    private val deltaAttachment = "compat-2026-11-06-delta-01234.bin"
    private val fullName = GenerationNames.derive(fullAttachment)
    private val deltaName = GenerationNames.derive(deltaAttachment)

    /** Stores a generation with one full filter and one delta; returns its directory. */
    private fun install(
        trustClass: TrustClass = TrustClass.SIGNED,
        generationId: String = "g1",
        sourceTimestampMillis: Long = 1_762_430_400_000,
        full: ByteArray = fullBytes,
    ): String {
        layout.putBlob(full)
        val meta =
            StoreFixtures.meta(
                trustClass,
                generationId,
                sourceTimestampMillis,
                mapOf(fullName to StoreFixtures.sha256(full)),
            )
        val records = if (trustClass == TrustClass.SIGNED) "{\"data\":[]}".encodeToByteArray() else null
        return layout.writeGeneration(
            meta,
            StoreFixtures.index(fullName, deltaName),
            mapOf(deltaName to deltaBytes),
            records,
        )
    }

    @Test
    fun `the keys sit under the lowercase dataset and channel`() {
        assertEquals("crlite/compat", layout.root)
        assertEquals("crlite/all", StoreLayout(storage, Dataset.CRLITE, "ALL").root)
        val sha = StoreFixtures.sha256(fullBytes)
        assertEquals("crlite/compat/blobs/${sha.hex()}", layout.blobKey(sha))
        assertEquals(
            "crlite/compat/gen-0000000000001-711430f6164e9380/index.bin",
            layout.fileKey(GenerationNames.directory(1, "g1"), "index.bin"),
        )
        assertFailsWith<IllegalArgumentException> { layout.fileKey("../x", "index.bin") }
        assertFailsWith<IllegalArgumentException> { layout.blobKey(ByteString.EMPTY) }
        assertFailsWith<IllegalArgumentException> { StoreLayout(storage, Dataset.CRLITE, "compat") }
        assertFailsWith<IllegalArgumentException> { StoreLayout(storage, Dataset.CRLITE, "") }
        assertFailsWith<IllegalArgumentException> { StoreLayout(storage, Dataset.CRLITE, "1X") }
    }

    @Test
    fun `a channel is an enum constant's name, so its lowercase segment is a key segment`() {
        for (good in listOf(
            "COMPAT",
            "DEFAULT",
            "ALL",
            "A",
            "A_B1",
        )) {
            assertEquals(true, StoreLayout.isChannelName(good), good)
        }
        for (bad in listOf("", "compat", "Compat", "_A", "1A", "A-B", "A.B", "A/B", "A\nB", "AÉ", ".", "..")) {
            assertEquals(false, StoreLayout.isChannelName(bad), bad)
        }
    }

    @Test
    fun `a generation is written with meta json last, under its derived names`() {
        val directory = install()
        assertEquals(GenerationNames.directory(1_762_430_400_000, "g1"), directory)
        val prefix = "crlite/compat/$directory/"
        assertEquals(
            listOf(
                "crlite/compat/blobs/${StoreFixtures.sha256(fullBytes).hex()}",
                prefix + "index.bin",
                prefix + deltaName,
                prefix + "records.json",
                prefix + "meta.json",
            ),
            storage.writes,
        )
    }

    @Test
    fun `33- and 64-character names are the derived names in index bin, the directory, meta json and the files`() {
        val directory = install()
        assertEquals("compat-2026-11--decf10cbc971a35f", fullName)
        assertEquals("compat-2026-11--31041d40a1b14a73", deltaName)
        val stored = assertNotNull(layout.readGeneration(directory))
        assertEquals(setOf("index.bin", fullName, deltaName), stored.files.names)
        assertEquals(setOf(fullName), stored.meta.blobs.keys)
        val index = assertNotNull(storage.read("crlite/compat/$directory/index.bin"))
        assertEquals(
            listOf(fullName, deltaName),
            dev.revokt.engine.c2sp.C2spIndex
                .read(index)
                .filenames,
        )
        val names = storage.names()
        assertNotNull(names.singleOrNull { it.endsWith("/$deltaName") })
        assertNull(names.firstOrNull { it.contains(fullAttachment) || it.contains(deltaAttachment) })
        val meta = assertNotNull(storage.read("crlite/compat/$directory/meta.json")).decodeToString()
        assertEquals(false, meta.contains(fullAttachment))
        assertContentEquals(fullBytes, stored.files.bytes(fullName))
        assertContentEquals(deltaBytes, stored.files.bytes(deltaName))
        assertEquals("g1", stored.files.generationId)
        assertEquals(TrustClass.SIGNED, stored.files.trustClass)
        assertEquals(1_762_430_400_000, stored.files.sourceTimestampMillis)
        assertContentEquals("{\"data\":[]}".encodeToByteArray(), layout.records(directory))
    }

    @Test
    fun `layout unit for data-path (e) (not the fixture) - a MIRROR generation reloads as MIRROR`() {
        val directory = install(TrustClass.MIRROR)
        val stored = assertNotNull(layout.readGeneration(directory))
        assertEquals(TrustClass.MIRROR, stored.meta.trustClass)
        assertEquals(TrustClass.MIRROR, stored.files.trustClass)
        assertNull(layout.records(directory))
    }

    @Test
    fun `layout unit for data-path (e) (not the fixture) - a meta json for the other channel is no generation`() {
        val directory = install()
        val other = StoreLayout(storage, Dataset.CRLITE, "DEFAULT")
        val metaKey = "crlite/compat/$directory/meta.json"
        val moved =
            MetaJson.write(
                StoreFixtures.meta(
                    channel = "DEFAULT",
                    blobs =
                        mapOf(fullName to StoreFixtures.sha256(fullBytes)),
                ),
            )
        storage.write(metaKey, moved)
        assertNull(layout.meta(directory))
        assertNull(layout.readGeneration(directory))
        assertNull(other.readGeneration(directory))
    }

    @Test
    fun `a meta json in the wrong directory, or of another dataset path, is no generation`() {
        val directory = install()
        val metaKey = "crlite/compat/$directory/meta.json"
        storage.write(
            metaKey,
            MetaJson.write(
                StoreFixtures.meta(
                    generationId = "g2",
                    blobs =
                        mapOf(fullName to StoreFixtures.sha256(fullBytes)),
                ),
            ),
        )
        assertNull(layout.readGeneration(directory))
    }

    @Test
    fun `an incomplete or damaged generation is no generation`() {
        val directory = install()
        val prefix = "crlite/compat/$directory/"
        val blobKey = layout.blobKey(StoreFixtures.sha256(fullBytes))
        for ((key, damage) in listOf<Pair<String, ByteArray?>>(
            prefix + "meta.json" to null,
            prefix + "meta.json" to "{".encodeToByteArray(),
            prefix + "index.bin" to null,
            prefix + "index.bin" to byteArrayOf(1, 2, 3),
            prefix + "index.bin" to StoreFixtures.index(deltaName),
            prefix + "index.bin" to StoreFixtures.index(fullName, deltaName, "extra"),
            prefix + deltaName to null,
            prefix + "records.json" to null,
            blobKey to null,
            blobKey to byteArrayOf(3, 0, 1, 2, 4),
        )) {
            val original = storage.read(key)
            if (damage == null) storage.delete(key) else storage.write(key, damage)
            assertNull(layout.readGeneration(directory), key)
            if (original == null) storage.delete(key) else storage.write(key, original)
            assertNotNull(layout.readGeneration(directory), "restored $key")
        }
    }

    @Test
    fun `writeGeneration refuses an inconsistent generation and a complete directory`() {
        val sha = StoreFixtures.sha256(fullBytes)
        layout.putBlob(fullBytes)
        val meta = StoreFixtures.meta(blobs = mapOf(fullName to sha))
        val records = byteArrayOf()
        val index = StoreFixtures.index(fullName, deltaName)
        val deltas = mapOf(deltaName to deltaBytes)
        assertFailsWith<IllegalArgumentException> { layout.writeGeneration(meta, index, deltas, null) }
        assertFailsWith<IllegalArgumentException> {
            layout.writeGeneration(StoreFixtures.meta(TrustClass.MIRROR, blobs = meta.blobs), index, deltas, records)
        }
        assertFailsWith<IllegalArgumentException> { layout.writeGeneration(meta, index, emptyMap(), records) }
        assertFailsWith<IllegalArgumentException> {
            layout.writeGeneration(meta, index, deltas + ("x" to byteArrayOf()), records)
        }
        assertFailsWith<IllegalArgumentException> {
            layout.writeGeneration(
                meta,
                index,
                deltas + (fullName to byteArrayOf()),
                records,
            )
        }
        assertFailsWith<IllegalArgumentException> { layout.writeGeneration(meta, byteArrayOf(0), deltas, records) }
        assertFailsWith<IllegalArgumentException> {
            layout.writeGeneration(meta.copy(channel = "DEFAULT"), index, deltas, records)
        }
        val absent = StoreFixtures.meta(blobs = mapOf(fullName to StoreFixtures.sha256(byteArrayOf(42))))
        assertFailsWith<IllegalArgumentException> { layout.writeGeneration(absent, index, deltas, records) }
        assertEquals(listOf(layout.blobKey(sha)), storage.writes)
        layout.writeGeneration(meta, index, deltas, records)
        assertFailsWith<IllegalStateException> { layout.writeGeneration(meta, index, deltas, records) }
    }

    @Test
    fun `writeGeneration refuses a file named index bin, meta json or records json`() {
        val sha = StoreFixtures.sha256(fullBytes)
        layout.putBlob(fullBytes)
        val meta = StoreFixtures.meta(blobs = mapOf(fullName to sha))
        for (reserved in listOf("index.bin", "meta.json", "records.json")) {
            val index = StoreFixtures.index(fullName, reserved)
            assertFailsWith<IllegalArgumentException>(reserved) {
                layout.writeGeneration(meta, index, mapOf(reserved to deltaBytes), byteArrayOf())
            }
        }
        assertEquals(listOf(layout.blobKey(sha)), storage.writes)
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
    fun `the pointer round-trips through current, and an absent pointer is not a malformed one`() {
        assertEquals(StoreRead.Absent, layout.pointer())
        val older = install(generationId = "g0", sourceTimestampMillis = 1)
        val newer = install(generationId = "g1", sourceTimestampMillis = 2, full = byteArrayOf(3, 0, 5))
        layout.point(Pointer(newer, older))
        assertEquals(StoreRead.Found(Pointer(newer, older)), layout.pointer())
        layout.point(Pointer(newer, null))
        assertEquals(StoreRead.Found(Pointer(newer, null)), layout.pointer())
        for (bad in listOf("{\"live\":\"../x\"}", "", "[]", "{")) {
            storage.write("crlite/compat/current", bad.encodeToByteArray())
            assertEquals(StoreRead.Malformed, layout.pointer(), bad)
        }
    }

    @Test
    fun `previous is only ever a complete generation of the same or a higher trust class`() {
        val signed = install(TrustClass.SIGNED, "s", 1)
        val mirror = install(TrustClass.MIRROR, "m", 2)
        layout.point(Pointer(mirror, signed))
        layout.point(Pointer(signed, null))
        layout.point(Pointer(install(TrustClass.SIGNED, "s2", 3), signed))
        val writes = storage.writes.size
        assertFailsWith<IllegalArgumentException> { layout.point(Pointer(signed, mirror)) }
        val incomplete = GenerationNames.directory(4, "partial")
        storage.write("crlite/compat/$incomplete/index.bin", StoreFixtures.index(deltaName))
        assertFailsWith<IllegalArgumentException> { layout.point(Pointer(signed, incomplete)) }
        assertFailsWith<IllegalArgumentException> { layout.point(Pointer(incomplete, signed)) }
        assertEquals(writes + 1, storage.writes.size)
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
        assertEquals(now + dev.revokt.RevoktLimits.MAX_BACKOFF, read.sources.getValue("rs").backoffUntilMillis)
        for (bad in listOf("[]", "", "{\"watermarkMillis\":\"5\"}")) {
            storage.write("crlite/compat/updater.json", bad.encodeToByteArray())
            assertEquals(StoreRead.Malformed, layout.updater(now), bad)
        }
    }

    @Test
    fun `prune leaves exactly live, previous and their blobs`() {
        val previous = install(TrustClass.SIGNED, "p", 1, byteArrayOf(3, 0, 1))
        val live = install(TrustClass.SIGNED, "l", 2, byteArrayOf(3, 0, 2))
        val old = install(TrustClass.SIGNED, "o", 0, byteArrayOf(3, 0, 3))
        val shared = install(TrustClass.MIRROR, "shared", 3, byteArrayOf(3, 0, 1))
        val partial = GenerationNames.directory(5, "interrupted")
        storage.write("crlite/compat/$partial/index.bin", StoreFixtures.index(deltaName))
        storage.write("crlite/compat/stray/file", byteArrayOf(1))
        storage.write("crlite/compat/blobs/" + "0".repeat(64), byteArrayOf(1))
        storage.write("crlite/default/blobs/" + "1".repeat(64), byteArrayOf(1))
        storage.write("crlite/default/gen-0000000000009-0000000000000000/meta.json", byteArrayOf(1))
        layout.point(Pointer(live, previous))
        layout.writeUpdater(UpdaterRecord(), 0)
        val before = storage.names()
        val deleted = layout.prune()
        val after = storage.names()
        assertEquals(before.size - after.size, deleted)
        val keptBlobs =
            setOf(byteArrayOf(3, 0, 1), byteArrayOf(3, 0, 2))
                .map {
                    layout.blobKey(StoreFixtures.sha256(it))
                }.toSet()
        assertEquals(
            setOf("crlite/compat/current", "crlite/compat/updater.json") +
                keptBlobs +
                before.filter { it.startsWith("crlite/compat/$live/") || it.startsWith("crlite/compat/$previous/") } +
                before.filter { it.startsWith("crlite/default/") },
            after,
        )
        assertNotNull(layout.readGeneration(live))
        assertNotNull(layout.readGeneration(previous))
        assertNull(layout.readGeneration(old))
        assertNull(layout.readGeneration(shared))
        assertEquals(0, layout.prune())
    }

    @Test
    fun `prune with no pointer keeps no directory and no blob`() {
        install()
        storage.write("crlite/compat/updater.json", byteArrayOf())
        layout.prune()
        assertEquals(setOf("crlite/compat/updater.json"), storage.names())
    }

    @Test
    fun `prune with a malformed pointer deletes nothing`() {
        val directory = install()
        install(generationId = "unpointed", full = byteArrayOf(3, 0, 7))
        storage.write("crlite/compat/stray/file", byteArrayOf(1))
        layout.point(Pointer(directory, null))
        for (bad in listOf("{\"live\":\"../x\"}", "", "{")) {
            storage.write("crlite/compat/current", bad.encodeToByteArray())
            val before = storage.names()
            assertEquals(0, layout.prune(), bad)
            assertEquals(before, storage.names(), bad)
        }
    }

    @Test
    fun `prune keeps every blob and the directory when a pointed meta json is present but malformed`() {
        val live = install(TrustClass.SIGNED, "l", 2, byteArrayOf(3, 0, 2))
        val previous = install(TrustClass.SIGNED, "p", 1, byteArrayOf(3, 0, 1))
        val old = install(TrustClass.SIGNED, "o", 0, byteArrayOf(3, 0, 3))
        layout.point(Pointer(live, previous))
        val metaKey = "crlite/compat/$previous/meta.json"
        val good = assertNotNull(storage.read(metaKey))
        val otherDirectory = MetaJson.write(StoreFixtures.meta(generationId = "elsewhere", sourceTimestampMillis = 1))
        for (bad in listOf(
            "{".encodeToByteArray(),
            good.decodeToString().replace("\"metaVersion\":1", "\"metaVersion\":2").encodeToByteArray(),
            good.decodeToString().replace("\"channel\":\"COMPAT\"", "\"channel\":\"DEFAULT\"").encodeToByteArray(),
            otherDirectory,
        )) {
            storage.write(metaKey, bad)
            val blobs = storage.names().filter { it.startsWith("crlite/compat/blobs/") }.toSet()
            val previousKeys = storage.names().filter { it.startsWith("crlite/compat/$previous/") }.toSet()
            layout.prune()
            val after = storage.names()
            assertEquals(blobs, after.filter { it.startsWith("crlite/compat/blobs/") }.toSet(), bad.decodeToString())
            assertEquals(previousKeys, after.filter { it.startsWith("crlite/compat/$previous/") }.toSet())
            assertNotNull(layout.readGeneration(live))
            assertNull(layout.readGeneration(old))
        }
        storage.write(metaKey, good)
        layout.prune()
        assertEquals(BlobState.ABSENT, layout.blob(StoreFixtures.sha256(byteArrayOf(3, 0, 3))))
        assertNotNull(layout.readGeneration(previous))
    }

    @Test
    fun `prune keeps a pointed directory with no meta json, but references no blob for it`() {
        val live = install(TrustClass.SIGNED, "l", 2, byteArrayOf(3, 0, 2))
        val previous = install(TrustClass.SIGNED, "p", 1, byteArrayOf(3, 0, 1))
        layout.point(Pointer(live, previous))
        storage.delete("crlite/compat/$previous/meta.json")
        layout.prune()
        assertEquals(BlobState.ABSENT, layout.blob(StoreFixtures.sha256(byteArrayOf(3, 0, 1))))
        assertNotNull(storage.read("crlite/compat/$previous/index.bin"))
        assertNotNull(layout.readGeneration(live))
    }

    @Test
    fun `deleteGeneration deletes meta json first, so an interrupted delete leaves no complete directory`() {
        val directory = install()
        // A store that lists meta.json last, the worst order for a delete that follows names(), and fails the second
        // delete, as a process death would interrupt it.
        val inner = StoreFixtures.Recording(storage)
        var deletes = 0
        val failing =
            object : RevoktStorage by inner {
                override fun names(): Set<String> =
                    inner.names().sortedBy { it.endsWith("/meta.json") }.toCollection(LinkedHashSet())

                override fun delete(name: String) {
                    check(++deletes < 2) { "interrupted" }
                    inner.delete(name)
                }
            }
        assertFailsWith<IllegalStateException> {
            StoreLayout(
                failing,
                Dataset.CRLITE,
                "COMPAT",
            ).deleteGeneration(directory)
        }
        assertEquals(listOf("crlite/compat/$directory/meta.json"), inner.deletes)
        assertNull(layout.meta(directory))
        assertNull(layout.readGeneration(directory))
        storage.deletes.clear()
        layout.deleteGeneration(directory)
        assertEquals(emptyList(), storage.names().filter { it.contains(directory) })
    }

    @Test
    fun `deleteGeneration removes the directory and keeps the blobs`() {
        val directory = install()
        val other = install(generationId = "g2")
        layout.deleteGeneration(directory)
        assertNull(layout.readGeneration(directory))
        assertNotNull(layout.readGeneration(other))
        assertEquals(BlobState.MATCH, layout.blob(StoreFixtures.sha256(fullBytes)))
        assertEquals(emptyList(), storage.names().filter { it.contains(directory) })
    }

    @Test
    fun `the layout reads and writes through any RevoktStorage`() {
        val plain = StoreLayout(RevoktStorage.inMemory(), Dataset.CRLITE, "DEFAULT")
        plain.putBlob(fullBytes)
        val meta =
            StoreFixtures.meta(
                TrustClass.BUNDLED,
                channel = "DEFAULT",
                blobs =
                    mapOf(fullName to StoreFixtures.sha256(fullBytes)),
            )
        val directory = plain.writeGeneration(meta, StoreFixtures.index(fullName), emptyMap(), null)
        assertEquals(meta, plain.readGeneration(directory)?.meta)
    }
}
