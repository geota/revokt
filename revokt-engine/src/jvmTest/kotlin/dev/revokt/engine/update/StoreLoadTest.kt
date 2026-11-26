// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FilterFormat
import dev.revokt.LogLevel
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonBoolean
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.store.GenerationFileJson
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.deltaRecord
import dev.revokt.engine.update.UpdateFixtures.fullRecord
import dev.revokt.engine.update.UpdateFixtures.log
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec §6.5 Load (one function for the recovery chain, an install's load-back and the adopt scan) and Prune, over a
 * store the install wrote (#287). Prune is fail closed: it deletes nothing beside a pointer, or a pointed generation,
 * that does not read.
 */
internal class StoreLoadTest : InstallFixture() {
    private var pruneFailures = 0

    private fun prune(installed: String): Int = store.pruneAfter(installed, logger) { pruneFailures++ }

    private fun blob(bytes: ByteArray): String = bytes.toByteString().sha256().hex()

    private val v4 = UpdateFixtures.v4(listOf(log(1) to (1_000L to 2_000L)))

    /** A generation of one v4 full filter of its own, so its blob is no other generation's. */
    private fun ownFull(ts: Long): InstallResult.Installed =
        installed(
            install(
                UpdateFixtures.pending(
                    store,
                    listOf(FilterRecord("own", "compat", false, 1, "own.filter")),
                    mapOf("own.filter" to v4),
                    sourceTimestampMillis = ts,
                    format = FilterFormat.V4,
                ),
            ),
        )

    @Test
    fun `a load returns the generation the install wrote, byte for byte, its index rebuilt`() {
        val p = pending()
        val r = installed(install(p))
        val loaded = assertIs<GenerationLoad.Loaded>(store.load(r.name)).value
        assertEquals(p.generationId, loaded.files.generationId)
        assertEquals(TS, loaded.files.sourceTimestampMillis)
        assertEquals(FilterFormat.V3, loaded.format)
        assertContentEquals(p.index, loaded.files.bytes(StoreLayout.INDEX))
        for (placed in p.placed) {
            assertContentEquals(UpdateFixtures.bodies.getValue(placed.record.filename), loaded.files.bytes(placed.name))
        }
        assertContentEquals(p.file.payload, loaded.generation.file.payload)
    }

    @Test
    fun `each failed step is a failed load, an absent file told apart`() {
        val r = installed(install(pending()))
        assertEquals(true, assertIs<GenerationLoad.Failed>(store.load("0".repeat(64))).absent)
        // Step 3: a blob gone, then rotted.
        val delta =
            store.blobKey(
                UpdateFixtures.bodies
                    .getValue(deltaRecord.filename)
                    .toByteString()
                    .sha256(),
            )
        val bytes = storage.inner.read(delta)!!
        storage.inner.delete(delta)
        assertEquals(false, assertIs<GenerationLoad.Failed>(store.load(r.name)).absent)
        storage.inner.write(delta, byteArrayOf(1))
        assertIs<GenerationLoad.Failed>(store.load(r.name))
        storage.inner.write(delta, bytes)
        assertIs<GenerationLoad.Loaded>(store.load(r.name))
        // Step 1: the file damaged.
        val key = store.generationKey(r.name)
        val file = storage.inner.read(key)!!
        storage.inner.write(key, file.copyOf(file.size - 1))
        assertEquals(false, assertIs<GenerationLoad.Failed>(store.load(r.name)).absent)
    }

    @Test
    fun `records that fail the schema, place no full, or exceed the record cap are no generation (step 2)`() {
        val json = UpdateFixtures.recordsJson(listOf(fullRecord, deltaRecord))
        val noFull = UpdateFixtures.file(json.filter { (it["incremental"] as JsonBoolean).value }, TS)
        val noFullName = store.putGeneration(GenerationFileJson.write(noFull))
        assertEquals(StoreRead.Malformed, store.stored(noFullName))
        val bad = UpdateFixtures.file(listOf(Json.parse("{\"id\":\"x\"}".encodeToByteArray()) as JsonObject), TS)
        assertEquals(StoreRead.Malformed, store.stored(store.putGeneration(GenerationFileJson.write(bad))))
        val ok = store.putGeneration(GenerationFileJson.write(UpdateFixtures.file(json, TS)))
        assertIs<StoreRead.Found<*>>(store.stored(ok))
        val capped = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT, maxChangesetRecords = 1)
        assertEquals(StoreRead.Malformed, capped.stored(ok))
    }

    @Test
    fun `prune keeps exactly what the pointer names and their blobs, deleting generation files before blobs`() {
        val g1 = ownFull(TS)
        val g2 = installed(install(pending(TS + 1)))
        val g3 = installed(install(pending(TS + 2)))
        assertEquals(StoreRead.Found(Pointer(g3.name, g2.name)), store.pointer())
        assertEquals(true, g3.prunable)
        storage.inner.write("crlite/compat/blobs/${"c".repeat(64)}", byteArrayOf(1))
        // A key outside blobs/ and generations/, which prune never lists for deletion.
        storage.inner.write("crlite/compat/meta.json", "1".encodeToByteArray())
        storage.deletes.clear()
        assertEquals(3, prune(g3.name))
        assertEquals(0, pruneFailures)
        assertEquals(listOf("generations/${g1.name}"), storage.deletes.take(1), "generation files first")
        assertEquals(setOf("blobs/${blob(v4)}", "blobs/${"c".repeat(64)}"), storage.deletes.drop(1).toSet())
        val keys = storage.names().map { it.removePrefix("crlite/compat/") }.toSet()
        val kept = listOf(fullRecord, deltaRecord).map { "blobs/" + blob(UpdateFixtures.bodies.getValue(it.filename)) }
        val expected =
            setOf("current", "updater.json", "meta.json", "generations/${g2.name}", "generations/${g3.name}")
        assertEquals(expected + kept, keys)
    }

    @Test
    fun `prune deletes nothing beside an absent or malformed pointer, or one that does not read back as the install`() {
        val g1 = ownFull(TS)
        val g2 = installed(install(pending(TS + 1)))
        val before = storage.names()
        storage.inner.delete("crlite/compat/current")
        assertEquals(0, prune(g2.name))
        storage.inner.write("crlite/compat/current", "{".encodeToByteArray())
        assertEquals(0, prune(g2.name))
        store.point(Pointer(g1.name, null))
        assertEquals(0, prune(g2.name))
        assertEquals(3, pruneFailures)
        assertEquals(before - "crlite/compat/current", storage.names() - "crlite/compat/current")
        assertEquals(3, logger.messages.count { it.first == LogLevel.WARN && "not pruned" in it.second })
    }

    @Test
    fun `prune deletes nothing when a generation the pointer names does not read`() {
        val g0 = ownFull(TS - 1)
        val g1 = installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        val before = storage.names()
        val key = store.generationKey(g1.name)
        val bytes = storage.inner.read(key)!!
        for (damage in listOf(
            null,
            bytes.copyOf(10),
            bytes.decodeToString().replace("\"generationVersion\":1", "\"generationVersion\":2").encodeToByteArray(),
        )) {
            if (damage == null) storage.inner.delete(key) else storage.inner.write(key, damage)
            assertEquals(0, prune(g2.name))
        }
        assertEquals(3, pruneFailures)
        assertEquals(before - key, storage.names() - key)
        assertIs<StoreRead.Found<*>>(store.readGeneration(g0.name), "the unnamed g0 survives too")
    }

    @Test
    fun `a pointed generation's rotted blob does not stop prune, and is kept by name`() {
        val g0 = ownFull(TS - 1)
        installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        val delta =
            store.blobKey(
                UpdateFixtures.bodies
                    .getValue(deltaRecord.filename)
                    .toByteString()
                    .sha256(),
            )
        storage.inner.write(delta, byteArrayOf(1))
        assertEquals(2, prune(g2.name), "g0's file and its blob")
        assertEquals(0, pruneFailures)
        assertTrue(delta in storage.names())
        assertEquals(StoreRead.Absent, store.readGeneration(g0.name))
    }

    @Test
    fun `prune keeps a newer generation file that passes steps 1 and 2, and deletes a newer damaged one`() {
        // An interrupted install's newer generation file (written, never flipped), then an older install over it.
        val newer = ownFull(TS + 10)
        store.point(Pointer(installed(install(pending())).name, null))
        val g2 = installed(install(pending(TS + 1)))
        val garbage = "d".repeat(64)
        storage.inner.write(store.generationKey(garbage), "{}".encodeToByteArray())
        prune(g2.name)
        assertEquals(0, pruneFailures)
        assertIs<StoreRead.Found<*>>(store.stored(newer.name))
        assertTrue(store.blobKey(v4.toByteString().sha256()) in storage.names())
        assertEquals(StoreRead.Absent, store.readGeneration(garbage))
    }

    /**
     * Three generation files no pointer names, two older than the live one (prune's to delete) and one newer (kept),
     * with the live one installed over them: the names of the three, and of the live one.
     */
    private fun unnamedBesideLive(): Pair<List<String>, String> {
        val files = listOf(TS, TS + 1, TS + 5).map { store.putGeneration(GenerationFileJson.write(pending(it).file)) }
        val live = installed(install(pending(TS + 3)))
        assertEquals(StoreRead.Found(Pointer(live.name, null)), store.pointer())
        return files to live.name
    }

    @Test
    fun `P1 - a read that throws on any generation file prune reads deletes nothing`() {
        val (files, live) = unnamedBesideLive()
        for (thrower in files) {
            val before = storage.inner.names()
            storage.failRead = { if (it == store.generationKey(thrower)) IllegalStateException("disk") else null }
            assertEquals(0, prune(live), "a throw on $thrower")
            assertEquals(before, storage.inner.names(), "nothing deleted on a throw on $thrower")
        }
        assertEquals(files.size, pruneFailures)
        storage.failRead = { null }
        // Once nothing throws: the two older files go (their blobs are the live one's), the newer one stays.
        assertEquals(2, prune(live))
        assertEquals(setOf(files[2], live), store.generationNames())
    }

    @Test
    fun `P1 - a listing that throws deletes nothing`() {
        val (_, live) = unnamedBesideLive()
        val before = storage.inner.names()
        storage.failNames = { IllegalStateException("disk") }
        assertEquals(0, prune(live))
        assertEquals(1, pruneFailures)
        assertEquals(before, storage.inner.names())
    }

    @Test
    fun `a throw during prune is a store failure and a warning, never the caller's`() {
        installed(install(pending()))
        val g2 = installed(install(pending(TS + 1)))
        storage.failRead = { if (it.endsWith("/current")) IllegalStateException("disk") else null }
        assertEquals(0, prune(g2.name))
        assertEquals(1, pruneFailures)
        assertTrue(logger.messages.any { it.first == LogLevel.WARN && "pruning" in it.second })
    }
}
