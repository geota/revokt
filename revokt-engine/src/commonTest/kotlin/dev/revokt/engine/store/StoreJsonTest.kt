// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.FilterFormat
import dev.revokt.RevoktLimits
import dev.revokt.TrustClass
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `meta.json`, `current` and `updater.json` (spec §6.5, #109). */
class StoreJsonTest {
    private val full = "compat-2026-11-06-full-filter-with-a-very-long-name-012345678.ff"
    private val blobs = mapOf(GenerationNames.derive(full) to StoreFixtures.sha256(byteArrayOf(1)))

    private fun text(bytes: ByteArray): String = bytes.decodeToString()

    /** [bytes] with the member `"key":value` text [from] replaced by [to]. */
    private fun edited(
        bytes: ByteArray,
        from: String,
        to: String,
    ): ByteArray {
        val s = text(bytes)
        assertTrue(from in s, "$from in $s")
        return s.replace(from, to).encodeToByteArray()
    }

    @Test
    fun `a SIGNED meta json round-trips with every member`() {
        val meta = StoreFixtures.meta(blobs = blobs)
        val bytes = MetaJson.write(meta)
        assertEquals(meta, MetaJson.read(bytes))
        assertEquals(
            """{"blobs":{"compat-2026-11--decf10cbc971a35f":"blobs/${blobs.values.single().hex()}"},""" +
                """"changesetTimestampMillis":1762430400001,"channel":"COMPAT",""" +
                """"collection":"security-state/cert-revocations","dataset":"CRLITE","format":"V3",""" +
                """"freshness":"RECORD_LAST_MODIFIED","generationId":"g1","metaVersion":1,""" +
                """"signature":"${"09".repeat(96)}","signerLeafSha256":"${"07".repeat(32)}",""" +
                """"sourceTimestampMillis":1762430400000,"trustClass":"SIGNED"}""",
            text(bytes),
        )
    }

    @Test
    fun `meta json carries the derived name, never the attachment filename`() {
        val bytes = text(MetaJson.write(StoreFixtures.meta(blobs = blobs)))
        assertTrue("compat-2026-11--decf10cbc971a35f" in bytes)
        assertTrue(full !in bytes)
    }

    @Test
    fun `layout unit for data-path (e) (not the fixture) - a MIRROR meta json reloads as MIRROR`() {
        val meta = StoreFixtures.meta(trustClass = TrustClass.MIRROR, blobs = blobs)
        val read = MetaJson.read(MetaJson.write(meta))
        assertEquals(meta, read)
        assertEquals(TrustClass.MIRROR, read?.trustClass)
        assertNull(read?.signed)
        assertNull(read?.collection)
    }

    @Test
    fun `a MIRROR meta json that carries signed members still reloads as MIRROR`() {
        val signed = MetaJson.write(StoreFixtures.meta(blobs = blobs))
        val relabelled = edited(signed, "\"trustClass\":\"SIGNED\"", "\"trustClass\":\"MIRROR\"")
        val read = MetaJson.read(relabelled)
        assertEquals(TrustClass.MIRROR, read?.trustClass)
        assertNull(read?.signed)
    }

    @Test
    fun `unknown meta json members are ignored`() {
        val meta = StoreFixtures.meta(blobs = blobs)
        val bytes = edited(MetaJson.write(meta), "{\"blobs\"", "{\"aFutureMember\":[1,{\"x\":null}],\"blobs\"")
        assertEquals(meta, MetaJson.read(bytes))
    }

    @Test
    fun `a malformed meta json reads as nothing`() {
        val bytes = MetaJson.write(StoreFixtures.meta(blobs = blobs))
        val sha = blobs.values.single().hex()
        for ((from, to) in listOf(
            "\"metaVersion\":1" to "\"metaVersion\":2",
            "\"metaVersion\":1" to "\"metaVersion\":\"1\"",
            "\"trustClass\":\"SIGNED\"" to "\"trustClass\":\"signed\"",
            "\"trustClass\":\"SIGNED\"" to "\"trustClass\":\"FUTURE\"",
            "\"dataset\":\"CRLITE\"" to "\"dataset\":0",
            "\"format\":\"V3\"" to "\"format\":\"V9\"",
            "\"freshness\":\"RECORD_LAST_MODIFIED\"" to "\"freshness\":null",
            "\"channel\":\"COMPAT\"" to "\"channel\":\"compat\"",
            "\"channel\":\"COMPAT\"" to "\"channel\":\"../x\"",
            "\"generationId\":\"g1\"" to "\"generationId\":\"\"",
            "\"sourceTimestampMillis\":1762430400000" to "\"sourceTimestampMillis\":-1",
            "\"sourceTimestampMillis\":1762430400000" to "\"sourceTimestampMillis\":1.5",
            "\"sourceTimestampMillis\":1762430400000" to "\"sourceTimestampMillis\":18446744073709551615",
            "\"collection\":\"security-state/cert-revocations\"" to "\"collection\":7",
            "\"blobs/$sha\"" to "\"blobs/${sha.uppercase()}\"",
            "\"blobs/$sha\"" to "\"blobs/${sha.dropLast(1)}\"",
            "\"blobs/$sha\"" to "\"$sha\"",
            "\"blobs/$sha\"" to "\"blobs/../$sha\"",
            "\"blobs/$sha\"" to "7",
            "\"compat-2026-11--decf10cbc971a35f\"" to "\"$full\"",
            "\"compat-2026-11--decf10cbc971a35f\"" to "\"../x\"",
            "\"blobs\":{" to "\"blobs\":[],\"x\":{",
            "\"signerLeafSha256\":\"${"07".repeat(32)}\"" to "\"signerLeafSha256\":\"${"07".repeat(31)}\"",
            "\"signature\":\"${"09".repeat(96)}\"" to "\"signature\":\"${"09".repeat(95)}0\"",
            "\"signature\":\"${"09".repeat(96)}\"" to "\"signature\":\"${"09".repeat(95)}\"",
            "\"signature\":\"${"09".repeat(96)}\"" to "\"signature\":\"${"09".repeat(97)}\"",
            "\"signature\":\"${"09".repeat(96)}\"" to "\"signature\":\"${"0A".repeat(96)}\"",
            "\"signature\":\"${"09".repeat(96)}\"" to "\"signature\":\"\"",
            "\"changesetTimestampMillis\":1762430400001," to "",
        )) {
            assertNull(MetaJson.read(edited(bytes, from, to)), "$from -> $to")
        }
        for (bad in listOf(
            "",
            "[]",
            "{}",
            "null",
            "{\"metaVersion\":1}",
            "{",
            "\u0000",
        )) {
            assertNull(MetaJson.read(bad.encodeToByteArray()), bad)
        }
    }

    @Test
    fun `a meta value that breaks the layout's rules is refused`() {
        assertFailsWith<IllegalArgumentException> { StoreFixtures.meta(blobs = mapOf(full to blobs.values.single())) }
        assertFailsWith<IllegalArgumentException> {
            StoreFixtures.meta(
                blobs =
                    mapOf("a" to byteArrayOf(1).toByteString()),
            )
        }
        assertFailsWith<IllegalArgumentException> { StoreFixtures.meta(sourceTimestampMillis = -1) }
        assertFailsWith<IllegalArgumentException> {
            StoreFixtures.meta(TrustClass.MIRROR).copy(signed = StoreFixtures.meta().signed)
        }
        assertFailsWith<IllegalArgumentException> { StoreFixtures.meta().copy(signed = null) }
        for (size in listOf(0, 1, 95, 97)) {
            assertFailsWith<IllegalArgumentException>("$size") {
                SignedMeta(1, ByteArray(32).toByteString(), ByteArray(size).toByteString())
            }
        }
        assertFailsWith<IllegalArgumentException> {
            SignedMeta(
                1,
                ByteArray(31).toByteString(),
                ByteArray(1).toByteString(),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            SignedMeta(
                1,
                ByteArray(32).toByteString(),
                ByteArray(0).toByteString(),
            )
        }
        assertEquals(FilterFormat.V3, StoreFixtures.meta().format)
    }

    @Test
    fun `the pointer round-trips, with and without previous`() {
        val live = GenerationNames.directory(2, "b")
        val previous = GenerationNames.directory(1, "a")
        for (pointer in listOf(Pointer(live, previous), Pointer(live, null))) {
            assertEquals(pointer, PointerJson.read(PointerJson.write(pointer)))
        }
        assertEquals("""{"live":"$live"}""", text(PointerJson.write(Pointer(live, null))))
        assertEquals(
            Pointer(live, null),
            PointerJson.read("""{"live":"$live","previous":null,"next":1}""".encodeToByteArray()),
        )
    }

    @Test
    fun `a pointer that names anything but generation directories reads as nothing`() {
        val live = GenerationNames.directory(2, "b")
        for (bad in listOf(
            """{"live":"../x"}""",
            """{"live":"blobs"}""",
            """{"live":"$live","previous":"$live"}""",
            """{"live":"$live","previous":"gen-x"}""",
            """{"live":"$live","previous":3}""",
            """{"previous":"$live"}""",
            """{"live":null}""",
            """["$live"]""",
        )) {
            assertNull(PointerJson.read(bad.encodeToByteArray()), bad)
        }
    }

    private val now = 1_762_430_400_000L

    private val record =
        UpdaterRecord(
            watermarkMillis = 1_762_000_000_000,
            seedInstalledAtMillis = 1_761_000_000_000,
            datasetLastAttemptAtMillis = now - 5,
            sources =
                mapOf(
                    "remote-settings" to
                        SourceRecord(
                            lastVerifiedLastModified = 1_762_000_000_123,
                            lastVerifiedAtMillis = now - 10,
                            lastAttemptAtMillis = now - 5,
                            backoffUntilMillis = now + 1_000,
                            consecutiveFailures = 3,
                            feedHostBlock =
                                FeedHostBlock(
                                    now - 100,
                                    setOf(ByteArray(32) { 2 }.toByteString(), ByteArray(32) { 1 }.toByteString()),
                                ),
                        ),
                    "mirror" to SourceRecord(),
                ),
        )

    @Test
    fun `updater json round-trips`() {
        assertEquals(UpdaterRead(record), UpdaterJson.read(UpdaterJson.write(record, now), now))
        assertEquals(UpdaterRead(UpdaterRecord()), UpdaterJson.read(UpdaterJson.write(UpdaterRecord(), now), now))
        assertEquals("""{"sources":{}}""", text(UpdaterJson.write(UpdaterRecord(), now)))
    }

    @Test
    fun `unknown updater json members are ignored`() {
        val bytes =
            edited(UpdaterJson.write(record, now), "\"consecutiveFailures\":3", "\"consecutiveFailures\":3,\"zNew\":{}")
        val wider = edited(bytes, "{\"datasetLastAttemptAtMillis\"", "{\"aNew\":true,\"datasetLastAttemptAtMillis\"")
        assertEquals(UpdaterRead(record), UpdaterJson.read(wider, now))
    }

    @Test
    fun `a malformed file or dataset-level member makes updater json malformed`() {
        val bytes = UpdaterJson.write(record, now)
        for ((from, to) in listOf(
            "\"watermarkMillis\":1762000000000" to "\"watermarkMillis\":\"1762000000000\"",
            "\"watermarkMillis\":1762000000000" to "\"watermarkMillis\":1.5",
            "\"seedInstalledAtMillis\":1761000000000" to "\"seedInstalledAtMillis\":[]",
            "\"datasetLastAttemptAtMillis\":${now - 5}" to "\"datasetLastAttemptAtMillis\":18446744073709551615",
        )) {
            assertNull(UpdaterJson.read(edited(bytes, from, to), now), "$from -> $to")
        }
        for (bad in listOf(
            "[]",
            "x",
            "",
            "null",
            "{\"sources\":{}",
        )) {
            assertNull(UpdaterJson.read(bad.encodeToByteArray(), now), bad)
        }
    }

    @Test
    fun `a bad source entry is dropped alone and the watermark survives`() {
        val bytes = UpdaterJson.write(record, now)
        val hash = "01".repeat(32)
        val withoutRemoteSettings = record.copy(sources = record.sources - "remote-settings")
        for ((from, to) in listOf(
            "\"consecutiveFailures\":3" to "\"consecutiveFailures\":-1",
            "\"consecutiveFailures\":3" to "\"consecutiveFailures\":2147483648",
            "\"lastVerifiedLastModified\":1762000000123" to "\"lastVerifiedLastModified\":\"x\"",
            "\"$hash\"" to "\"${hash.dropLast(1)}A\"",
            "\"$hash\"" to "\"${hash.drop(2)}\"",
            "\"$hash\"" to "1",
            "\"chainSha256s\":[" to "\"chainSha256s\":7,\"was\":[",
            ",\"sinceMillis\":${now - 100}" to "",
        )) {
            val read = assertNotNull(UpdaterJson.read(edited(bytes, from, to), now), "$from -> $to")
            assertEquals(withoutRemoteSettings, read.record, "$from -> $to")
            assertEquals(setOf("remote-settings"), read.droppedSources, "$from -> $to")
            assertEquals(1_762_000_000_000, read.record.watermarkMillis)
        }
        val mirrorBad = UpdaterJson.read(edited(bytes, "\"mirror\":{\"consecutiveFailures\":0}", "\"mirror\":[]"), now)
        assertEquals(UpdaterRead(record.copy(sources = record.sources - "mirror"), setOf("mirror")), mirrorBad)
        val bothBad =
            edited(
                edited(bytes, "\"mirror\":{\"consecutiveFailures\":0}", "\"mirror\":7"),
                "\"consecutiveFailures\":3",
                "\"consecutiveFailures\":-1",
            )
        assertEquals(
            UpdaterRead(record.copy(sources = emptyMap()), setOf("mirror", "remote-settings")),
            UpdaterJson.read(bothBad, now),
        )
        assertEquals(UpdaterRead(UpdaterRecord()), UpdaterJson.read("{}".encodeToByteArray(), now))
        // A sources member that is not an object reads as no sources and is reported (#131); null is absent.
        for (sources in listOf("[]", "7", "null", "\"x\"")) {
            val read = UpdaterJson.read("{\"watermarkMillis\":5,\"sources\":$sources}".encodeToByteArray(), now)
            val malformed = sources != "null"
            assertEquals(UpdaterRead(UpdaterRecord(watermarkMillis = 5), sourcesMalformed = malformed), read, sources)
            assertEquals(if (malformed) 1 else 0, read?.storeFailures, sources)
        }
        assertEquals(2, UpdaterJson.read(bothBad, now)?.storeFailures)
        assertEquals(0, UpdaterJson.read("{}".encodeToByteArray(), now)?.storeFailures)
    }

    @Test
    fun `a backoff far in the future is clamped on write and again on read`() {
        val far = record.copy(sources = mapOf("rs" to SourceRecord(backoffUntilMillis = now + 365L * 24 * 3_600_000)))
        val written = UpdaterJson.write(far, now)
        assertEquals(
            now + RevoktLimits.MAX_BACKOFF,
            UpdaterJson
                .read(written, now)
                ?.record
                ?.sources
                ?.get("rs")
                ?.backoffUntilMillis,
        )
        // A file written by a clock that was far ahead, read now: clamped on read.
        val ahead = UpdaterJson.write(far, now + 300L * 24 * 3_600_000)
        assertEquals(
            now + RevoktLimits.MAX_BACKOFF,
            UpdaterJson
                .read(ahead, now)
                ?.record
                ?.sources
                ?.get("rs")
                ?.backoffUntilMillis,
        )
        // Within the cap nothing changes, and the cap saturates instead of overflowing.
        val near = SourceRecord(backoffUntilMillis = now + RevoktLimits.MAX_BACKOFF)
        assertEquals(
            near,
            UpdaterJson
                .read(
                    UpdaterJson.write(UpdaterRecord(sources = mapOf("rs" to near)), now),
                    now,
                )?.record
                ?.sources
                ?.get("rs"),
        )
        val max = SourceRecord(backoffUntilMillis = Long.MAX_VALUE)
        assertEquals(
            max,
            UpdaterJson
                .read(
                    UpdaterJson.write(
                        UpdaterRecord(sources = mapOf("rs" to max)),
                        Long.MAX_VALUE - 1,
                    ),
                    Long.MAX_VALUE - 1,
                )?.record
                ?.sources
                ?.get("rs"),
        )
    }

    @Test
    fun `negative failure counts and short chain hashes are refused`() {
        assertFailsWith<IllegalArgumentException> { SourceRecord(consecutiveFailures = -1) }
        assertFailsWith<IllegalArgumentException> { FeedHostBlock(1, setOf(ByteArray(31).toByteString())) }
    }
}
