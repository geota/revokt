// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(RevoktInternalApi::class)

package dev.revokt.engine.store

import dev.revokt.FilterFormat
import dev.revokt.RevoktInternalApi
import dev.revokt.RevoktLimits
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `current` and `updater.json` (spec §6.5, #109); the generation file is `GenerationFileTest`'s. */
class StoreJsonTest {
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
    fun `the pointer round-trips, with and without previous`() {
        val live = "b".repeat(64)
        val previous = "a".repeat(64)
        for (pointer in listOf(Pointer(live, previous), Pointer(live, null))) {
            assertEquals(pointer, PointerJson.read(PointerJson.write(pointer)))
        }
        assertEquals("""{"live":"$live"}""", text(PointerJson.write(Pointer(live, null))))
        assertEquals(Pointer(live, null), PointerJson.read("""{"live":"$live","previous":null}""".encodeToByteArray()))
    }

    @Test
    fun `a pointer with an unknown or a duplicate member reads as nothing (#246)`() {
        val live = "b".repeat(64)
        val previous = "a".repeat(64)
        for (bad in listOf(
            // A flipped byte in the member name: a lenient reader would read Pointer(live, null).
            """{"live":"$live","p|evious":"$previous"}""",
            """{"live":"$live","|revious":"$previous"}""",
            """{"live":"$live","previous":null,"next":1}""",
            """{"live":"$live","previous":"$previous","live":"$live"}""",
            """{"live":"$live","live":"$live"}""",
        )) {
            assertNull(PointerJson.read(bad.encodeToByteArray()), bad)
        }
    }

    @Test
    fun `a pointer that names anything but generation file names reads as nothing`() {
        val live = "b".repeat(64)
        for (bad in listOf(
            """{"live":"../x"}""",
            """{"live":"blobs"}""",
            """{"live":"$live","previous":"$live"}""",
            """{"live":"$live","previous":"gen-0000000000001-0123456789abcdef"}""",
            """{"live":"${"B".repeat(64)}"}""",
            """{"live":"${"b".repeat(63)}"}""",
            """{"live":"${"b".repeat(65)}"}""",
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
        // An earlier build's per-source fetcher hold is one such member.
        val held =
            edited(
                bytes,
                "\"consecutiveFailures\":3",
                "\"consecutiveFailures\":3,\"feedHostBlock\":{\"chainSha256s\":[],\"sinceMillis\":1}",
            )
        assertEquals(UpdaterRead(record), UpdaterJson.read(held, now))
        // A malformed one too: the member is no longer read, so its shape cannot drop the source.
        val malformed = edited(bytes, "\"consecutiveFailures\":3", "\"consecutiveFailures\":3,\"feedHostBlock\":7")
        assertEquals(UpdaterRead(record), UpdaterJson.read(malformed, now))
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
        val withoutRemoteSettings = record.copy(sources = record.sources - "remote-settings")
        for ((from, to) in listOf(
            "\"consecutiveFailures\":3" to "\"consecutiveFailures\":-1",
            "\"consecutiveFailures\":3" to "\"consecutiveFailures\":2147483648",
            "\"lastVerifiedLastModified\":1762000000123" to "\"lastVerifiedLastModified\":\"x\"",
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
    fun `negative failure counts are refused`() {
        assertFailsWith<IllegalArgumentException> { SourceRecord(consecutiveFailures = -1) }
    }
}
