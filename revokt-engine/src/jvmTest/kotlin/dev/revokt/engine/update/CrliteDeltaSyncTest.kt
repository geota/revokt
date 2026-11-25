// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.Dataset
import dev.revokt.RevoktLimits
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.WarningCode
import dev.revokt.engine.fetch.json
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.update.UpdateFixtures.log
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.engine.verify.ContentSignatureFailure
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * #141's acceptance test: deltas from the cursor, the `_since` merge, reset-and-retry once (on Firefox's
 * `InvalidSignatureError` family and an unmergeable change list, never on an x5u failure) and the half-cap warnings (spec §7.1, §7.2, §6.5, §4 sync diagnostics, §9 "incremental fixtures" and "signature over records
 * with a tombstone merged vs not merged"), and #201's re-hash of a stored delta before it is reused. The scripted
 * Remote Settings of [CrliteSyncFixture] answers `_since` with the records modified after the cursor and its tombstones.
 */
internal class CrliteDeltaSyncTest : CrliteDeltaFixture() {
    @Test
    fun `incremental fixture - a delta changeset with a tombstone installs from the cursor, its records signed`() {
        val server = installedFirst()
        next(server, listOf(full, delta2), listOf(tombstone))
        val now = ts2 + hour
        val run = sync(server, now = now).assert(SyncOutcome.INSTALLED)
        val id = "$ts2/${delta2.id}"
        assertEquals(
            id,
            run.result.installed.values
                .single(),
        )
        // The changes after the cursor only, the x5u, and the one new body: the full's blob is reused.
        assertEquals(
            listOf(monitor, server.sinceUrl(ts), x5u, "$base/", attachments + delta2.location),
            server.fetcher.requests.map { it.url },
        )
        val stored = stored(liveName())
        assertEquals(id, stored.generationId)
        val payload = checkNotNull(ContentSignature.recordsJson(server.records.map(::json), ts2))
        assertContentEquals(payload, stored.file.payload)
        assertEquals(listOf(full.id, delta2.id), stored.placed.map { it.record.id }, "the tombstoned delta is gone")
        assertEquals(ts2, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(ts2, updater(now).watermarkMillis)
        // The previous generation is kept, as the pointer's previous, with its blobs.
        assertEquals(StoreRead.Found(Pointer(stored.name, assertNotNull(name1))), store.pointer())
        loaded(name1)
    }

    @Test
    fun `a _since changeset verifies over the merge, which installs, and fails over its changes alone`() {
        val server = installedFirst()
        next(server, listOf(full, delta2), listOf(tombstone))
        // The signature over the delta's changes alone (no merge) does not verify.
        val changes = server.changes(ts).map(::json)
        val alone =
            ContentSignature.verifyRecords(
                verifier,
                changes,
                ts2,
                server.sign(),
                ContentSignature.MODE,
                leafKey.public.encoded,
            )
        assertEquals(ContentSignatureFailure.INVALID, alone.failure)
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertFalse(server.fetcher.requests.any { it.url == server.changesetUrl }, "no full re-fetch")
    }

    @Test
    fun `signature over records with a tombstone merged vs not - the unmerged set fails and resets once`() {
        val server = installedFirst()
        next(server, listOf(full, delta2), listOf(tombstone))
        // The same signed collection, served from the cursor without its tombstone: the merge keeps the deleted
        // delta, so the signature fails, and the whole collection is fetched once and installs.
        server.since = { listOf(delta2.json()) }
        val now = ts2 + hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(
            listOf(monitor, server.sinceUrl(ts), x5u, server.changesetUrl, "$base/", attachments + delta2.location),
            server.fetcher.requests.map { it.url },
        )
        assertEquals("$ts2/${delta2.id}", live().generationId)
        val warned = recording.messages.single { "did not verify" in it.second }
        assertTrue("since $ts" in warned.second, warned.second)
    }

    @Test
    fun `a _since changeset that never verifies is fetched in full exactly once, then FAILED`() {
        val server = installedFirst()
        next(server, listOf(full, delta, delta2))
        server.signature = Server(records = listOf(full.json())).sign()
        val now = ts2 + hour
        sync(server, now = now).assert(SyncFailure.SIGNATURE_INVALID)
        // One x5u fetch for both: the sync's verifier validated it once (§7.1, one result per URL per sync).
        assertEquals(
            listOf(monitor, server.sinceUrl(ts), x5u, server.changesetUrl),
            server.fetcher.requests.map { it.url },
        )
        assertEquals(name1, liveName())
        assertEquals(ts, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(1, sourceRecord(now).consecutiveFailures)
    }

    @Test
    fun `a _since fetch that fails before verification is FAILED without a full re-fetch`() {
        val server = installedFirst()
        next(server, listOf(full, delta, delta2))
        server.overrides[server.sinceUrl(ts)] = { response(500) }
        sync(server, now = ts2 + hour).assert(SyncFailure.CHANGESET_FETCH).also {
            assertEquals(500, it.result.httpStatus)
        }
        assertEquals(listOf(monitor, server.sinceUrl(ts)), server.fetcher.requests.map { it.url })
    }

    @Test
    fun `data-path - after three failures a 304 resets consecutiveFailures to 0`() {
        val server = installedFirst()
        server.overrides[server.sinceUrl(ts)] = { response(500) }
        // Each a poll interval apart, past the failure backoff the previous one left.
        val at = (1..4).map { ts + it * 7 * hour }
        for (now in at.take(3)) sync(server, now = now).assert(SyncFailure.CHANGESET_FETCH)
        assertEquals(3, sourceRecord(at[2]).consecutiveFailures)
        server.overrides.remove(server.sinceUrl(ts))
        sync(server, now = at[3]).assert(SyncOutcome.UNCHANGED)
        assertEquals(0, sourceRecord(at[3]).consecutiveFailures)
        assertNull(sourceRecord(at[3]).backoffUntilMillis)
    }

    @Test
    fun `a delta whose blob is stored and re-hashes is reused, not fetched, and one that does not is fetched again`() {
        val server = installedFirst()
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + delta2.location), server.attachmentRequests())
        // A third generation with the delta's blob rotted: fetched again, as Firefox's isFilterOnDisk re-hashes its
        // files (#201, every blob), and rewritten, a store failure.
        val key = store.blobKey(delta.body.toByteString().sha256())
        storage.inner.write(key, byteArrayOf(1, 2, 3))
        server.ts = ts2 + 1_000
        server.fetcher.requests.clear()
        val run = sync(server, now = server.ts + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + delta.location), server.attachmentRequests())
        assertEquals(1, run.storeFailures)
        assertContentEquals(delta.body, storage.inner.read(key))
    }

    @Test
    fun `each body is written as its blob as it arrives, before the next is fetched`() {
        val server = installedFirst()
        storage.inner.write(store.blobKey(delta.body.toByteString().sha256()), byteArrayOf(9))
        next(server, listOf(full, delta, delta2))
        var writtenFirst = false
        server.overrides[attachments + delta2.location] = {
            writtenFirst = store.readBlob(delta.body.toByteString().sha256()) != null
            response(200, delta2.body)
        }
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + delta.location, attachments + delta2.location), server.attachmentRequests())
        assertTrue(writtenFirst, "the first delta was written before the second was fetched")
    }

    @Test
    fun `a sync that fails after writing some bodies deletes nothing, and the retry fetches only the rest`() {
        val server = installedFirst()
        next(server, listOf(full2, delta2))
        server.overrides[attachments + delta2.location] = { response(404) }
        val before = storage.names()
        sync(server, now = ts2 + hour).assert(SyncFailure.ATTACHMENT_FETCH)
        assertEquals(before + store.blobKey(full2.body.toByteString().sha256()), storage.names())
        assertEquals(name1, liveName())
        server.overrides.clear()
        server.fetcher.requests.clear()
        sync(server, now = ts2 + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + delta2.location), server.attachmentRequests())
    }

    @Test
    fun `#201 - a retried flip whose stored delta rotted in between fetches it again and installs`() {
        val server = Server()
        storage.failWrite = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        sync(server).assert(SyncFailure.STORE_FAILED)
        storage.failWrite = { null }
        val key = store.blobKey(delta.body.toByteString().sha256())
        storage.inner.write(key, delta.body.copyOf().also { it[it.size - 1] = (it.last() + 1).toByte() })
        server.fetcher.requests.clear()
        val run = sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertEquals(listOf(attachments + delta.location), server.attachmentRequests())
        assertEquals(live().generationFile, liveName())
    }

    @Test
    fun `a re-parented full downloads at once while the live data is fresh, as there is no metered deferral`() {
        val server = installedFirst()
        next(
            server,
            listOf(full2),
            listOf(tombstone, """{"id":"${full.id}","last_modified":${ts + 650},"deleted":true}"""),
        )
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + full2.location), server.attachmentRequests())
        assertEquals("$ts2/${full2.id}", live().generationId)
    }

    @Test
    fun `a bit-rotted full on the delta path is fetched again and installs`() {
        val server = installedFirst()
        storage.inner.write(store.blobKey(full.body.toByteString().sha256()), byteArrayOf(1))
        next(server, listOf(full, delta, delta2))
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + full.location, attachments + delta2.location), server.attachmentRequests())
    }

    @Test
    fun `#205 - an orphan file and a rotted blob never loop, the next sync refetching only the rot`() {
        // The first sync writes its generation file, then prepare throws: an unnamed generation file is left.
        val records = listOf(full, delta, delta2)
        val bodies = records.associate { it.location to it.body }
        val server = Server(records = records.map { it.json() }, bodies = bodies)
        val throwing = UpdateFixtures.TestEngine().apply { onPrepare = { throw IllegalArgumentException("corrupt") } }
        sync(server, engine = throwing).assert(SyncFailure.ENGINE_FAILED)
        val orphan = store.generationNames().single()
        assertNull(liveName())
        val key = store.blobKey(delta.body.toByteString().sha256())
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).also { it[0] = (it[0] + 1).toByte() })
        // The same collection, served by another signer: another generation file under another name.
        val p256 = ecPair("x5u-leaf-p256", "secp256r1")
        val chain2 = chain(leaf = leaf(spki = p256.public.encoded))
        val resigned = Server(records = server.records, bodies = bodies, pem = pem(chain2), key = p256.private)
        val run = sync(resigned, now = ts + 8 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures, "the rotted blob, rewritten")
        // Only the rotted delta is fetched: the full's blob and the intact delta re-hash and are reused.
        assertEquals(listOf(attachments + delta.location), resigned.attachmentRequests())
        val live = stored(liveName())
        assertEquals(chain2[0].toByteString().sha256(), live.file.signerLeafSha256)
        assertTrue(live.name != orphan)
        // No prune after an install over an absent pointer: the orphan stays for the next prune.
        assertIs<StoreRead.Found<*>>(store.readGeneration(orphan))
    }

    @Test
    fun `a cursor older than the live generation fetches the whole collection, and installs`() {
        val server = installedFirst()
        // The second generation flips, then its updater json write fails: the pointer names it, the cursor stays ts.
        next(server, listOf(full, delta, delta2))
        storage.failWrite = { if (it.endsWith("updater.json")) IllegalStateException("updater") else null }
        sync(server, now = ts2 + hour).assert(SyncFailure.STORE_FAILED)
        storage.failWrite = { null }
        assertEquals("$ts2/${delta2.id}", stored(liveName()).generationId)
        assertEquals(ts, sourceRecord(ts2 + hour).lastVerifiedLastModified)
        // A third. The cursor is not the live generation's <ts>, so it is not sent (#147, §7.1): the whole collection.
        val delta3 =
            Rec(
                "f1e2d3c4-0000-4000-8000-000000000004",
                true,
                ts + 800,
                "20261023-1-compat.filter.delta",
                UpdateFixtures.v4(listOf(log(4) to (1_000L to 2_000L))),
                parent = full.id,
            )
        server.ts = ts2 + 1_000
        server.records = listOf(full, delta, delta2, delta3).map { it.json() }
        server.bodies = server.bodies + (delta3.location to delta3.body)
        server.fetcher.requests.clear()
        val now = server.ts + 8 * hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(server.changesetUrl, server.fetcher.requests[1].url)
        assertFalse(server.fetcher.requests.any { "_since" in it.url }, "no cursor sent")
        assertFalse(server.fetcher.requests.any { "If-None-Match" in it.headers }, "no cursor sent")
        // The stored full and the deltas the live generation holds are reused: only the new delta is fetched.
        assertEquals(listOf(attachments + delta3.location), server.attachmentRequests())
        assertEquals(server.ts, sourceRecord(now).lastVerifiedLastModified)
    }

    @Test
    fun `a _since change with no id does not merge, and the whole collection is fetched without verifying it`() {
        val server = installedFirst()
        next(server, listOf(full, delta, delta2))
        server.since = { listOf(delta2.json(), """{"last_modified":${ts + 900},"deleted":true}""") }
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        // An unmergeable change list is a trigger of its own: no x5u is fetched for it.
        assertEquals(
            listOf(monitor, server.sinceUrl(ts), server.changesetUrl, x5u, "$base/", attachments + delta2.location),
            server.fetcher.requests.map { it.url },
        )
        assertTrue(recording.messages.any { "do not merge with the stored records" in it.second })
    }

    @Test
    fun `a _since changeset with no signatures resets once, as Firefox's MissingSignatureError does`() =
        resetsOnce("absent, not an array or empty", "[]")

    @Test
    fun `a _since changeset whose every entry is skipped resets once`() =
        resetsOnce("no entry has", """[{"x5u":"$x5u","signature":"","mode":"p384ecdsa"}]""")

    @Test
    fun `a _since changeset with a null signature entry resets once`() = resetsOnce("is null", "[null]")

    @Test
    fun `a _since changeset whose x5u fetch fails is X5U_FETCH without a reset`() =
        neverResets(SyncFailure.X5U_FETCH) { it.overrides[x5u] = { response(500) } }

    @Test
    fun `a _since changeset whose x5u is not PEM is X5U_CHAIN without a reset`() =
        neverResets(SyncFailure.X5U_CHAIN, "FRAMING") { it.pem = "not a PEM chain" }

    @Test
    fun `a _since changeset whose x5u chain fails is X5U_CHAIN without a reset`() =
        neverResets(SyncFailure.X5U_CHAIN) { it.pem = pem(served.take(2)) }

    @Test
    fun `a _since changeset whose x5u is outside its validity is CLOCK_SKEW without a reset`() =
        neverResets(SyncFailure.CLOCK_SKEW, now = millis("2051-01-01T00:00:00Z")) {}

    /**
     * A `_since` changeset signed with [signatures] as its `metadata.signatures` fails with a failure whose detail
     * holds [failure], and the sync fetches the whole collection once, which verifies and installs.
     */
    private fun resetsOnce(
        failure: String,
        signatures: String,
    ) {
        val server = installedFirst()
        next(server, listOf(full, delta, delta2))
        server.overrides[server.sinceUrl(ts)] = {
            ok(
                """{"changes":[${server.changes(ts).joinToString(",")}],"timestamp":$ts2,""" +
                    """"metadata":{"signatures":$signatures}}""",
            )
        }
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED)
        assertEquals(
            listOf(monitor, server.sinceUrl(ts), server.changesetUrl, x5u, "$base/", attachments + delta2.location),
            server.fetcher.requests.map { it.url },
        )
        assertTrue(recording.messages.any { failure in it.second && "did not verify" in it.second })
        assertEquals("$ts2/${delta2.id}", live().generationId)
    }

    /**
     * A `_since` changeset whose x5u fails after [arm] ends the sync with [failure], logged with [detail] when given:
     * the whole collection is never fetched (the sync's verifier would reuse the failed x5u, §7.1), and nothing
     * advances.
     */
    private fun neverResets(
        failure: SyncFailure,
        detail: String? = null,
        now: Long = ts2 + hour,
        arm: (Server) -> Unit,
    ) {
        val server = installedFirst()
        next(server, listOf(full, delta, delta2))
        arm(server)
        val run = sync(server, now = now)
        assertEquals(SyncOutcome.FAILED to failure, run.result.outcome to run.result.failure, "${run.result}")
        if (detail !=
            null
        ) {
            assertTrue(recording.messages.any { "$failure: $detail" in it.second }, "${recording.messages}")
        }
        assertEquals(listOf(monitor, server.sinceUrl(ts), x5u), server.fetcher.requests.map { it.url })
        assertFalse(recording.messages.any { "fetching the whole collection" in it.second })
        assertEquals(ts, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(1, sourceRecord(now).consecutiveFailures)
        assertEquals(name1, liveName())
    }

    @Test
    fun `a monitor changes body above half of MAX_JSON_BYTES warns, and the sync installs`() {
        val server = Server()
        val padding = "x".repeat((RevoktLimits.MAX_JSON_BYTES / 2).toInt())
        server.overrides[monitor] = {
            ok(
                """{"changes":[{"id":"x","bucket":"security-state","collection":"cert-revocations",""" +
                    """"last_modified":$ts}],"timestamp":$ts,"padding":"$padding"}""",
            )
        }
        val run = sync(server).assert(SyncOutcome.INSTALLED, WarningCode.CAP_NEAR_LIMIT)
        assertTrue(
            "monitor/changes is" in
                run.result.warnings
                    .single()
                    .message,
        )
    }

    @Test
    fun `a changeset above half of MAX_JSON_BYTES warns once, even when a reset fetches it twice`() {
        val server = installedFirst()
        next(server, listOf(full, delta2), listOf(tombstone))
        server.since = { listOf(delta2.json()) }
        server.padding = (RevoktLimits.MAX_JSON_BYTES / 2).toInt()
        val run = sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED, WarningCode.CAP_NEAR_LIMIT)
        assertTrue(server.fetcher.requests.any { it.url == server.changesetUrl }, "reset")
        assertTrue(
            "the changeset is" in
                run.result.warnings
                    .single()
                    .message,
        )
    }

    @Test
    fun `a changeset body above half of MAX_JSON_BYTES is CAP_NEAR_LIMIT on warnings, and the sync installs`() {
        val server = Server()
        server.padding = (RevoktLimits.MAX_JSON_BYTES / 2).toInt()
        val run = sync(server).assert(SyncOutcome.INSTALLED, WarningCode.CAP_NEAR_LIMIT)
        assertTrue(
            "the changeset is" in
                run.result.warnings
                    .single()
                    .message,
        )
    }

    @Test
    fun `an x5u body above half of MAX_X5U_BYTES warns, and one of exactly half does not`() {
        val half = (RevoktLimits.MAX_X5U_BYTES / 2).toInt()
        val chain = pem(served)

        // Text before the first block is skipped by the PEM reader (rustls-pki-types, §7.1).
        fun padded(size: Int): String = "#".repeat(size - chain.length - 1) + "\n" + chain
        val server = Server(pem = padded(half))
        sync(server).assert(SyncOutcome.INSTALLED)
        server.pem = padded(half + 1)
        server.ts = ts2
        sync(server, now = ts2 + hour).assert(SyncOutcome.INSTALLED, WarningCode.CAP_NEAR_LIMIT)
    }

    @Test
    fun `a channel of more than half MAX_CHANGESET_RECORDS records warns, and the sync installs`() {
        val count = RevoktLimits.MAX_CHANGESET_RECORDS / 2
        val deltas =
            (1..count).map { i ->
                Rec(
                    "d-$i",
                    true,
                    delta.effectiveTimestamp + i,
                    "20261021-$i-compat.filter.delta",
                    UpdateFixtures.v4(listOf(log(100 + i) to (1_000L to 2_000L))),
                    parent = full.id,
                )
            }
        val records = listOf(full) + deltas
        val server = Server(records = records.map { it.json() }, bodies = records.associate { it.location to it.body })
        val run = sync(server).assert(SyncOutcome.INSTALLED, WarningCode.CAP_NEAR_LIMIT)
        assertTrue(
            "${count + 1} records" in
                run.result.warnings
                    .single()
                    .message,
        )
    }
}
