// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

@file:OptIn(dev.revokt.RevoktInternalApi::class)

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.FilterFormat
import dev.revokt.LogLevel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktStorage
import dev.revokt.SignatureVerifier
import dev.revokt.SyncFailure
import dev.revokt.SyncOutcome
import dev.revokt.VerifyResult
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.fetch.FetchLimits
import dev.revokt.engine.fetch.ScriptedFetcher
import dev.revokt.engine.fetch.client
import dev.revokt.engine.fetch.json
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.store.GenerationFileJson
import dev.revokt.engine.store.GenerationNames
import dev.revokt.engine.store.Pointer
import dev.revokt.engine.store.SourceRecord
import dev.revokt.engine.store.StoreLayout
import dev.revokt.engine.store.StoreRead
import dev.revokt.engine.store.UpdaterRecord
import dev.revokt.engine.update.UpdateFixtures.TestEngine
import dev.revokt.engine.update.UpdateFixtures.deltaRecord
import dev.revokt.engine.update.UpdateFixtures.fullRecord
import dev.revokt.engine.update.UpdateFixtures.log
import dev.revokt.engine.verify.ContentSignature
import dev.revokt.engine.verify.X5uChainFixture
import dev.revokt.verify.JcaFixtures
import okio.ByteString.Companion.toByteString
import java.security.PrivateKey
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * #137's failure paths of one sync (spec §6.5: "every loader task catches `Throwable`"; a store failure is
 * `STORE_FAILED`; the cursor, `lastVerified*` and the watermark advance only through an install): throwing fetchers,
 * verifiers, engines and stores, the retried flip, and prune after the flip.
 */
internal class CrliteSyncFailureTest : CrliteSyncFixture() {
    private fun oom(what: String): Nothing = throw OutOfMemoryError(what)

    @Test
    fun `nothing escapes - a throwing fetcher, verifier or engine is FAILED, an OutOfMemoryError included`() {
        // Each a poll interval apart, past the failure backoff the previous one left.
        val at = (0..3).map { ts + hour + it * 7 * hour }
        val throwing = Server()
        throwing.overrides[monitor] = { oom("fetcher") }
        sync(throwing, now = at[0]).assert(SyncFailure.CHANGESET_FETCH).also {
            assertIs<OutOfMemoryError>(it.result.cause)
        }
        val verifierOom =
            object : SignatureVerifier {
                override fun verify(
                    sigAlg: ByteArray,
                    spki: ByteArray,
                    message: ByteArray,
                    signature: ByteArray,
                ): VerifyResult = oom("verifier")

                override fun unsupportedOids(): Set<String> = emptySet()
            }
        sync(
            Server(),
            now = at[1],
            with = verifierOom,
        ).assert(SyncFailure.INTERNAL_ERROR).also {
            assertIs<OutOfMemoryError>(it.result.cause)
        }
        val prepareOom = TestEngine().apply { onPrepare = { oom("prepare") } }
        sync(Server(), now = at[2], engine = prepareOom).assert(SyncFailure.ENGINE_FAILED).also {
            assertIs<OutOfMemoryError>(it.result.cause)
        }
        val activateThrows = TestEngine().apply { onActivate = { error("activate") } }
        sync(Server(), now = at[3], engine = activateThrows).assert(SyncFailure.ENGINE_FAILED)
        assertNothingAdvanced(at[3], failures = 4)
    }

    @Test
    fun `#209 - an updater json read that throws leaves the file byte-identical, the watermark and cursor kept`() {
        val server = Server()
        server.headers = arrayOf("Backoff" to "60")
        sync(server).assert(SyncOutcome.INSTALLED)
        val key = "crlite/compat/updater.json"
        val before = checkNotNull(storage.inner.read(key))
        assertEquals(ts, updater().watermarkMillis)
        // Past the backoff, so the sync reads updater.json first; each read throws, a fatal error included.
        val at = ts + 2 * hour
        for (thrown in listOf(IllegalStateException("read"), OutOfMemoryError("read"))) {
            storage.failRead = { if (it.endsWith("updater.json")) thrown else null }
            val run = sync(server, now = at)
            if (thrown is OutOfMemoryError) {
                run.assert(SyncFailure.INTERNAL_ERROR)
                assertEquals(0, run.storeFailures)
            } else {
                run.assert(SyncFailure.STORE_FAILED)
                assertEquals(1, run.storeFailures)
            }
            storage.failRead = { null }
            assertContentEquals(before, storage.inner.read(key), "$thrown")
        }
        val s = sourceRecord(at)
        assertEquals(
            listOf<Any?>(ts, ts + hour, 0),
            listOf(s.lastVerifiedLastModified, s.lastVerifiedAtMillis, s.consecutiveFailures),
        )
        assertEquals(ts, updater(at).watermarkMillis)
    }

    @Test
    fun `a store that throws is STORE_FAILED, and a failing updater write is counted, not thrown`() {
        storage.failRead = { if (it.endsWith("updater.json")) IllegalStateException("read") else null }
        sync(Server()).assert(SyncFailure.STORE_FAILED).also {
            assertEquals(1, it.storeFailures)
        }
        storage.failRead = { null }
        storage.failWrite = { if (it.endsWith("updater.json")) IllegalStateException("write") else null }
        val server = Server()
        server.signature = Server(records = listOf(full.json())).sign()
        sync(server, now = ts + 8 * hour).assert(SyncFailure.SIGNATURE_INVALID).also {
            assertEquals(1, it.storeFailures)
        }
    }

    @Test
    fun `store reads and writes that throw are STORE_FAILED, whatever step they serve`() {
        // The reuse probe's blob read.
        storage.failRead = { if ("/blobs/" in it) IllegalStateException("blob read") else null }
        sync(Server()).assert(SyncFailure.STORE_FAILED).also {
            assertEquals(1, it.storeFailures)
        }
        // A full's blob write.
        storage.failRead = { null }
        storage.failWrite = { if ("/blobs/" in it) IllegalStateException("blob write") else null }
        sync(Server(), now = ts + 8 * hour).assert(SyncFailure.STORE_FAILED).also {
            assertEquals(1, it.storeFailures)
        }
        // The pointer read of the UNCHANGED check.
        storage.failWrite = { null }
        val server = Server()
        val now = ts + 15 * hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        storage.failRead = { if (it.endsWith("/current")) IllegalStateException("pointer read") else null }
        sync(server, now = now + hour).assert(SyncFailure.STORE_FAILED).also {
            assertEquals(1, it.storeFailures)
        }
    }

    @Test
    fun `an OutOfMemoryError counts a store failure from the first body fetch on, not before`() {
        // Before any body: reading updater.json.
        storage.failRead = { if (it.endsWith("updater.json")) OutOfMemoryError("updater read") else null }
        sync(Server()).assert(SyncFailure.INTERNAL_ERROR).also {
            assertEquals(0, it.storeFailures)
            assertIs<OutOfMemoryError>(it.result.cause)
        }
        storage.failRead = { null }
        // The body phase (§6.5's install): the delta's fetch, then the full's read-back for buildIndex.
        val fetchOom = Server()
        fetchOom.overrides[attachments + delta.location] = { oom("delta fetch") }
        sync(fetchOom, now = ts + 8 * hour).assert(SyncFailure.ATTACHMENT_FETCH).also {
            assertEquals(1, it.storeFailures)
        }
        val readBackOom = Server()
        readBackOom.overrides[attachments + delta.location] = {
            storage.failRead = { if ("/blobs/" in it) OutOfMemoryError("blob read-back") else null }
            response(200, delta.body)
        }
        sync(readBackOom, now = ts + 15 * hour).assert(SyncFailure.INTERNAL_ERROR).also {
            assertEquals(1, it.storeFailures)
            assertIs<OutOfMemoryError>(it.result.cause)
        }
    }

    @Test
    fun `a server root that fails or names a base outside allowedDomains is ATTACHMENT_BASE, nothing advanced`() {
        val roots =
            listOf<(FetchRequest) -> FetchResponse>(
                { response(500) },
                { ok("""{"capabilities":{"attachments":{"base_url":"https://evil.example/"}}}""") },
                {
                    ok(
                        """{"capabilities":{"attachments":{"base_url":"http://firefox-settings-attachments.cdn.mozilla.net/"}}}""",
                    )
                },
                { ok("{}") },
            )
        for ((i, root) in roots.withIndex()) {
            val server = Server()
            server.overrides["$base/"] = root
            // Each sync after the last one's failure backoff (at most the 6 h poll interval).
            val now = ts + hour + i * 7 * hour
            sync(server, now = now).assert(SyncFailure.ATTACHMENT_BASE)
            // No fallback: no attachment is fetched from any base, and the failure counts.
            assertEquals(emptyList(), server.attachmentRequests())
            assertNothingAdvanced(now, failures = i + 1)
        }
    }

    @Test
    fun `a prune that throws after the flip leaves the sync INSTALLED and its updater json advanced`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = assertNotNull(liveName())
        server.ts = ts + 1_000
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        // Only prune deletes in the first directory; the install itself deletes only its own before writing it.
        storage.failDelete = { if (first in it) IllegalStateException("delete") else null }
        server.ts = ts + 2_000
        val now = ts + 3 * hour
        val run = sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertEquals(ts + 2_000, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(ts + 2_000, updater(now).watermarkMillis)
        assertEquals(0, sourceRecord(now).consecutiveFailures)
    }

    @Test
    fun `a throw that escapes prune's own catch still leaves the sync INSTALLED and its updater json advanced`() {
        // prune logs its failure through safeLog, which rethrows a fatal error: here the logger's OutOfMemoryError
        // escapes prune, and only the post-install guard keeps the outcome.
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = assertNotNull(liveName())
        server.ts = ts + 1_000
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        storage.failDelete = { if (first in it) IllegalStateException("delete") else null }
        throwOn = { if (it.startsWith("pruning")) OutOfMemoryError("logger") else null }
        server.ts = ts + 2_000
        val now = ts + 3 * hour
        val run = sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(mapOf(Dataset.CRLITE to "${ts + 2_000}/${delta.id}"), run.result.installed)
        assertEquals(2, run.storeFailures)
        assertEquals(ts + 2_000, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(ts + 2_000, updater(now).watermarkMillis)
    }

    @Test
    fun `an install that counted store failures still prunes`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = assertNotNull(liveName())
        server.ts = ts + 1_000
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        storage.inner.write("crlite/compat/updater.json", "{".encodeToByteArray())
        server.ts = ts + 2_000
        sync(server, now = ts + 3 * hour).assert(SyncOutcome.INSTALLED).also { assertEquals(1, it.storeFailures) }
        assertEquals(StoreRead.Absent, store.readGeneration(first))
    }

    @Test
    fun `a pointer that does not read back after the flip is not pruned on, so nothing is deleted`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = assertNotNull(liveName())
        // current reads before the install, and not after its flip: a storage that breaks read-after-write.
        var flipped = false
        storage.failWrite = {
            if (it.endsWith("/current")) flipped = true
            null
        }
        storage.hidden = { flipped && it.endsWith("/current") }
        server.ts = ts + 1_000
        val run = sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertIs<StoreRead.Found<*>>(store.readGeneration(first))
    }

    @Test
    fun `UNCHANGED against a served generation the pointer does not name re-flips to it with no fetch or publish`() {
        val server = Server()
        storage.failWrite = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        sync(server).assert(SyncFailure.STORE_FAILED)
        assertEquals("$ts/${delta.id}", live().generationId)
        assertNull(liveName())
        assertNull(sourceRecord().lastVerifiedLastModified)
        storage.failWrite = { null }
        // An unnamed stray generation file: a heal flip is never pruned after (spec §6.5 "the re-flip").
        val other = UpdateFixtures.pending(store, listOf(fullRecord)).file
        val stray = store.putGeneration(GenerationFileJson.write(other))
        val epoch = snapshot.snapshot.generationEpoch
        server.fetcher.requests.clear()
        val now = ts + 2 * hour
        val engine = TestEngine()
        sync(server, now = now, engine = engine).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Found(Pointer(assertNotNull(live().generationFile), null)), store.pointer())
        assertEquals(emptyList(), engine.prepared, "the engine already serves it")
        assertEquals(epoch, snapshot.snapshot.generationEpoch, "nothing is published")
        assertEquals(emptyList(), server.attachmentRequests())
        assertIs<StoreRead.Found<*>>(store.readGeneration(stray), "no prune follows")
        assertEquals(ts, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(ts, updater(now).watermarkMillis)
        sync(server, now = now + hour).assert(SyncOutcome.UNCHANGED)
    }

    @Test
    fun `the re-flip keeps the old live generation as previous, by the candidate rule`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val old = assertNotNull(liveName())
        server.ts = ts + day
        storage.failWrite = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        sync(server, now = ts + day + hour).assert(SyncFailure.STORE_FAILED)
        storage.failWrite = { null }
        val served = assertNotNull(live().generationFile)
        assertNotEquals(old, served)
        sync(server, now = ts + day + 2 * hour).assert(SyncOutcome.INSTALLED)
        assertEquals(StoreRead.Found(Pointer(served, old)), store.pointer())
    }

    @Test
    fun `a served file that does not re-hash is not re-flipped to, so the collection installs and rewrites it`() {
        val server = Server()
        storage.failWrite = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        sync(server).assert(SyncFailure.STORE_FAILED)
        storage.failWrite = { null }
        val served = assertNotNull(live().generationFile)
        val key = store.generationKey(served)
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).let { it.copyOf(it.size - 1) })
        val engine = TestEngine()
        val run = sync(server, now = ts + 2 * hour, engine = engine).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared, "a full install")
        assertEquals(StoreRead.Found(Pointer(served, null)), store.pointer(), "the same bytes, the same name")
        assertIs<StoreRead.Found<*>>(store.stored(served), "rewritten")
        assertEquals(1, run.storeFailures, "the damaged served file, once")
    }

    @Test
    fun `a served generation with a rotted blob is not re-flipped to, so its blob is fetched again and rewritten`() {
        val server = Server()
        storage.failWrite = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        sync(server).assert(SyncFailure.STORE_FAILED)
        storage.failWrite = { null }
        val served = assertNotNull(live().generationFile)
        val key = store.blobKey(delta.body.toByteString().sha256())
        storage.inner.write(key, checkNotNull(storage.inner.read(key)).also { it[0] = (it[0] + 1).toByte() })
        server.fetcher.requests.clear()
        val engine = TestEngine()
        val run = sync(server, now = ts + 2 * hour, engine = engine).assert(SyncOutcome.INSTALLED)
        assertEquals(listOf(attachments + delta.location), server.attachmentRequests())
        assertContentEquals(delta.body, storage.inner.read(key))
        assertEquals(listOf("$ts/${delta.id}"), engine.prepared, "a full install")
        assertEquals(StoreRead.Found(Pointer(served, null)), store.pointer())
        assertEquals(1, run.storeFailures, "the rotted blob, once")
    }

    @Test
    fun `a retried flip over the same ts re-signed re-flips to the served file, then is UNCHANGED, with no loop`() {
        val server = Server()
        storage.failWrite = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        sync(server).assert(SyncFailure.STORE_FAILED)
        storage.failWrite = { null }
        val first = assertNotNull(live().generationFile)
        // Remote Settings re-signs the same collection at the same <ts>: a fresh ECDSA signature.
        val resigned = Server().sign()
        assertNotEquals(server.sign(), resigned)
        server.signature = resigned
        val now = ts + 2 * hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        // The re-signed collection is UNCHANGED at the same <ts>: the served file, which passes Load, is flipped to.
        assertEquals(StoreRead.Found(Pointer(first, null)), store.pointer())
        assertEquals("$ts/${delta.id}", stored(first).generationId)
        assertEquals(ts, sourceRecord(now).lastVerifiedLastModified)
        sync(server, now = now + hour).assert(SyncOutcome.UNCHANGED)
    }

    @Test
    fun `a malformed updater json counts a store failure and the sync goes on`() {
        storage.inner.write("crlite/compat/updater.json", "{".encodeToByteArray())
        val run = sync(Server()).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
    }
}
