// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.update

import dev.revokt.CrliteChannel
import dev.revokt.CrliteQueryResult
import dev.revokt.Dataset
import dev.revokt.DiagnosticCode
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.FilterFormat
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.RevoktStorage
import dev.revokt.SignatureVerifier
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.TrustClass
import dev.revokt.VerifyResult
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.fetch.FetchLimits
import dev.revokt.engine.fetch.ScriptedFetcher
import dev.revokt.engine.fetch.client
import dev.revokt.engine.fetch.json
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.store.GenerationNames
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * #137's acceptance test: one full CRLite generation synced from a scripted Remote Settings (spec §11's 0.2 row, §6.3,
 * §6.5, §7.1, §5.1 limits, §4 sync diagnostics). The fetcher records every request; the changeset is signed by #126's
 * fixture chain (a test root pinned in place of `root-ca-production-amo`); the records are synthesised from
 * `corpus/clubcard`'s `record.json` sources, as [UpdateFixtures] does, with its compat filters as the attachments.
 */
internal class CrliteSyncTest : X5uChainFixture() {
    private val base = "https://firefox.settings.services.mozilla.com/v1"
    private val monitor = "$base/buckets/monitor/collections/changes/changeset?_expected=0"
    private val x5u = "https://content-signature-2.cdn.mozilla.net/chains/test.chain"
    private val attachments = "https://firefox-settings-attachments.cdn.mozilla.net/"
    private val ts = 1_792_587_631_204
    private val hour = 3_600_000L
    private val day = 24 * hour

    private val source =
        MozillaRemoteSettings.DEFAULT
            .newBuilder()
            .pinnedRootSpkiSha256s(pinned.map { it.toByteArray() })
            .build()

    /** The x5u chain served, one per test: each `chain()` call signs afresh, and ECDSA signatures are randomised. */
    private val served = chain()

    private fun pem(chain: List<ByteArray>): String =
        chain.joinToString("") {
            "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(it) +
                "\n-----END CERTIFICATE-----\n"
        }

    /** One `cert-revocations` record, its attachment served at [location] with [body]. */
    private class Rec(
        val id: String,
        val incremental: Boolean,
        val effectiveTimestamp: Long,
        val filename: String,
        val body: ByteArray,
        val size: Long = body.size.toLong(),
        val hash: String = body.toByteString().sha256().hex(),
        val parent: String? = null,
        val channel: String = "compat",
    ) {
        val location = "security-state-staging/cert-revocations/$id.filter"

        fun json(): String =
            """{"id":"$id","last_modified":$effectiveTimestamp,"channel":"$channel","incremental":$incremental,""" +
                (parent?.let { """"parent":"$it",""" } ?: "") +
                """"effectiveTimestamp":$effectiveTimestamp,"attachment":{"filename":"$filename","hash":"$hash",""" +
                """"size":$size,"location":"$location","mimetype":"application/octet-stream"}}"""
    }

    private val full =
        Rec(
            fullRecord.id,
            false,
            fullRecord.effectiveTimestamp,
            fullRecord.filename,
            UpdateFixtures.bodies.getValue(fullRecord.filename),
        )
    private val delta =
        Rec(
            deltaRecord.id,
            true,
            deltaRecord.effectiveTimestamp,
            deltaRecord.filename,
            UpdateFixtures.bodies.getValue(deltaRecord.filename),
            parent = full.id,
        )

    /**
     * The scripted Remote Settings: `monitor/changes` listing the collection at [ts], its changeset of [records] at
     * [ts] signed under [key] (or with [signature]), the x5u at [x5u] and each record's attachment; [overrides] answer
     * a URL first, and anything else is a 404.
     */
    private inner class Server(
        var ts: Long = this.ts,
        var records: List<String> = listOf(full.json(), delta.json()),
        var bodies: Map<String, ByteArray> = listOf(full, delta).associate { it.location to it.body },
        var pem: String = pem(served),
        var key: PrivateKey = leafKey.private,
    ) {
        val overrides = HashMap<String, (FetchRequest) -> FetchResponse>()
        var headers: Array<Pair<String, String>> = emptyArray()
        var signature: String? = null
        private val signatures = HashMap<Pair<Long, List<String>>, String>()

        val fetcher = ScriptedFetcher { request -> overrides[request.url]?.invoke(request) ?: answer(request.url) }

        val changesetUrl: String
            get() = "$base/buckets/security-state/collections/cert-revocations/changeset?_expected=$ts"

        fun attachmentRequests(): List<String> = fetcher.requests.map { it.url }.filter { it.startsWith(attachments) }

        /** Autograph's signature over [records] at [ts], once per changeset (ECDSA signs with fresh randomness). */
        fun sign(): String =
            signature ?: signatures.getOrPut(ts to records) {
                val payload = checkNotNull(ContentSignature.recordsJson(records.map(::json), ts))
                Base64.getUrlEncoder().withoutPadding().encodeToString(
                    JcaFixtures.sign(
                        "SHA384withECDSAinP1363Format",
                        key,
                        "Content-Signature:\u0000".encodeToByteArray() + payload,
                    ),
                )
            }

        private fun answer(url: String): FetchResponse =
            when {
                url == monitor -> {
                    ok(
                        """{"changes":[{"id":"x","bucket":"security-state","collection":"cert-revocations",""" +
                            """"last_modified":$ts}],"timestamp":$ts}""",
                        *headers,
                    )
                }

                url == changesetUrl -> {
                    ok(
                        """{"changes":[${records.joinToString(",")}],"timestamp":$ts,"metadata":{"signatures":""" +
                            """[{"x5u":"$x5u","signature":"${sign()}","mode":"p384ecdsa"}]}}""",
                        *headers,
                    )
                }

                url == x5u -> {
                    ok(pem, *headers)
                }

                url.startsWith(attachments) -> {
                    bodies[url.removePrefix(attachments)]?.let { response(200, it, *headers) } ?: response(404)
                }

                else -> {
                    response(404)
                }
            }
    }

    /** A storage whose reads and writes a test can fail, key by key. */
    private class Faulty(
        val inner: RevoktStorage = RevoktStorage.inMemory(),
    ) : RevoktStorage by inner {
        var failWrite: (String) -> Throwable? = { null }
        var failRead: (String) -> Throwable? = { null }

        override fun read(name: String): ByteArray? {
            failRead(name)?.let { throw it }
            return inner.read(name)
        }

        override fun write(
            name: String,
            bytes: ByteArray,
        ) {
            failWrite(name)?.let { throw it }
            inner.write(name, bytes)
        }
    }

    private val storage = Faulty()
    private val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
    private val logger = UpdateFixtures.Recording()
    private val snapshot =
        SnapshotRef(
            GenerationSnapshot(
                0,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, null, false, null, null, false, false, false)),
                null,
            ),
        )

    private fun sync(
        server: Server,
        now: Long = server.ts + hour,
        engine: TestEngine = TestEngine(),
        limits: FetchLimits = FetchLimits(),
        with: SignatureVerifier = verifier,
    ): SyncRun =
        CrliteSync(
            client(server.fetcher, source, limits),
            store,
            engine,
            snapshot,
            with,
            day,
            day,
            logger,
        ).syncOnce(now)

    private fun SyncRun.assert(
        outcome: SyncOutcome,
        stage: SyncStage? = null,
        vararg codes: DiagnosticCode,
    ): SyncRun {
        assertEquals(outcome to stage, result.outcome to result.stage, "$result")
        assertEquals(codes.toList(), result.warnings.map { it.code }, "$result")
        return this
    }

    /** A failure's warnings: `SYNC_FAILED`, then [codes]. */
    private fun failed(vararg codes: DiagnosticCode): Array<DiagnosticCode> =
        arrayOf(DiagnosticCode.SYNC_FAILED, *codes)

    private fun updater(now: Long = ts + hour): UpdaterRecord =
        (store.updater(now) as? StoreRead.Found)?.value?.record ?: UpdaterRecord()

    private fun sourceRecord(now: Long = ts + hour): SourceRecord = updater(now).sources.getValue(source.sourceId)

    private fun live(): DatasetGeneration = snapshot.snapshot.datasets.getValue(Dataset.CRLITE)

    private fun liveDirectory(): String? = (store.pointer() as? StoreRead.Found)?.value?.live

    /** Nothing advanced: no cursor, no `lastVerified*`, no watermark, no pointer; the attempt written, one failure. */
    private fun assertNothingAdvanced(
        now: Long = ts + hour,
        failures: Int = 1,
    ) {
        val record = updater(now)
        assertNull(record.watermarkMillis)
        assertEquals(now, record.datasetLastAttemptAtMillis)
        val s = record.sources.getValue(source.sourceId)
        assertEquals(
            listOf<Any?>(null, null, now, failures),
            listOf(s.lastVerifiedLastModified, s.lastVerifiedAtMillis, s.lastAttemptAtMillis, s.consecutiveFailures),
        )
        assertNull(liveDirectory())
        assertNull(live().generationId)
    }

    @Test
    fun `a full changeset installs, its id the ts and last placed record, records json the signed payload`() {
        val server = Server()
        val engine = TestEngine()
        val run = sync(server, engine = engine).assert(SyncOutcome.INSTALLED)
        val id = "$ts/${delta.id}"
        assertEquals(mapOf(Dataset.CRLITE to id), run.result.installed)
        assertEquals(listOf(id), engine.prepared)
        assertEquals(200, run.result.httpStatus)
        assertEquals(source.sourceId, run.result.sourceId)
        assertEquals(0, run.storeFailures)
        // The wire: the poll, the whole changeset (no _since, no If-None-Match until #141), the x5u, each body once.
        assertEquals(
            listOf(monitor, server.changesetUrl, x5u, attachments + full.location, attachments + delta.location),
            server.fetcher.requests.map { it.url },
        )
        assertFalse(server.fetcher.requests.any { "If-None-Match" in it.headers })
        val directory = GenerationNames.directory(ts, id)
        assertEquals(directory, liveDirectory())
        val payload = checkNotNull(ContentSignature.recordsJson(server.records.map(::json), ts))
        assertContentEquals(payload, store.records(directory))
        val meta = assertNotNull(store.meta(directory))
        assertEquals(
            listOf(TrustClass.SIGNED, FilterFormat.V3, ts, "security-state/cert-revocations"),
            listOf(meta.trustClass, meta.format, meta.sourceTimestampMillis, meta.collection),
        )
        assertEquals(ts, meta.signed?.changesetTimestampMillis)
        assertEquals(served[0].toByteString().sha256(), meta.signed?.signerLeafSha256)
        assertEquals(96, meta.signed?.signature?.size)
        // The cursor, lastVerified* and the watermark advance after the flip.
        val now = ts + hour
        assertEquals(ts, updater().watermarkMillis)
        val s = sourceRecord()
        assertEquals(
            listOf<Any?>(ts, now, now, 0),
            listOf(s.lastVerifiedLastModified, s.lastVerifiedAtMillis, s.lastAttemptAtMillis, s.consecutiveFailures),
        )
        assertNull(s.backoffUntilMillis)
        // The published generation, with the loader's own maximum coverage.
        val published = live()
        assertEquals(
            listOf(id, TrustClass.SIGNED, ts, false),
            listOf(
                published.generationId,
                published.trustClass,
                published.sourceTimestampMillis,
                published.clockBehind,
            ),
        )
        val index = C2spIndex.read(assertNotNull(store.index(directory)))
        assertEquals(maxCoverageMillis(index), published.maxCoverageMillis)
        assertNotNull(published.maxCoverageMillis)
    }

    @Test
    fun `the same changeset again is UNCHANGED by timestamp, fetching no body`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        server.fetcher.requests.clear()
        val later = ts + 2 * hour
        sync(server, now = later).assert(SyncOutcome.UNCHANGED)
        assertEquals(listOf(monitor, server.changesetUrl, x5u), server.fetcher.requests.map { it.url })
        val s = sourceRecord(later)
        assertEquals(
            listOf(ts, ts + hour, later),
            listOf(s.lastVerifiedLastModified, s.lastVerifiedAtMillis, s.lastAttemptAtMillis),
        )
    }

    @Test
    fun `content-signature item - 33 and 64 character filenames install under their 32 character derived names`() {
        val long33 = "a".repeat(24) + "-compat.f"
        val long64 = "b".repeat(51) + "-compat.delta"
        assertEquals(33 to 64, long33.length to long64.length)
        val f = Rec(full.id, false, full.effectiveTimestamp, long33, full.body)
        val d = Rec(delta.id, true, delta.effectiveTimestamp, long64, delta.body, parent = full.id)
        val server =
            Server(
                records = listOf(f.json(), d.json()),
                bodies =
                    listOf(f, d).associate {
                        it.location to
                            it.body
                    },
            )
        sync(server).assert(SyncOutcome.INSTALLED)
        val directory = assertNotNull(liveDirectory())
        val names = listOf(GenerationNames.derive(long33), GenerationNames.derive(long64))
        assertEquals(listOf(32, 32), names.map { it.length })
        assertEquals(names, C2spIndex.read(assertNotNull(store.index(directory))).filenames)
        assertEquals(setOf(names[0]), store.meta(directory)?.blobs?.keys)
        assertEquals(
            setOf(StoreLayout.INDEX) + names,
            store
                .readGeneration(directory)
                ?.files
                ?.names
                ?.toSet(),
        )
        // The attachment filenames stay in the signed records only.
        val records = assertNotNull(store.records(directory)).decodeToString()
        assertTrue(long33 in records && long64 in records)
    }

    @Test
    fun `content-signature item - two filenames mapping to one name are FAILED, INDEX_INCONSISTENT, before any body`() {
        val long = "c".repeat(40) + ".delta"
        val short = GenerationNames.derive(long)
        val f = Rec(full.id, false, full.effectiveTimestamp, short, full.body)
        val d = Rec(delta.id, true, delta.effectiveTimestamp, long, delta.body, parent = full.id)
        val server =
            Server(
                records = listOf(f.json(), d.json()),
                bodies =
                    listOf(f, d).associate {
                        it.location to
                            it.body
                    },
            )
        sync(server).assert(SyncOutcome.FAILED, SyncStage.INDEX, *failed(DiagnosticCode.INDEX_INCONSISTENT))
        assertEquals(emptyList(), server.attachmentRequests())
        assertNothingAdvanced()
    }

    @Test
    fun `a channel with two fulls, or none, is FAILED, INDEX_INCONSISTENT, before any body`() {
        val second = Rec("f2", false, full.effectiveTimestamp + 1, "second.filter", full.body)
        for ((i, records) in listOf(
            listOf(full.json(), second.json(), delta.json()),
            listOf(delta.json()),
        ).withIndex()) {
            val server = Server(records = records)
            // Each a poll interval apart, past the failure backoff the previous one left.
            sync(
                server,
                now = ts + hour + i * 7 * hour,
            ).assert(SyncOutcome.FAILED, SyncStage.INDEX, *failed(DiagnosticCode.INDEX_INCONSISTENT))
            assertEquals(emptyList(), server.attachmentRequests())
        }
    }

    @Test
    fun `content-signature sequence, no seed - 25 h ahead installs clock-behind, then UNCHANGED, then normally`() {
        val server = Server()
        val behind = ts - 25 * hour
        sync(server, now = behind).assert(SyncOutcome.INSTALLED, null, DiagnosticCode.CLOCK_BEHIND)
        assertTrue(live().clockBehind)
        assertEquals(ts, live().sourceTimestampMillis)
        // lastVerifiedAtMillis advanced; the watermark and the cursor did not.
        assertNull(updater(behind).watermarkMillis)
        val s = sourceRecord(behind)
        assertEquals(
            listOf<Any?>(null, behind, 0),
            listOf(s.lastVerifiedLastModified, s.lastVerifiedAtMillis, s.consecutiveFailures),
        )
        // The next poll of the same changeset is UNCHANGED, the clock still behind.
        server.fetcher.requests.clear()
        sync(server, now = behind + hour).assert(SyncOutcome.UNCHANGED)
        assertEquals(emptyList(), server.attachmentRequests())
        assertTrue(live().clockBehind)
        // The clock corrected: the next changeset installs normally and advances everything. The full is reused.
        server.ts = ts + 1_000
        server.fetcher.requests.clear()
        val now = server.ts + hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertFalse(live().clockBehind)
        assertEquals(server.ts, updater(now).watermarkMillis)
        assertEquals(server.ts, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(listOf(attachments + delta.location), server.attachmentRequests())
    }

    @Test
    fun `data-path (g) - an intermediates-shaped changeset is SYNC_SCHEMA_REJECTED and advances nothing`() {
        val intermediate =
            """{"schema":1792767600380,"derHash":"EmW5f+rzuC5XDD8JtLTqlMNK2m253Wa2Iq8f2wg96Ck=",
                "attachment":{"hash":"96ef47e108b2bf0b6156f5b22ec6ab5e6a7fc7eaed9a51acee44cd1ec2622df4","size":2247,
                  "filename":"aZdqNe5RmxZVjOpmYQBC5_un_r_Do0BdTy92bgU-lI4=.pem",
                  "location":"security-state-staging/intermediates/x.pem","mimetype":"application/x-pem-file"},
                "id":"53279a21-f633-432a-b73b-0b7f38f730c1","last_modified":1792771022925}"""
        val server = Server(records = listOf(intermediate))
        sync(server).assert(SyncOutcome.FAILED, SyncStage.SCHEMA, *failed(DiagnosticCode.SYNC_SCHEMA_REJECTED))
        assertEquals(emptyList(), server.attachmentRequests())
        assertNothingAdvanced()
    }

    @Test
    fun `data-path (g) - a signed attachment over MAX_FILTER_BYTES is FAILED with CAP_NEAR_LIMIT, not fetched`() {
        val big =
            Rec(
                delta.id,
                true,
                delta.effectiveTimestamp,
                delta.filename,
                delta.body,
                size =
                    RevoktLimits.MAX_FILTER_BYTES + 1,
                parent = full.id,
            )
        val server = Server(records = listOf(full.json(), big.json()))
        sync(server).assert(SyncOutcome.FAILED, SyncStage.ATTACHMENT, *failed(DiagnosticCode.CAP_NEAR_LIMIT))
        assertEquals(emptyList(), server.attachmentRequests())
        assertNothingAdvanced()
    }

    @Test
    fun `a signed attachment of exactly MAX_FILTER_BYTES is fetched, not refused`() {
        val atCap =
            Rec(
                delta.id,
                true,
                delta.effectiveTimestamp,
                delta.filename,
                delta.body,
                size = RevoktLimits.MAX_FILTER_BYTES,
                parent = full.id,
            )
        val server = Server(records = listOf(full.json(), atCap.json()))
        // Fetched under its signed size, and FAILED because the scripted body is shorter: no CAP_NEAR_LIMIT.
        sync(server).assert(SyncOutcome.FAILED, SyncStage.ATTACHMENT, *failed())
        assertEquals(listOf(attachments + full.location, attachments + delta.location), server.attachmentRequests())
    }

    @Test
    fun `a delta is a file of its directory, never a blob, even when its bytes are a stored blob's`() {
        val twin = Rec(delta.id, true, delta.effectiveTimestamp, delta.filename, full.body, parent = full.id)
        store.putBlob(full.body)
        val server =
            Server(
                records = listOf(full.json(), twin.json()),
                bodies =
                    listOf(full, twin).associate {
                        it.location to
                            it.body
                    },
            )
        sync(server).assert(SyncOutcome.INSTALLED)
        val meta = assertNotNull(store.meta(assertNotNull(liveDirectory())))
        assertEquals(setOf(full.filename), meta.blobs.keys)
        assertEquals(listOf(attachments + twin.location), server.attachmentRequests())
    }

    @Test
    fun `data-path (g) - a 3xx on the changeset is FAILED with its status, never followed`() {
        val server = Server()
        server.overrides[server.changesetUrl] =
            { response(302, ByteArray(0), "Location" to "https://elsewhere.example/") }
        val run = sync(server).assert(SyncOutcome.FAILED, SyncStage.CHANGESET, *failed())
        assertEquals(302, run.result.httpStatus)
        assertEquals(listOf(monitor, server.changesetUrl), server.fetcher.requests.map { it.url })
        assertNothingAdvanced()
    }

    @Test
    fun `a signature that does not verify is FAILED at SIGNATURE and advances nothing`() {
        val server = Server()
        server.signature = Server(records = listOf(full.json())).sign()
        sync(server).assert(SyncOutcome.FAILED, SyncStage.SIGNATURE, *failed())
        assertEquals(emptyList(), server.attachmentRequests())
        assertNothingAdvanced()
    }

    @Test
    fun `an x5u link outside its window at now is CLOCK_SKEW at X5U`() {
        val server = Server()
        val late = millis("2051-01-01T00:00:00Z")
        sync(server, now = late).assert(SyncOutcome.CLOCK_SKEW, SyncStage.X5U, *failed())
        assertNothingAdvanced(late)
    }

    @Test
    fun `a P-256 leaf's changeset installs, its 64-byte signature in meta json`() {
        val p256 = ecPair("x5u-leaf-p256", "secp256r1")
        val server = Server(pem = pem(chain(leaf = leaf(spki = p256.public.encoded))), key = p256.private)
        sync(server).assert(SyncOutcome.INSTALLED)
        assertEquals(
            64,
            store
                .meta(assertNotNull(liveDirectory()))
                ?.signed
                ?.signature
                ?.size,
        )
    }

    @Test
    fun `under a persisted backoff the sync is BACKOFF, fetches nothing and writes the attempt`() {
        val server = Server()
        server.headers = arrayOf("Backoff" to "600")
        sync(server).assert(SyncOutcome.INSTALLED)
        val installedAt = ts + hour
        assertEquals(installedAt + 600_000, sourceRecord().backoffUntilMillis)
        server.fetcher.requests.clear()
        val run = sync(server, now = installedAt + 1_000).assert(SyncOutcome.BACKOFF)
        assertNull(run.result.httpStatus)
        assertEquals(emptyList(), server.fetcher.requests)
        assertEquals(installedAt + 1_000, sourceRecord(installedAt + 1_000).lastAttemptAtMillis)
        // Once it passes, the sync polls again.
        sync(server, now = installedAt + 600_000).assert(SyncOutcome.UNCHANGED)
    }

    @Test
    fun `a watermark past the window is ROLLBACK_REFUSED before any body, and not a failure`() {
        store.writeUpdater(UpdaterRecord(watermarkMillis = ts + 2 * day), ts)
        val server = Server()
        sync(server).assert(SyncOutcome.ROLLBACK_REFUSED)
        assertEquals(emptyList(), server.attachmentRequests())
        val s = sourceRecord()
        assertEquals(
            listOf<Any?>(null, null, 0),
            listOf(s.lastVerifiedLastModified, s.lastVerifiedAtMillis, s.consecutiveFailures),
        )
        assertEquals(ts + 2 * day, updater().watermarkMillis)
    }

    @Test
    fun `a changeset beyond now + clockSkew beside a sane live generation is CLOCK_SKEW at CHANGESET`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val now = ts + 2 * hour
        server.ts = now + 2 * day
        sync(server, now = now).assert(SyncOutcome.CLOCK_SKEW, SyncStage.CHANGESET, *failed())
        assertEquals(ts, updater(now).watermarkMillis)
        assertEquals("$ts/${delta.id}", live().generationId)
    }

    @Test
    fun `a coverage end beyond the signed ts + clockSkew is FAILED at INDEX and leaves the generation out`() {
        val early = 1_792_000_000_000
        val server = Server(ts = early)
        sync(server).assert(SyncOutcome.FAILED, SyncStage.INDEX, *failed())
        assertNothingAdvanced(early + hour)
    }

    @Test
    fun `inside the rollback window a lower maximum coverage is ROLLBACK_REFUSED`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        // An older changeset (inside the window) of the full alone covers less than the live full and delta.
        server.ts = ts - hour
        server.records = listOf(full.json())
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.ROLLBACK_REFUSED)
        assertEquals("$ts/${delta.id}", live().generationId)
    }

    @Test
    fun `a stored full whose blob re-hashes is reused, and one that does not is fetched and rewritten`() {
        val server = Server()
        val blob = store.blobKey(full.body.toByteString().sha256())
        storage.inner.write(blob, byteArrayOf(1, 2, 3))
        val run = sync(server).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
        assertEquals(listOf(attachments + full.location, attachments + delta.location), server.attachmentRequests())
        assertContentEquals(full.body, storage.inner.read(blob))
    }

    @Test
    fun `a body that differs from its signed hash is FAILED at ATTACHMENT`() {
        val server = Server()
        server.bodies =
            server.bodies + (delta.location to delta.body.copyOf().also { it[it.size - 1] = (it.last() + 1).toByte() })
        sync(server).assert(SyncOutcome.FAILED, SyncStage.ATTACHMENT, *failed())
        assertNothingAdvanced()
    }

    @Test
    fun `each install prunes the store to the directories the pointer names`() {
        val server = Server()
        sync(server).assert(SyncOutcome.INSTALLED)
        val first = assertNotNull(liveDirectory())
        server.ts = ts + 1_000
        sync(server, now = ts + 2 * hour).assert(SyncOutcome.INSTALLED)
        server.ts = ts + 2_000
        sync(server, now = ts + 3 * hour).assert(SyncOutcome.INSTALLED)
        assertNull(store.meta(first))
        assertFalse(storage.names().any { "/$first/" in it })
    }

    @Test
    fun `a delta in an encoding the engine does not list is FORMAT_UNSUPPORTED, and the previous generation stays`() {
        // The lead's decision on #137: the format check covers every placed filter, not only the full.
        val engine = TestEngine(formats = setOf(FilterFormat.V3))
        val server = Server()
        sync(server, engine = engine).assert(SyncOutcome.INSTALLED)
        val previous = "$ts/${delta.id}"
        val v4 = UpdateFixtures.v4(listOf(log(1) to (1_000L to 2_000L)))
        val d = Rec("d-v4", true, delta.effectiveTimestamp + 1, "20261022-1-compat.filter.delta", v4, parent = full.id)
        server.ts = ts + 1_000
        server.records = listOf(full.json(), delta.json(), d.json())
        server.bodies = server.bodies + (d.location to v4)
        val now = ts + 2 * hour
        sync(server, now = now, engine = engine)
            .assert(SyncOutcome.FAILED, SyncStage.PREPARE, *failed(DiagnosticCode.FORMAT_UNSUPPORTED))
        assertEquals(listOf(previous), engine.prepared)
        assertEquals(previous, live().generationId)
        assertEquals(GenerationNames.directory(ts, previous), liveDirectory())
        assertEquals(ts, updater(now).watermarkMillis)
        assertEquals(ts, sourceRecord(now).lastVerifiedLastModified)
    }

    @Test
    fun `an engine that does not read the format is FAILED with FORMAT_UNSUPPORTED at PREPARE`() {
        val engine = TestEngine(formats = setOf(FilterFormat.V4))
        sync(
            Server(),
            engine = engine,
        ).assert(SyncOutcome.FAILED, SyncStage.PREPARE, *failed(DiagnosticCode.FORMAT_UNSUPPORTED))
        assertEquals(emptyList(), engine.prepared)
        assertNothingAdvanced()
    }

    @Test
    fun `a delta in another encoding than the full's installs, meta format the full's`() {
        // The maintainer's decision on #137: each filter is read in its own encoding, as Firefox and upki read them.
        val v4 = UpdateFixtures.v4(listOf(log(1) to (1_000L to 2_000L)))
        val d = Rec(delta.id, true, delta.effectiveTimestamp, delta.filename, v4, parent = full.id)
        val server =
            Server(
                records = listOf(full.json(), d.json()),
                bodies =
                    listOf(full, d).associate {
                        it.location to
                            it.body
                    },
            )
        sync(server).assert(SyncOutcome.INSTALLED)
        assertEquals(FilterFormat.V3, store.meta(assertNotNull(liveDirectory()))?.format)
    }

    @Test
    fun `the placement refusal precedes the rollback decision, as the issue orders them`() {
        store.writeUpdater(UpdaterRecord(watermarkMillis = ts + 2 * day), ts)
        val long = "c".repeat(40) + ".delta"
        val f = Rec(full.id, false, full.effectiveTimestamp, GenerationNames.derive(long), full.body)
        val d = Rec(delta.id, true, delta.effectiveTimestamp, long, delta.body, parent = full.id)
        val server = Server(records = listOf(f.json(), d.json()))
        sync(server).assert(SyncOutcome.FAILED, SyncStage.INDEX, *failed(DiagnosticCode.INDEX_INCONSISTENT))
    }

    @Test
    fun `a tombstone in the full changeset is merged away before the schema check, and records json omits it`() {
        val tombstone = """{"id":"gone","last_modified":$ts,"deleted":true}"""
        val server = Server(records = listOf(full.json(), tombstone, delta.json()))
        sync(server).assert(SyncOutcome.INSTALLED)
        val payload = checkNotNull(ContentSignature.recordsJson(listOf(full.json(), delta.json()).map(::json), ts))
        assertContentEquals(payload, store.records(assertNotNull(liveDirectory())))
    }

    @Test
    fun `a self-check mismatch is FAILED with ENGINE_SELF_CHECK_FAILED and counts a store failure`() {
        val engine = TestEngine().apply { preparedAnswer = { CrliteQueryResult.NOT_REVOKED } }
        val run = sync(Server(), engine = engine)
        run.assert(SyncOutcome.FAILED, SyncStage.SELF_CHECK, *failed(DiagnosticCode.ENGINE_SELF_CHECK_FAILED))
        assertEquals(1, run.storeFailures)
        assertNothingAdvanced()
    }

    private fun oom(what: String): Nothing = throw OutOfMemoryError(what)

    @Test
    fun `nothing escapes - a throwing fetcher, verifier or engine is FAILED, an OutOfMemoryError included`() {
        // Each a poll interval apart, past the failure backoff the previous one left.
        val at = (0..3).map { ts + hour + it * 7 * hour }
        val throwing = Server()
        throwing.overrides[monitor] = { oom("fetcher") }
        sync(throwing, now = at[0]).assert(SyncOutcome.FAILED, SyncStage.CHANGESET, *failed()).also {
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
        ).assert(SyncOutcome.FAILED, SyncStage.SIGNATURE, *failed()).also {
            assertIs<OutOfMemoryError>(it.result.cause)
        }
        val prepareOom = TestEngine().apply { onPrepare = { oom("prepare") } }
        sync(Server(), now = at[2], engine = prepareOom).assert(SyncOutcome.FAILED, SyncStage.PREPARE, *failed()).also {
            assertIs<OutOfMemoryError>(it.result.cause)
        }
        val activateThrows = TestEngine().apply { onActivate = { error("activate") } }
        sync(Server(), now = at[3], engine = activateThrows).assert(SyncOutcome.FAILED, SyncStage.ACTIVATE, *failed())
        assertNothingAdvanced(at[3], failures = 4)
    }

    @Test
    fun `a store that throws is STORE_FAILED at STORE, and a failing updater write is counted, not thrown`() {
        storage.failRead = { if (it.endsWith("updater.json")) IllegalStateException("read") else null }
        sync(Server()).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed()).also {
            assertEquals(1, it.storeFailures)
        }
        storage.failRead = { null }
        storage.failWrite = { if (it.endsWith("updater.json")) IllegalStateException("write") else null }
        val server = Server()
        server.signature = Server(records = listOf(full.json())).sign()
        sync(server, now = ts + 8 * hour).assert(SyncOutcome.FAILED, SyncStage.SIGNATURE, *failed()).also {
            assertEquals(1, it.storeFailures)
        }
    }

    @Test
    fun `UNCHANGED against a live generation the pointer does not name retries the install and flips it`() {
        val server = Server()
        storage.failWrite = { if (it.endsWith("/current")) IllegalStateException("flip") else null }
        sync(server).assert(SyncOutcome.STORE_FAILED, SyncStage.STORE, *failed())
        assertEquals("$ts/${delta.id}", live().generationId)
        assertNull(liveDirectory())
        assertNull(sourceRecord().lastVerifiedLastModified)
        storage.failWrite = { null }
        val now = ts + 2 * hour
        sync(server, now = now).assert(SyncOutcome.INSTALLED)
        assertEquals(GenerationNames.directory(ts, "$ts/${delta.id}"), liveDirectory())
        assertEquals(ts, sourceRecord(now).lastVerifiedLastModified)
        assertEquals(ts, updater(now).watermarkMillis)
    }

    @Test
    fun `a malformed updater json counts a store failure and the sync goes on`() {
        storage.inner.write("crlite/compat/updater.json", "{".encodeToByteArray())
        val run = sync(Server()).assert(SyncOutcome.INSTALLED)
        assertEquals(1, run.storeFailures)
    }

    @Test
    fun `a server Backoff on a failure waits the header`() {
        val server = Server()
        server.headers = arrayOf("Retry-After" to "60")
        server.overrides[x5u] = { response(500, ByteArray(0), "Retry-After" to "60") }
        sync(server).assert(SyncOutcome.FAILED, SyncStage.X5U, *failed()).also {
            assertEquals(500, it.result.httpStatus)
        }
        assertEquals(ts + hour + 60_000, sourceRecord().backoffUntilMillis)
    }
}
