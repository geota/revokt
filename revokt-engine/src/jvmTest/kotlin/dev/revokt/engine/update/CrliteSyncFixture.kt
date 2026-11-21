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
import dev.revokt.LogLevel
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.RevoktLogger
import dev.revokt.RevoktStorage
import dev.revokt.SignatureVerifier
import dev.revokt.SyncOutcome
import dev.revokt.SyncStage
import dev.revokt.VerifyResult
import dev.revokt.engine.c2sp.C2spIndex
import dev.revokt.engine.fetch.FetchLimits
import dev.revokt.engine.fetch.ScriptedFetcher
import dev.revokt.engine.fetch.client
import dev.revokt.engine.fetch.json
import dev.revokt.engine.fetch.ok
import dev.revokt.engine.fetch.response
import dev.revokt.engine.json.JsonInteger
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

/** The scripted Remote Settings, store, engine and helpers of [CrliteSyncTest] and [CrliteSyncFailureTest] (#137). */
internal open class CrliteSyncFixture : X5uChainFixture() {
    protected val base = "https://firefox.settings.services.mozilla.com/v1"
    protected val monitor = "$base/buckets/monitor/collections/changes/changeset?_expected=0"
    protected val x5u = "https://content-signature-2.cdn.mozilla.net/chains/test.chain"
    protected val attachments = "https://firefox-settings-attachments.cdn.mozilla.net/"
    protected val ts = 1_792_587_631_204
    protected val hour = 3_600_000L
    protected val day = 24 * hour

    protected val source =
        MozillaRemoteSettings.DEFAULT
            .newBuilder()
            .pinnedRootSpkiSha256s(pinned.map { it.toByteArray() })
            .build()

    /** The x5u chain served, one per test: each `chain()` call signs afresh, and ECDSA signatures are randomised. */
    protected val served = chain()

    protected fun pem(chain: List<ByteArray>): String =
        chain.joinToString("") {
            "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(it) +
                "\n-----END CERTIFICATE-----\n"
        }

    /** One `cert-revocations` record, its attachment served at [location] with [body]. */
    protected class Rec(
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

    protected val full =
        Rec(
            fullRecord.id,
            false,
            fullRecord.effectiveTimestamp,
            fullRecord.filename,
            UpdateFixtures.bodies.getValue(fullRecord.filename),
        )
    protected val delta =
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
     * a URL first, and anything else is a 404. A changeset `_since` a cursor lists the records whose `last_modified` is
     * after it and every tombstone of [tombstones], or [since]'s changes when set; with `If-None-Match` at [ts] it is a
     * 304, as Kinto answers a current ETag.
     */
    protected inner class Server(
        var ts: Long = this.ts,
        var records: List<String> = listOf(full.json(), delta.json()),
        var bodies: Map<String, ByteArray> = listOf(full, delta).associate { it.location to it.body },
        var pem: String = pem(served),
        var key: PrivateKey = leafKey.private,
    ) {
        val overrides = HashMap<String, (FetchRequest) -> FetchResponse>()
        var headers: Array<Pair<String, String>> = emptyArray()
        var signature: String? = null
        var tombstones: List<String> = emptyList()

        /** An unread member of that many bytes in the changeset envelope, to grow its body. */
        var padding: Int = 0
        var since: ((Long) -> List<String>)? = null
        private val signatures = HashMap<Pair<Long, List<String>>, String>()

        val fetcher = ScriptedFetcher { request -> overrides[request.url]?.invoke(request) ?: answer(request) }

        val changesetUrl: String
            get() = "$base/buckets/security-state/collections/cert-revocations/changeset?_expected=$ts"

        /** The changeset URL from [cursor]. */
        fun sinceUrl(cursor: Long): String = "$changesetUrl&_since=$cursor"

        /** The changes after [cursor]: [since]'s, else the records modified after it and [tombstones]. */
        fun changes(cursor: Long): List<String> =
            since?.invoke(cursor)
                ?: (
                    records.filter {
                        checkNotNull(
                            (json(it)["last_modified"] as JsonInteger).toLongOrNull(),
                        ) > cursor
                    } +
                        tombstones
                )

        /** The changeset from [cursor], as served whatever `If-None-Match` says. */
        fun sinceResponse(cursor: Long): FetchResponse = changeset(changes(cursor))

        private fun changeset(changes: List<String>): FetchResponse =
            ok(
                """{"changes":[${changes.joinToString(",")}],"timestamp":$ts,"metadata":{"signatures":""" +
                    """[{"x5u":"$x5u","signature":"${sign()}","mode":"p384ecdsa"}]}""" +
                    (if (padding > 0) ""","padding":"${"x".repeat(padding)}"}""" else "}"),
                *headers,
            )

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

        private fun answer(request: FetchRequest): FetchResponse {
            val url = request.url
            return when {
                url == monitor -> {
                    ok(
                        """{"changes":[{"id":"x","bucket":"security-state","collection":"cert-revocations",""" +
                            """"last_modified":$ts}],"timestamp":$ts}""",
                        *headers,
                    )
                }

                url == changesetUrl -> {
                    changeset(records)
                }

                url.startsWith("$changesetUrl&_since=") -> {
                    if (request.headers["If-None-Match"] == "\"$ts\"") {
                        response(304, ByteArray(0), *headers)
                    } else {
                        changeset(changes(url.substringAfter("&_since=").toLong()))
                    }
                }

                url == x5u -> {
                    ok(pem, *headers)
                }

                // The server root, read for its attachment base before the first attachment fetch (spec §7.1).
                url == "$base/" -> {
                    ok("""{"capabilities":{"attachments":{"base_url":"$attachments"}}}""", *headers)
                }

                url.startsWith(attachments) -> {
                    bodies[url.removePrefix(attachments)]?.let { response(200, it, *headers) } ?: response(404)
                }

                else -> {
                    response(404)
                }
            }
        }
    }

    /** A storage whose reads and writes a test can fail, key by key. */
    protected class Faulty(
        val inner: RevoktStorage = RevoktStorage.inMemory(),
    ) : RevoktStorage by inner {
        var failWrite: (String) -> Throwable? = { null }
        var failRead: (String) -> Throwable? = { null }
        var failDelete: (String) -> Throwable? = { null }
        var hidden: (String) -> Boolean = { false }

        override fun read(name: String): ByteArray? {
            failRead(name)?.let { throw it }
            return if (hidden(name)) null else inner.read(name)
        }

        override fun delete(name: String) {
            failDelete(name)?.let { throw it }
            inner.delete(name)
        }

        override fun write(
            name: String,
            bytes: ByteArray,
        ) {
            failWrite(name)?.let { throw it }
            inner.write(name, bytes)
        }
    }

    protected val storage = Faulty()
    protected val store = StoreLayout(storage, Dataset.CRLITE, CrliteChannel.COMPAT)
    protected val recording = UpdateFixtures.Recording()

    /** The sync's logger: [recording], unless a test makes it throw on a message. */
    protected var throwOn: (String) -> Throwable? = { null }
    protected val logger =
        RevoktLogger { level, message, cause ->
            throwOn(message)?.let { throw it }
            recording.log(level, message, cause)
        }
    protected val snapshot =
        SnapshotRef(
            GenerationSnapshot(
                0,
                mapOf(Dataset.CRLITE to DatasetGeneration(null, null, false, null, null, false, false)),
                null,
            ),
        )

    protected fun sync(
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
            logger,
        ).syncOnce(now)

    protected fun SyncRun.assert(
        outcome: SyncOutcome,
        stage: SyncStage? = null,
        vararg codes: DiagnosticCode,
    ): SyncRun {
        assertEquals(outcome to stage, result.outcome to result.stage, "$result")
        assertEquals(codes.toList(), result.warnings.map { it.code }, "$result")
        return this
    }

    /** A failure's warnings: `SYNC_FAILED`, then [codes]. */
    protected fun failed(vararg codes: DiagnosticCode): Array<DiagnosticCode> =
        arrayOf(DiagnosticCode.SYNC_FAILED, *codes)

    protected fun updater(now: Long = ts + hour): UpdaterRecord =
        (store.updater(now) as? StoreRead.Found)?.value?.record ?: UpdaterRecord()

    protected fun sourceRecord(now: Long = ts + hour): SourceRecord = updater(now).sources.getValue(source.sourceId)

    protected fun live(): DatasetGeneration = snapshot.snapshot.datasets.getValue(Dataset.CRLITE)

    protected fun liveDirectory(): String? = (store.pointer() as? StoreRead.Found)?.value?.live

    /** Nothing advanced: no cursor, no `lastVerified*`, no watermark, no pointer; the attempt written, one failure. */
    protected fun assertNothingAdvanced(
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
}
