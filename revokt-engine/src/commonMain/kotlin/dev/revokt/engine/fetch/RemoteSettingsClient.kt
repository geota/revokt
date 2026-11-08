// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.RevoktTestingApi
import dev.revokt.SyncStage
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonParseException
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.json.JsonValue
import kotlinx.coroutines.CoroutineDispatcher
import okio.ByteString

/**
 * The caps and the deadline one client fetches under (spec §5.1 limits). Caps are overridable upward only, as the
 * builder's `limits { }` is (§4: a lower value throws).
 */
internal data class FetchLimits(
    val maxJsonBytes: Long = RevoktLimits.MAX_JSON_BYTES,
    val maxX5uBytes: Long = RevoktLimits.MAX_X5U_BYTES,
    val maxFilterBytes: Long = RevoktLimits.MAX_FILTER_BYTES,
    val maxChangesetRecords: Int = RevoktLimits.MAX_CHANGESET_RECORDS,
    val fetchTimeoutMillis: Long = RevoktLimits.FETCH_TIMEOUT,
) {
    init {
        require(maxJsonBytes >= RevoktLimits.MAX_JSON_BYTES) { "maxJsonBytes below MAX_JSON_BYTES: $maxJsonBytes" }
        require(maxX5uBytes >= RevoktLimits.MAX_X5U_BYTES) { "maxX5uBytes below MAX_X5U_BYTES: $maxX5uBytes" }
        require(
            maxFilterBytes >= RevoktLimits.MAX_FILTER_BYTES,
        ) { "maxFilterBytes below MAX_FILTER_BYTES: $maxFilterBytes" }
        require(maxChangesetRecords >= RevoktLimits.MAX_CHANGESET_RECORDS) {
            "maxChangesetRecords below MAX_CHANGESET_RECORDS: $maxChangesetRecords"
        }
        require(fetchTimeoutMillis > 0) { "fetchTimeoutMillis must be positive, got $fetchTimeoutMillis" }
    }
}

/**
 * One collection's changeset as served (spec §7.1), nothing in it verified yet. [timestamp] is the envelope's
 * `timestamp`, the `<ts>` the content-signature payload is built with (`"last_modified": "<ts>"`, as Firefox builds it
 * and as Mozilla's signature over the corpus changeset verifies, #163): it is the signed `<ts>` once, and only once,
 * the signature verifies over it. No other timestamp of the envelope (`metadata.last_modified`, a record's
 * `last_modified`) is read. [signature], [x5u] and [mode] are exactly `metadata.signature`'s three fields (§4, §7.1;
 * the live collection also carries a `metadata.signatures` array, which is not read), null when absent or not a string.
 */
internal class Changeset(
    val timestamp: Long,
    val changes: List<JsonObject>,
    val signature: String?,
    val x5u: String?,
    val mode: String?,
) {
    override fun toString(): String = "Changeset(timestamp=$timestamp, ${changes.size} changes, x5u=$x5u, mode=$mode)"
}

/**
 * The Remote Settings client of spec §7.1 for one [dataset] of one [source], over the §3 fetch seam. Call-driven: the
 * schedule (#147), verification (#137), the reset-and-retry and deltas (#141) and the backoff persistence (#131) are
 * its callers'. Only `monitor/changes` and the collection's `changeset` are requested, plus the x5u chain and the
 * attachments.
 *
 * Every request carries `User-Agent` ([MozillaRemoteSettings.userAgent]); a changeset fetch from a cursor also carries
 * `If-None-Match` as the quoted cursor, synthesised, never an echoed ETag; no request carries `Accept-Encoding` (the
 * fetcher decodes gzip itself, §3). Every fetch runs on [io] under [FetchLimits.fetchTimeoutMillis] ([fetchWithin]), and
 * its body is re-checked against the request's cap before anything reads it. A 304 is [ClientResult.Unchanged] only
 * for the conditional changeset fetch; any other status but 200 is `FAILED` with the status, so a 3xx is never followed
 * and a 401 or 407 never answered. Every result is a [ClientResult], never a throw: a fetcher's throwable is `FAILED`
 * with it as the cause (§3), and only a fault in revokt's own code here propagates, to the loader's catch (§6.5).
 *
 * URLs join a base and a path with exactly one `/` ([joinUrl]), for [MozillaRemoteSettings.baseUrl] and for
 * [MozillaRemoteSettings.attachmentBaseUrl] with `attachment.location` alike (#177).
 */
@OptIn(RevoktTestingApi::class) // FetchRequest has no constructor but its Builder.
internal class RemoteSettingsClient(
    private val source: MozillaRemoteSettings,
    private val dataset: Dataset,
    private val fetcher: HttpFetcher,
    private val io: CoroutineDispatcher,
    private val limits: FetchLimits = FetchLimits(),
) {
    private val collection: String =
        requireNotNull(source.collection(dataset)) { "${source.sourceId} has no collection for $dataset" }

    /**
     * The collection's timestamp as `monitor/changes` lists it, the `_expected` for [fetchChangeset]. The request
     * carries `_expected=0` (mandatory, §7.1; this poll has no expectation of its own). The listed `last_modified` must
     * be an integer from 0 to `Long.MAX_VALUE`, so only an integer ever enters the changeset's query string; a body
     * that lists the collection other than once is `FAILED` (`MALFORMED`).
     */
    fun pollChanges(): ClientResult<Long> {
        val url = joinUrl(source.baseUrl, "buckets/monitor/collections/changes/changeset?_expected=0")
        val body =
            when (val exchange = exchange(SyncStage.CHANGESET, url, limits.maxJsonBytes, cursor = null)) {
                is Exchange.Ended -> return exchange.result
                is Exchange.Body -> exchange
            }
        val changes =
            envelope(body.bytes)?.let { it["changes"] as? JsonArray }
                ?: return malformed(body, "monitor/changes is not a changeset")
        val listed =
            changes.items.filter {
                it is JsonObject && string(it["bucket"]) == source.bucket && string(it["collection"]) == collection
            }
        if (listed.size != 1) {
            return malformed(body, "monitor/changes lists ${source.bucket}/$collection ${listed.size} times")
        }
        val expected =
            count((listed.single() as JsonObject)["last_modified"])
                ?: return malformed(body, "last_modified is not an integer ≥ 0")
        return ClientResult.Ok(expected, body.status, body.backoffMillis)
    }

    /**
     * The collection's changeset at [expected] (`_expected`, mandatory), the whole collection when [since] is null, else
     * the changes after the verified cursor [since] (`_since=<since>`, bare, as Firefox's `RemoteSettingsClient` sends
     * it at `cac25a6fa321b0051932359b84c4e2fe3caabdc5`, and `If-None-Match: "<since>"`, quoted, as §3 says; a 304 is
     * [ClientResult.Unchanged]). The body is parsed with the engine's JSON tree under `MAX_JSON_BYTES`; its `changes`
     * are objects and its `timestamp` an integer from 0 to `Long.MAX_VALUE`, else `FAILED` (`MALFORMED`). Nothing in it
     * is trusted until #137 verifies it.
     */
    fun fetchChangeset(
        expected: Long,
        since: Long?,
    ): ClientResult<Changeset> {
        if (expected < 0 || (since != null && since < 0)) {
            return ClientResult.Failed(
                SyncStage.CHANGESET,
                ClientFailure.QUERY_VALUE,
                "_expected $expected, _since $since: not integers ≥ 0",
            )
        }
        val query = "?_expected=$expected" + (since?.let { "&_since=$it" } ?: "")
        val url = joinUrl(source.baseUrl, "buckets/${source.bucket}/collections/$collection/changeset$query")
        val body =
            when (val exchange = exchange(SyncStage.CHANGESET, url, limits.maxJsonBytes, cursor = since)) {
                is Exchange.Ended -> return exchange.result
                is Exchange.Body -> exchange
            }
        val root =
            envelope(body.bytes)
                ?: return malformed(body, "the body is not a JSON object")
        val changes =
            (root["changes"] as? JsonArray)?.items?.map {
                it as? JsonObject
                    ?: return malformed(body, "a change is not an object")
            }
                ?: return malformed(body, "changes is not an array")
        val timestamp = count(root["timestamp"]) ?: return malformed(body, "timestamp is not an integer ≥ 0")
        val fields = ((root["metadata"] as? JsonObject)?.get("signature") as? JsonObject) ?: JsonObject.EMPTY
        val changeset =
            Changeset(timestamp, changes, string(fields["signature"]), string(fields["x5u"]), string(fields["mode"]))
        return ClientResult.Ok(changeset, body.status, body.backoffMillis)
    }

    /**
     * The x5u chain's bytes from [url], the changeset's unsigned `x5u` (spec §7.1): [X5uUrl]'s rules first, the
     * rewrite included, and nothing is fetched when one fails; then the fetch, capped at `MAX_X5U_BYTES`. Stage `X5U`.
     */
    fun fetchX5u(url: String): ClientResult<ByteString> {
        val checked = X5uUrl.check(url, source.x5uHosts, source.x5uHostRewrites)
        val allowed =
            checked.url
                ?: return ClientResult.Failed(
                    SyncStage.X5U,
                    ClientFailure.X5U_URL,
                    "${checked.failure}: ${checked.detail}",
                )
        return when (val exchange = exchange(SyncStage.X5U, allowed, limits.maxX5uBytes, cursor = null)) {
            is Exchange.Ended -> exchange.result
            is Exchange.Body -> ClientResult.Ok(exchange.bytes, exchange.status, exchange.backoffMillis)
        }
    }

    /**
     * Schema-checks [records], the verified and merged set (tombstones removed), for this client's collection
     * ([CrliteSchema]), then keeps [channel]'s. A failing record is `FAILED` at `SCHEMA` (`SYNC_SCHEMA_REJECTED`, §7.1),
     * a §6.3 filename failure included (the issue's reading: 2690 puts the filename "under §6.3's rule" in the schema);
     * more than `MAX_CHANGESET_RECORDS` kept records is `FAILED` at `CHANGESET`, before any body fetch. Fetches nothing.
     */
    fun checkRecords(
        records: List<JsonObject>,
        channel: CrliteChannel,
    ): ClientResult<List<CrliteRecord>> =
        when (val check = CrliteSchema.check(records, channel, limits.maxChangesetRecords)) {
            is RecordCheck.Passed -> {
                ClientResult.Ok(check.records, null, null)
            }

            is RecordCheck.Rejected -> {
                if (check.index == null) {
                    ClientResult.Failed(SyncStage.CHANGESET, ClientFailure.TOO_MANY_RECORDS, check.detail)
                } else {
                    ClientResult.Failed(SyncStage.SCHEMA, ClientFailure.SCHEMA, "$dataset: ${check.detail}")
                }
            }
        }

    /**
     * [record]'s attachment from `attachmentBaseUrl` + its relative `location`, capped at `min(attachment.size,
     * MAX_FILTER_BYTES)` (spec §5.1). A declared size above `MAX_FILTER_BYTES` is `FAILED` before any fetch
     * (`CAP_NEAR_LIMIT`, #137); the body's size and SHA-256 must equal the signed record's. Stage `ATTACHMENT`.
     * [record] comes from [checkRecords] over a changeset whose signature verified: its size and hash are only as
     * trustworthy as that.
     */
    fun fetchAttachment(record: CrliteRecord): ClientResult<ByteString> {
        val attachment = record.attachment
        if (attachment.size > limits.maxFilterBytes) {
            return ClientResult.Failed(
                SyncStage.ATTACHMENT,
                ClientFailure.ATTACHMENT_OVER_CAP,
                "${record.id}: ${attachment.size} bytes declared, cap ${limits.maxFilterBytes}",
            )
        }
        val url = joinUrl(source.attachmentBaseUrl, attachment.location)
        val body =
            when (val exchange = exchange(SyncStage.ATTACHMENT, url, attachment.size, cursor = null)) {
                is Exchange.Ended -> return exchange.result
                is Exchange.Body -> exchange
            }
        if (body.bytes.size.toLong() != attachment.size) {
            return body.failed(
                SyncStage.ATTACHMENT,
                ClientFailure.ATTACHMENT_SIZE,
                "${record.id}: ${body.bytes.size} bytes, signed size ${attachment.size}",
            )
        }
        if (body.bytes.sha256() != attachment.sha256) {
            return body.failed(
                SyncStage.ATTACHMENT,
                ClientFailure.ATTACHMENT_HASH,
                "${record.id}: SHA-256 differs from the signed hash",
            )
        }
        return ClientResult.Ok(body.bytes, body.status, body.backoffMillis)
    }

    private sealed class Exchange {
        /** A 200 whose body is within the request's cap. */
        class Body(
            val bytes: ByteString,
            val status: Int,
            val backoffMillis: Long?,
        ) : Exchange() {
            fun failed(
                stage: SyncStage,
                failure: ClientFailure,
                detail: String,
            ): ClientResult.Failed = ClientResult.Failed(stage, failure, detail, status, null, backoffMillis)
        }

        class Ended(
            val result: ClientResult<Nothing>,
        ) : Exchange()
    }

    /**
     * One request to [url] under [maxBodyBytes]; [cursor] makes it conditional. Header values are checked before the
     * fetch: a CR or LF is `FAILED`, never sanitised (#177).
     */
    private fun exchange(
        stage: SyncStage,
        url: String,
        maxBodyBytes: Long,
        cursor: Long?,
    ): Exchange {
        val request =
            FetchRequest
                .Builder()
                .url(url)
                .header("User-Agent", source.userAgent)
                .apply { if (cursor != null) header("If-None-Match", "\"$cursor\"") }
                .maxBodyBytes(maxBodyBytes)
                .timeoutMillis(limits.fetchTimeoutMillis)
                .build()
        for ((name, value) in request.headers) {
            if ('\r' in value || '\n' in value) {
                return end(ClientResult.Failed(stage, ClientFailure.HEADER_VALUE, "$name holds a CR or LF"))
            }
        }
        val response: FetchResponse =
            when (val timed = fetchWithin(io, request.timeoutMillis) { fetcher.fetch(request) }) {
                is Timed.Done -> {
                    timed.response
                        ?: return end(
                            ClientResult.Failed(stage, ClientFailure.FETCHER_THREW, "the fetcher returned null"),
                        )
                }

                is Timed.Threw -> {
                    return end(
                        ClientResult.Failed(
                            stage,
                            ClientFailure.FETCHER_THREW,
                            "the fetcher threw",
                            cause = timed.cause,
                        ),
                    )
                }

                Timed.TimedOut -> {
                    return end(
                        ClientResult.Failed(
                            stage,
                            ClientFailure.TIMEOUT,
                            "no response within ${request.timeoutMillis} ms",
                        ),
                    )
                }
            }
        val status = response.status
        val backoff = Backoff.read(response)
        if (status == ClientResult.NOT_MODIFIED && cursor != null) return end(ClientResult.Unchanged(backoff))
        if (status != ClientResult.OK) {
            return end(ClientResult.Failed(stage, ClientFailure.HTTP_STATUS, "status $status", status, null, backoff))
        }
        val bytes = response.bodyBytes
        if (bytes.size > maxBodyBytes) {
            return end(
                ClientResult.Failed(
                    stage,
                    ClientFailure.BODY_TOO_LARGE,
                    "${bytes.size} bytes, cap $maxBodyBytes",
                    status,
                    null,
                    backoff,
                ),
            )
        }
        return Exchange.Body(bytes, status, backoff)
    }

    private fun end(result: ClientResult<Nothing>): Exchange = Exchange.Ended(result)

    /** [bytes] as a JSON object under `MAX_JSON_BYTES`, or null when it is not one. */
    private fun envelope(bytes: ByteString): JsonObject? =
        try {
            Json.parse(bytes.toByteArray(), limits.maxJsonBytes) as? JsonObject
        } catch (ignored: JsonParseException) {
            null
        }

    /** The changeset or `monitor/changes` body is not the envelope: `FAILED` at `CHANGESET` with the response's status. */
    private fun malformed(
        body: Exchange.Body,
        detail: String,
    ): ClientResult.Failed = body.failed(SyncStage.CHANGESET, ClientFailure.MALFORMED, detail)

    private fun string(value: JsonValue?): String? = (value as? JsonString)?.value

    private fun count(value: JsonValue?): Long? = (value as? JsonInteger)?.takeIf { !it.negative }?.toLongOrNull()
}

/**
 * [base] and [path] with exactly one `/` between them, whatever slashes either brings (#177: one rule for `baseUrl` and
 * for `attachmentBaseUrl` with `attachment.location`).
 */
internal fun joinUrl(
    base: String,
    path: String,
): String = base.trimEnd('/') + "/" + path.trimStart('/')
