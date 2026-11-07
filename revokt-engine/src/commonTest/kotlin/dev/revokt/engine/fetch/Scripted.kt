// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.Dataset
import dev.revokt.FetchRequest
import dev.revokt.FetchResponse
import dev.revokt.HttpFetcher
import dev.revokt.MozillaRemoteSettings
import dev.revokt.SyncStage
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonObject
import kotlinx.coroutines.Dispatchers
import kotlin.test.assertEquals
import kotlin.test.assertIs

/** A scripted [HttpFetcher]: answers each request with [answer] and records every request it was handed. */
internal class ScriptedFetcher(
    private val answer: (FetchRequest) -> FetchResponse,
) : HttpFetcher {
    val requests = mutableListOf<FetchRequest>()

    override fun fetch(request: FetchRequest): FetchResponse {
        requests.add(request)
        return answer(request)
    }
}

internal fun response(
    status: Int,
    body: ByteArray = ByteArray(0),
    vararg headers: Pair<String, String>,
): FetchResponse =
    FetchResponse
        .Builder()
        .status(status)
        .body(body)
        .apply { for ((name, value) in headers) header(name, value) }
        .build()

internal fun ok(
    body: String,
    vararg headers: Pair<String, String>,
): FetchResponse = response(200, body.encodeToByteArray(), *headers)

internal fun client(
    fetcher: HttpFetcher,
    source: MozillaRemoteSettings = MozillaRemoteSettings.DEFAULT,
    limits: FetchLimits = FetchLimits(),
): RemoteSettingsClient = RemoteSettingsClient(source, Dataset.CRLITE, fetcher, Dispatchers.Default, limits)

internal fun json(text: String): JsonObject = Json.parse(text.encodeToByteArray()) as JsonObject

/** The result as a [ClientResult.Failed] at [stage] for [failure]. */
internal fun ClientResult<*>.assertFailed(
    stage: SyncStage,
    failure: ClientFailure,
): ClientResult.Failed {
    val failed = assertIs<ClientResult.Failed>(this, "expected $failure at $stage, got $this")
    assertEquals(stage to failure, failed.stage to failed.failure, failed.detail)
    return failed
}

internal fun <T> ClientResult<T>.assertOk(): T = assertIs<ClientResult.Ok<T>>(this, "expected Ok, got $this").value
