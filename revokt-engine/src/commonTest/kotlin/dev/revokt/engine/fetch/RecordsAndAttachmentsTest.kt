// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.fetch

import dev.revokt.CrliteChannel
import dev.revokt.DiagnosticCode
import dev.revokt.MozillaRemoteSettings
import dev.revokt.RevoktLimits
import dev.revokt.SyncStage
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The collection schema check, the channel filter and the record cap (spec §7.1, §6.3 "Hardening", §5.1
 * `MAX_CHANGESET_RECORDS`, §9 `data-path (g)`), and the attachment fetch (§5.1 `MAX_FILTER_BYTES`, `ATTACHMENT`).
 */
class RecordsAndAttachmentsTest {
    private val body = "a CRLite filter".encodeToByteArray()
    private val hash = body.toByteString().sha256().hex()

    /** A `cert-revocations` record shaped as the live collection's (2026-11-07), with [patch] merged over its members. */
    private fun record(
        id: String = "ed453ef9-602d-421b-9c5d-83930d58a34c",
        channel: String = "default",
        incremental: Boolean = true,
        attachment: String = attachment(),
        extra: String = "",
    ): String =
        """{"id":"$id","channel":"$channel","incremental":$incremental,
            ${if (incremental) "\"parent\":\"0d16fcf7-cffd-45a8-961c-285c64b3602c\"," else ""}
            "effectiveTimestamp":1793969677000,"last_modified":1793980622465,"schema":1793980025745,
            "details":{"name":"2026-11-06T12:54:37+00:00Z-diff"},"filter_expression":"x",
            "attachment":$attachment$extra}"""

    private fun attachment(
        filename: String = "20261106-1-default.filter.delta",
        hash: String = this.hash,
        size: String = body.size.toString(),
        location: String = "security-state-staging/cert-revocations/20261106154706--ed453ef9.delta",
    ): String =
        """{"hash":"$hash","size":$size,"filename":"$filename","location":"$location","mimetype":"application/x-protobuf"}"""

    private fun check(
        vararg records: String,
        channel: CrliteChannel = CrliteChannel.DEFAULT,
    ): ClientResult<List<CrliteRecord>> =
        client(ScriptedFetcher { error("the record check fetches nothing") }).checkRecords(records.map(::json), channel)

    private fun rejected(vararg records: String) {
        val failed = check(*records).assertFailed(SyncStage.SCHEMA, ClientFailure.SCHEMA)
        assertEquals(DiagnosticCode.SYNC_SCHEMA_REJECTED, failed.code)
        assertNull(failed.httpStatus)
    }

    @Test
    fun `a live-shaped delta and full pass, typed as the signed record declares them`() {
        val delta = check(record()).assertOk().single()
        assertEquals("ed453ef9-602d-421b-9c5d-83930d58a34c", delta.id)
        assertEquals(true to "0d16fcf7-cffd-45a8-961c-285c64b3602c", delta.incremental to delta.parent)
        assertEquals(1793969677000, delta.effectiveTimestamp)
        assertEquals("20261106-1-default.filter.delta", delta.attachment.filename)
        assertEquals(hash, delta.attachment.sha256.hex())
        assertEquals(body.size.toLong(), delta.attachment.size)
        // Mozilla's fulls carry no parent.
        val full =
            check(
                record(incremental = false, extra = ""","coverage":[],"enrolledIssuers":[]"""),
            ).assertOk().single()
        assertEquals(false to null, full.incremental to full.parent)
        val fullWithParent = check(record(incremental = false, extra = ""","parent":"p"""")).assertOk().single()
        assertEquals("p", fullWithParent.parent)
    }

    @Test
    fun `data-path (g) an intermediates changeset on the cert-revocations URL is SYNC_SCHEMA_REJECTED at SCHEMA`() {
        // The shape of Mozilla's security-state/intermediates records (the corpus changeset, revokt-corpus).
        val intermediate =
            """{"schema":1792767600380,"derHash":"EmW5f+rzuC5XDD8JtLTqlMNK2m253Wa2Iq8f2wg96Ck=",
                "attachment":{"hash":"96ef47e108b2bf0b6156f5b22ec6ab5e6a7fc7eaed9a51acee44cd1ec2622df4","size":2247,
                  "filename":"aZdqNe5RmxZVjOpmYQBC5_un_r_Do0BdTy92bgU-lI4=.pem",
                  "location":"security-state-staging/intermediates/x.pem","mimetype":"application/x-pem-file"},
                "id":"53279a21-f633-432a-b73b-0b7f38f730c1","last_modified":1792771022925}"""
        rejected(intermediate)
        rejected(record(), intermediate)
    }

    @Test
    fun `every schema field is required and typed`() {
        val missing =
            listOf(
                record().replace("\"channel\":\"default\",", ""),
                record().replace("\"incremental\":true,", ""),
                record().replace("\"effectiveTimestamp\":1793969677000,", ""),
                record().replace("\"parent\":\"0d16fcf7-cffd-45a8-961c-285c64b3602c\",", ""),
                record().replace("\"id\":\"ed453ef9-602d-421b-9c5d-83930d58a34c\",", ""),
                record(attachment = attachment().replace("\"filename\":\"20261106-1-default.filter.delta\",", "")),
                record(attachment = attachment().replace("\"hash\":\"$hash\",", "")),
                record(attachment = attachment().replace("\"size\":${body.size},", "")),
                record(
                    attachment =
                        attachment().replace(
                            ",\"location\":\"security-state-staging/cert-revocations/20261106154706--ed453ef9.delta\"",
                            "",
                        ),
                ),
            )
        for (r in missing) rejected(r)
        val mistyped =
            listOf(
                record().replace("\"channel\":\"default\"", "\"channel\":1"),
                record().replace("\"incremental\":true", "\"incremental\":\"true\""),
                record().replace("\"incremental\":true", "\"incremental\":1"),
                record().replace("\"effectiveTimestamp\":1793969677000", "\"effectiveTimestamp\":1793969677000.0"),
                record().replace("\"effectiveTimestamp\":1793969677000", "\"effectiveTimestamp\":-1"),
                record().replace("\"effectiveTimestamp\":1793969677000", "\"effectiveTimestamp\":\"1793969677000\""),
                record().replace("\"parent\":\"0d16fcf7-cffd-45a8-961c-285c64b3602c\"", "\"parent\":null"),
                record(incremental = false, extra = ""","parent":7"""),
                record().replace("\"id\":\"ed453ef9-602d-421b-9c5d-83930d58a34c\"", "\"id\":5"),
                record(attachment = "[]"),
                record(attachment = "null"),
                record(attachment = attachment(hash = hash.uppercase())),
                record(attachment = attachment(hash = hash.dropLast(1))),
                record(attachment = attachment(hash = hash + "0")),
                record(attachment = attachment(hash = "g" + hash.drop(1))),
                record(attachment = attachment(size = "-1")),
                record(attachment = attachment(size = "15.0")),
                record(attachment = attachment(size = "\"15\"")),
                record(attachment = attachment(size = "18446744073709551615")),
                record(attachment = attachment(location = "")),
                record(
                    attachment =
                        attachment().replace(
                            "\"filename\":\"20261106-1-default.filter.delta\"",
                            "\"filename\":1",
                        ),
                ),
                record(
                    attachment =
                        attachment()
                            .replace(
                                "\"location\":\"security-state",
                                "\"location\":[\"security-state",
                            ).replace(".delta\",\"mimetype", ".delta\"],\"mimetype"),
                ),
            )
        for (r in mistyped) rejected(r)
    }

    @Test
    fun `a filename outside the §6_3 rule is SYNC_SCHEMA_REJECTED at SCHEMA, and a 64-character one passes`() {
        for (name in listOf(
            "",
            ".",
            "..",
            "a/b",
            "../x",
            "a b",
            "a\\\\b",
            "filtér",
            "a:b",
            "x".repeat(65),
            "a\\u0000b",
        )) {
            rejected(record(attachment = attachment(filename = name)))
        }
        for (name in listOf("x".repeat(64), "...", ".hidden", "a..b", "A-Z_a.z-09", "-", "_")) {
            assertEquals(
                name,
                check(record(attachment = attachment(filename = name)))
                    .assertOk()
                    .single()
                    .attachment.filename,
            )
        }
    }

    @Test
    fun `a reserved name, index_bin included, is SYNC_SCHEMA_REJECTED, compared exactly`() {
        for (name in listOf(
            "index.bin",
            "meta.json",
            "records.json",
            "current",
            "updater.json",
            "store.version",
            ".lock",
        )) {
            rejected(record(attachment = attachment(filename = name)))
        }
        // Only a C2SP mirror's manifest names are compared ignoring case (§6.3, §7.3).
        check(record(attachment = attachment(filename = "Index.bin"))).assertOk()
        assertEquals(7, AttachmentName.RESERVED.size)
    }

    @Test
    fun `the channel filter keeps the requested channel's records after checking every record`() {
        val compat = record(id = "c", channel = "compat")
        val other = record(id = "o", channel = "experimental")
        assertEquals(listOf("d"), check(record(id = "d"), compat, other).assertOk().map { it.id })
        assertEquals(
            listOf(
                "c",
            ),
            check(record(id = "d"), compat, other, channel = CrliteChannel.COMPAT).assertOk().map {
                it.id
            },
        )
        // A failing record of another channel still fails the whole set.
        rejected(
            record(id = "d"),
            record(id = "c", channel = "compat", attachment = attachment(filename = "index.bin")),
        )
        // The channel names are compared exactly.
        assertEquals(emptyList(), check(record(channel = "DEFAULT")).assertOk())
    }

    @Test
    fun `more than MAX_CHANGESET_RECORDS after channel filtering is FAILED before any body fetch`() {
        val cap = RevoktLimits.MAX_CHANGESET_RECORDS
        val defaults = List(cap) { record(id = "d$it") }
        val compats = List(cap + 1) { record(id = "c$it", channel = "compat") }
        assertEquals(cap, check(*(defaults + compats).toTypedArray()).assertOk().size)
        val failed =
            check(*(defaults + compats).toTypedArray(), channel = CrliteChannel.COMPAT)
                .assertFailed(SyncStage.CHANGESET, ClientFailure.TOO_MANY_RECORDS)
        assertNull(failed.code)
        val raised = FetchLimits(maxChangesetRecords = cap + 1)
        val ok =
            client(ScriptedFetcher { error("unused") }, limits = raised)
                .checkRecords(compats.map(::json), CrliteChannel.COMPAT)
        assertEquals(cap + 1, ok.assertOk().size)
    }

    private fun crlite(
        size: Long = body.size.toLong(),
        location: String = "security-state-staging/cert-revocations/x.delta",
        sha256: String = hash,
    ): CrliteRecord =
        check(
            record(attachment = attachment(size = size.toString(), location = location, hash = sha256)),
        ).assertOk().single()

    @Test
    fun `an attachment is fetched from attachmentBaseUrl and its relative location with exactly one slash`() {
        val cdn = "https://firefox-settings-attachments.cdn.mozilla.net"
        val path = "security-state-staging/cert-revocations/x.delta"
        for ((base, location) in listOf("$cdn/" to path, cdn to path, "$cdn//" to "/$path")) {
            val fetcher = ScriptedFetcher { response(200, body) }
            val source =
                MozillaRemoteSettings.DEFAULT
                    .newBuilder()
                    .attachmentBaseUrl(base)
                    .build()
            assertEquals(
                body.toByteString(),
                client(fetcher, source).fetchAttachment(crlite(location = location)).assertOk(),
            )
            val request = fetcher.requests.single()
            assertEquals(
                "https://firefox-settings-attachments.cdn.mozilla.net/security-state-staging/cert-revocations/x.delta",
                request.url,
            )
            assertEquals(mapOf("User-Agent" to "revokt"), request.headers)
            // The cap is min(attachment.size, MAX_FILTER_BYTES): the signed size here.
            assertEquals(body.size.toLong(), request.maxBodyBytes)
        }
    }

    @Test
    fun `an attachment whose hash or size differs from the signed record is FAILED at ATTACHMENT`() {
        val flipped = body.copyOf().also { it[0] = (it[0] + 1).toByte() }
        client(ScriptedFetcher { response(200, flipped) })
            .fetchAttachment(crlite())
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.ATTACHMENT_HASH)
        client(ScriptedFetcher { response(200, body.copyOf(body.size - 1)) })
            .fetchAttachment(crlite())
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.ATTACHMENT_SIZE)
        client(ScriptedFetcher { response(200, body + 0) })
            .fetchAttachment(crlite())
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.BODY_TOO_LARGE)
        // The right bytes under a wrong signed hash fail too.
        client(ScriptedFetcher { response(200, body) })
            .fetchAttachment(crlite(sha256 = "0".repeat(64)))
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.ATTACHMENT_HASH)
        // An empty attachment is checked the same way.
        val empty = ByteArray(0).toByteString().sha256().hex()
        assertEquals(
            0,
            client(
                ScriptedFetcher {
                    response(200)
                },
            ).fetchAttachment(crlite(size = 0, sha256 = empty)).assertOk().size,
        )
    }

    @Test
    fun `a signed size above MAX_FILTER_BYTES is FAILED with CAP_NEAR_LIMIT before any fetch`() {
        val fetcher = ScriptedFetcher { response(200, body) }
        val failed =
            client(fetcher)
                .fetchAttachment(crlite(size = RevoktLimits.MAX_FILTER_BYTES + 1))
                .assertFailed(SyncStage.ATTACHMENT, ClientFailure.ATTACHMENT_OVER_CAP)
        assertEquals(DiagnosticCode.CAP_NEAR_LIMIT, failed.code)
        assertEquals(0, fetcher.requests.size)
        // At the cap the fetch runs, capped at the signed size.
        client(fetcher)
            .fetchAttachment(crlite(size = RevoktLimits.MAX_FILTER_BYTES))
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.ATTACHMENT_SIZE)
        assertEquals(RevoktLimits.MAX_FILTER_BYTES, fetcher.requests.single().maxBodyBytes)
        // A raised cap admits it.
        val raised = FetchLimits(maxFilterBytes = RevoktLimits.MAX_FILTER_BYTES + 1)
        client(fetcher, limits = raised)
            .fetchAttachment(crlite(size = RevoktLimits.MAX_FILTER_BYTES + 1))
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.ATTACHMENT_SIZE)
        assertEquals(2, fetcher.requests.size)
    }

    @Test
    fun `the attachment fetch carries stage ATTACHMENT, its status and Backoff on every failure`() {
        val failed =
            client(ScriptedFetcher { response(401, headers = arrayOf("Retry-After" to "3")) })
                .fetchAttachment(crlite())
                .assertFailed(SyncStage.ATTACHMENT, ClientFailure.HTTP_STATUS)
        assertEquals(401 to 3_000L, failed.httpStatus to failed.backoffMillis)
        client(
            ScriptedFetcher {
                response(302)
            },
        ).fetchAttachment(crlite()).assertFailed(SyncStage.ATTACHMENT, ClientFailure.HTTP_STATUS)
        client(ScriptedFetcher { throw IllegalStateException() })
            .fetchAttachment(crlite())
            .assertFailed(SyncStage.ATTACHMENT, ClientFailure.FETCHER_THREW)
        assertTrue(crlite().toString().contains(hash))
    }

    @Test
    fun `the schema check reads the merged set, so a tombstone that reaches it is rejected`() {
        rejected("""{"id":"x","last_modified":1,"deleted":true}""")
        assertEquals(emptyList(), check().assertOk())
    }
}
