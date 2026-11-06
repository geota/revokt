// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonInteger
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.parse.producer.ExternalCorpus
import dev.revokt.verify.JcaFixtures.flip
import dev.revokt.verify.JcaSignatureVerifier
import okio.ByteString.Companion.toByteString
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The payload builder against recorded changesets (spec §7.1, §9 "canonical JSON against `canonical_json`"): its
 * `records.json` for a changeset is the payload `canonical_json` 0.7.0 produced (#92's `remote-settings.tsv`), and
 * Mozilla's own signature over the large corpus's intermediates changeset verifies through [ContentSignature] under
 * the SPKI of the x5u leaf that served it (`mozilla-content-signing-c0.der`, the committed `onecrl` leaf). It proves
 * the bytes and the signature check, not the chain, which is #126's.
 */
class ContentSignatureCorpusTest {
    private fun resource(path: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream(path)) { "missing $path" }.use { it.readBytes() }

    private val verifier = JcaSignatureVerifier()

    private class Changeset(
        val tree: JsonObject,
    ) {
        val changes = (tree["changes"] as JsonArray).items.map { it as JsonObject }
        val timestamp = checkNotNull((tree["timestamp"] as JsonInteger).toLongOrNull())
        private val signature = (tree["metadata"] as JsonObject)["signature"] as JsonObject
        val text = (signature["signature"] as JsonString).value
        val mode = (signature["mode"] as JsonString).value
        val recordsJson =
            checkNotNull(
                ContentSignature.recordsJson(checkNotNull(ContentSignature.merge(emptyList(), changes)), timestamp),
            )
    }

    private fun assertRecorded(
        file: String,
        changeset: Changeset,
    ) {
        val row =
            resource("/dev/revokt/engine/json/remote-settings.tsv")
                .decodeToString()
                .lines()
                .map { it.split("\t") }
                .single { it[0] == file && it.getOrNull(2) == "payload" }
        assertEquals(
            row[3] to row[4].toInt(),
            changeset.recordsJson
                .toByteString()
                .sha256()
                .hex() to changeset.recordsJson.size,
            file,
        )
    }

    @Test
    fun `records json of the synthetic CRLite changeset, its tombstone removed, is canonical_json's payload`() {
        val changeset = Changeset(Json.parse(resource("/dev/revokt/engine/json/crlite-changeset.json")) as JsonObject)
        assertTrue(changeset.changes.any { it["deleted"] != null }, "the synthetic changeset carries a tombstone")
        assertRecorded("crlite-changeset.json", changeset)
    }

    @Test
    fun `Mozilla's signature over the corpus intermediates changeset verifies, and a flipped byte does not`() {
        val dir =
            ExternalCorpus.dir ?: return println("content signature: no large corpus on this run (-Prevokt.corpus)")
        val file = "issuer/mozilla-intermediates/changeset.json"
        val changeset = Changeset(Json.parse(File(dir, file).readBytes()) as JsonObject)
        assertRecorded(file, changeset)
        val leaf =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificate(
                    resource("/dev/revokt/engine/parse/certs/mozilla-content-signing-c0.der").inputStream(),
                )
                as X509Certificate
        val spki = leaf.publicKey.encoded
        val records = checkNotNull(ContentSignature.merge(emptyList(), changeset.changes))
        assertTrue(
            ContentSignature
                .verifyRecords(
                    verifier,
                    records,
                    changeset.timestamp,
                    changeset.text,
                    changeset.mode,
                    spki,
                ).verified,
        )
        assertTrue(
            ContentSignature
                .verifyRawPayload(
                    verifier,
                    changeset.recordsJson,
                    changeset.text,
                    changeset.mode,
                    spki,
                ).verified,
        )
        val body = changeset.recordsJson
        for (i in listOf(0, 1, body.size / 2, body.size - 2, body.size - 1)) {
            assertEquals(
                ContentSignatureFailure.INVALID,
                ContentSignature
                    .verifyRawPayload(
                        verifier,
                        flip(body, i),
                        changeset.text,
                        changeset.mode,
                        spki,
                    ).failure,
                "byte $i",
            )
        }
        assertEquals(
            ContentSignatureFailure.INVALID,
            ContentSignature
                .verifyRecords(
                    verifier,
                    records,
                    changeset.timestamp + 1,
                    changeset.text,
                    changeset.mode,
                    spki,
                ).failure,
        )
        assertEquals(
            ContentSignatureFailure.INVALID,
            ContentSignature
                .verifyRecords(
                    verifier,
                    records.drop(1),
                    changeset.timestamp,
                    changeset.text,
                    changeset.mode,
                    spki,
                ).failure,
        )
    }
}
