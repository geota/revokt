// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.json

import dev.revokt.engine.parse.producer.ExternalCorpus
import okio.ByteString.Companion.toByteString
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Spec §9 "canonical JSON against `canonical_json`" (#92): revokt's parser and canonical serialiser against the
 * goldens `canonical_json` 0.7.0 recorded (native/revokt-oracle/record-canonical-json.sh), byte for byte. Where the
 * oracle accepts, revokt produces the same bytes; where it rejects, revokt rejects. The one declared difference: an
 * object with a duplicated key, whose last member serde_json keeps and revokt rejects (spec §7.1).
 */
class CanonicalJsonOracleTest {
    private fun resource(name: String): ByteArray =
        checkNotNull(
            javaClass.getResourceAsStream("/dev/revokt/engine/json/$name"),
        ) { "missing $name" }.use { it.readBytes() }

    private fun rows(name: String): List<List<String>> =
        resource(name)
            .decodeToString()
            .lines()
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { it.split("\t") }

    private val b64 = Base64.getDecoder()

    private class Golden(
        val name: String,
        val input: ByteArray,
        val canonical: ByteArray?,
    )

    private val goldens =
        rows("canonical-json.tsv").map { f ->
            check(f.size == 4 && (f[2] == "OK" || f[2] == "ERR")) { "bad golden row ${f.firstOrNull()}" }
            Golden(f[0], b64.decode(f[1]), if (f[2] == "OK") b64.decode(f[3]) else null)
        }

    private fun revokt(input: ByteArray): Result<ByteArray> = runCatching { CanonicalJson.write(Json.parse(input)) }

    @Test
    fun `revokt agrees with canonical_json on every recorded input`() {
        val declared = mutableListOf<String>()
        for (g in goldens) {
            val ours = revokt(g.input)
            val error = (ours.exceptionOrNull() as? JsonParseException)?.error
            ours.exceptionOrNull()?.let { if (it !is JsonParseException) throw AssertionError(g.name, it) }
            when {
                g.canonical != null && ours.isSuccess -> assertContentEquals(g.canonical, ours.getOrThrow(), g.name)
                g.canonical != null && error == JsonError.DUPLICATE_KEY -> declared += g.name
                g.canonical != null -> fail("${g.name}: canonical_json accepts, revokt rejects with $error")
                ours.isSuccess -> fail("${g.name}: canonical_json rejects, revokt accepts")
            }
        }
        assertEquals(listOf("duplicate-same", "duplicate-escaped", "duplicate-nested", "duplicate-surrogate"), declared)
        assertTrue(goldens.count { it.name.startsWith("number-") } > 4000)
    }

    @Test
    fun `the goldens were recorded from the committed inputs`() {
        val curated =
            rows("canonical-json-inputs.tsv").map { (name, form, data) ->
                name to if (form == "text") data.encodeToByteArray() else b64.decode(data)
            }
        val recorded = goldens.associateBy { it.name }
        for ((name, input) in curated) {
            assertContentEquals(input, recorded[name]?.input, "$name changed since canonical-json.tsv was recorded")
        }
        assertEquals(goldens.size, recorded.size, "a name is recorded twice")
    }

    /**
     * The payload Remote Settings signs (spec §7.1), without its `Content-Signature:\0` prefix: the changeset's
     * records without tombstones, sorted by id, under `data`, and its `timestamp` as a string under `last_modified`.
     */
    private fun payload(changeset: JsonObject): JsonObject {
        val changes = (changeset["changes"] as JsonArray).items.map { it as JsonObject }
        val data =
            changes
                .filter { it["deleted"] != JsonBoolean.TRUE }
                .sortedWith { a, b -> JsonObject.compareCodePoints(id(a), id(b)) }
        val timestamp = checkNotNull((changeset["timestamp"] as JsonInteger).toLongOrNull())
        return JsonObject.of("data" to JsonArray(data), "last_modified" to JsonString(timestamp.toString()))
    }

    private fun id(record: JsonObject): String = (record["id"] as JsonString).value

    private fun checkChangeset(
        file: String,
        bytes: ByteArray,
    ) {
        val recorded = rows("remote-settings.tsv").filter { it[0] == file }
        assertEquals(listOf("document", "payload"), recorded.map { it[2] }, file)
        assertEquals(recorded[0][1], bytes.toByteString().sha256().hex(), "$file changed since it was recorded")
        val tree = Json.parse(bytes) as JsonObject
        for ((form, value) in listOf("document" to tree, "payload" to payload(tree))) {
            val canonical = CanonicalJson.write(value)
            val row = recorded.single { it[2] == form }
            assertEquals(
                row[3] to row[4].toInt(),
                canonical.toByteString().sha256().hex() to canonical.size,
                "$file $form",
            )
        }
    }

    @Test
    fun `the synthetic CRLite changeset's document and signed payload are canonical_json's`() {
        checkChangeset("crlite-changeset.json", resource("crlite-changeset.json"))
    }

    @Test
    fun `the recorded Remote Settings changeset of the large corpus is canonical_json's`() {
        val dir = ExternalCorpus.dir ?: return println("canonical JSON: no large corpus on this run (-Prevokt.corpus)")
        val file = "issuer/mozilla-intermediates/changeset.json"
        checkChangeset(file, File(dir, file).readBytes())
    }

    /**
     * Mozilla's own signature over the corpus changeset verifies against `Content-Signature:\0` plus revokt's canonical
     * payload (spec §7.1): the bytes revokt builds are the bytes Mozilla signed. It proves the bytes, not the chain: the
     * key is `metadata.signature.public_key`, which is unsigned metadata, not a key from the validated x5u chain.
     */
    @Test
    fun `Mozilla's signature over the corpus changeset verifies over revokt's payload`() {
        val dir =
            ExternalCorpus.dir ?: return println("content signature: no large corpus on this run (-Prevokt.corpus)")
        val tree = Json.parse(File(dir, "issuer/mozilla-intermediates/changeset.json").readBytes()) as JsonObject
        val signature = (tree["metadata"] as JsonObject)["signature"] as JsonObject
        val key =
            KeyFactory
                .getInstance("EC")
                .generatePublic(
                    X509EncodedKeySpec(Base64.getDecoder().decode((signature["public_key"] as JsonString).value)),
                )
        val verifier = Signature.getInstance("SHA384withECDSAinP1363Format")
        verifier.initVerify(key)
        verifier.update("Content-Signature:\u0000".encodeToByteArray() + CanonicalJson.write(payload(tree)))
        assertTrue(verifier.verify(Base64.getUrlDecoder().decode((signature["signature"] as JsonString).value)))
    }
}
