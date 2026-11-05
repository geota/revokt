// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.verify

import dev.revokt.SignatureVerifier
import dev.revokt.VerifyResult
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonArray
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.json.JsonString
import dev.revokt.engine.verify.ContentSignatureFailure.ENCODING
import dev.revokt.engine.verify.ContentSignatureFailure.INVALID
import dev.revokt.engine.verify.ContentSignatureFailure.MODE
import dev.revokt.engine.verify.ContentSignatureFailure.RECORDS
import dev.revokt.engine.verify.ContentSignatureFailure.UNSUPPORTED
import dev.revokt.verify.JcaFixtures
import dev.revokt.verify.JcaFixtures.ECDSA_SHA384
import dev.revokt.verify.JcaFixtures.flip
import dev.revokt.verify.JcaSignatureVerifier
import java.security.KeyPair
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Spec §7.1 "Verify" and "Content signature", §6.5 (`records.json` verified as raw bytes) and §9 "Content-signature
 * fixtures" (with mutations; a `mode` other than `p384ecdsa`; the signature over records with a tombstone merged vs not
 * merged). Every signature is made here by the test JDK under a fresh P-384 key, as Autograph makes it:
 * `SHA384withECDSAinP1363Format` (raw `r ‖ s`) over `"Content-Signature:\0"` and the payload, base64url without
 * padding. The x5u chain that certifies the key is #126's.
 */
class ContentSignatureTest {
    private val verifier = JcaSignatureVerifier()
    private val key: KeyPair = JcaFixtures.ec("secp384r1")
    private val spki: ByteArray = key.public.encoded
    private val prefix = "Content-Signature:\u0000".encodeToByteArray()
    private val url = Base64.getUrlEncoder().withoutPadding()

    private fun records(json: String): List<JsonObject> =
        (Json.parse(json.encodeToByteArray()) as JsonArray).items.map { it as JsonObject }

    private val stored =
        records(
            """[{"id":"c","last_modified":3,"v":"é"},{"id":"a","last_modified":1,"n":[1.5,-0]},
               {"id":"b","last_modified":2}]""",
        )

    private fun payload(
        records: List<JsonObject> = stored,
        ts: Long = TS,
    ): ByteArray = checkNotNull(ContentSignature.recordsJson(records, ts))

    private fun sign(
        message: ByteArray,
        pair: KeyPair = key,
        algorithm: String = "SHA384withECDSAinP1363Format",
    ): String = url.encodeToString(JcaFixtures.sign(algorithm, pair.private, message))

    private fun signPayload(body: ByteArray = payload()): String = sign(prefix + body)

    private fun raw(
        body: ByteArray,
        signature: String?,
        mode: String? = ContentSignature.MODE,
        leaf: ByteArray = spki,
        with: SignatureVerifier = verifier,
    ): ContentSignatureResult = ContentSignature.verifyRawPayload(with, body, signature, mode, leaf)

    private fun records(
        records: List<JsonObject>,
        signature: String?,
        ts: Long = TS,
        mode: String? = ContentSignature.MODE,
    ): ContentSignatureResult = ContentSignature.verifyRecords(verifier, records, ts, signature, mode, spki)

    private fun assertFailed(
        failure: ContentSignatureFailure,
        result: ContentSignatureResult,
        message: String? = null,
    ) = assertEquals(failure, result.failure, message)

    @Test
    fun `the payload is the canonical JSON of the records by id under data and the timestamp as a string`() {
        val withTombstone = stored + records("""[{"id":"0","deleted":true,"last_modified":4}]""")
        assertEquals(
            """{"data":[{"id":"a","last_modified":1,"n":[1.5E0,-0E0]},{"id":"b","last_modified":2},""" +
                """{"id":"c","last_modified":3,"v":"\u00e9"}],"last_modified":"1792587631204"}""",
            payload(withTombstone).decodeToString(),
        )
        assertEquals("""{"data":[],"last_modified":"0"}""", payload(emptyList(), 0).decodeToString())
    }

    @Test
    fun `ids sort by code point, not by UTF-16 unit`() {
        // U+FF5E is above the surrogates in UTF-16 but below U+1F600 in code points (and UTF-8).
        val ids = records("""[{"id":"\ud83d\ude00"},{"id":"\uff5e"},{"id":"Z"},{"id":"a"}]""")
        val data = (Json.parse(payload(ids)) as JsonObject)["data"] as JsonArray
        assertEquals(listOf("Z", "a", "\uff5e", "\ud83d\ude00"), data.items.map { id(it as JsonObject) })
    }

    @Test
    fun `a valid signature verifies over the records and over the raw records json`() {
        val signature = signPayload()
        assertTrue(records(stored, signature).verified)
        assertTrue(records(stored.reversed(), signature).verified, "the order the records arrive in is not signed")
        assertTrue(raw(payload(), signature).verified)
        assertEquals(ContentSignatureResult.VERIFIED, raw(payload(), signature))
    }

    @Test
    fun `a mode other than p384ecdsa fails before anything else`() {
        val signature = signPayload()
        for (mode in listOf(
            null,
            "",
            "p256ecdsa",
            "P384ECDSA",
            "p384ecdsa ",
            " p384ecdsa",
            "p384ecdsa\u0000",
            "p521ecdsa",
        )) {
            assertFailed(MODE, raw(payload(), signature, mode), "mode $mode")
            assertFailed(MODE, records(stored, signature, mode = mode), "mode $mode")
        }
    }

    @Test
    fun `a flipped payload byte at every position fails`() {
        val body = payload()
        val signature = signPayload(body)
        for (i in body.indices) assertFailed(INVALID, raw(flip(body, i), signature), "payload byte $i")
        for (i in body.indices) assertFailed(INVALID, raw(flip(body, i, 0x80), signature), "payload byte $i high bit")
        assertFailed(INVALID, raw(body.copyOf(body.size - 1), signature), "truncated payload")
        assertFailed(INVALID, raw(body + '\n'.code.toByte(), signature), "a trailing newline")
        assertFailed(INVALID, raw(ByteArray(0), signature), "an empty payload")
    }

    @Test
    fun `a signature over another prefix or framing fails`() {
        val body = payload()
        val framings =
            mapOf(
                "no prefix" to body,
                "no NUL" to "Content-Signature:".encodeToByteArray() + body,
                "two NULs" to "Content-Signature:\u0000\u0000".encodeToByteArray() + body,
                "a space for the NUL" to "Content-Signature: ".encodeToByteArray() + body,
                "lower case" to "content-signature:\u0000".encodeToByteArray() + body,
                "a newline after" to prefix + body + '\n'.code.toByte(),
                "the payload first" to body + prefix,
            )
        for ((name, message) in framings) assertFailed(INVALID, raw(body, sign(message)), name)
        for (i in prefix.indices) {
            assertFailed(INVALID, raw(body, sign(flip(prefix + body, i))), "prefix byte $i flipped")
        }
    }

    @Test
    fun `a mutated signature fails`() {
        val signature = signPayload()
        val bytes = Base64.getUrlDecoder().decode(signature)
        assertEquals(RawSignature.RAW_BYTES, bytes.size)
        for (i in bytes.indices) {
            assertFailed(
                INVALID,
                raw(payload(), url.encodeToString(flip(bytes, i))),
                "signature byte $i",
            )
        }
        val swapped = bytes.copyOfRange(48, 96) + bytes.copyOfRange(0, 48)
        assertFailed(INVALID, raw(payload(), url.encodeToString(swapped)), "r and s swapped")
        assertFailed(INVALID, raw(payload(), url.encodeToString(ByteArray(96))), "all zero")
        assertFailed(INVALID, raw(payload(), url.encodeToString(ByteArray(96) { -1 })), "all ones")
    }

    @Test
    fun `a signature that is not 128 base64url characters fails as an encoding`() {
        val signature = signPayload()
        val bytes = Base64.getUrlDecoder().decode(signature)
        val encodings =
            mapOf(
                "absent" to null,
                "empty" to "",
                "one character short" to signature.dropLast(1),
                "a group short" to signature.dropLast(4),
                "95 bytes" to url.encodeToString(bytes.copyOf(95)),
                "97 bytes" to url.encodeToString(bytes + 0),
                "padded" to "$signature==",
                "padding inside" to signature.dropLast(1) + "=",
                "standard alphabet" to Base64.getEncoder().encodeToString(bytes).replace('A', '+'),
                "a space" to " " + signature.drop(1),
                "a non-ASCII digit" to "\u0660" + signature.drop(1),
                "a trailing newline" to signature + "\n",
            )
        for ((name, text) in encodings) {
            assertFailed(ENCODING, raw(payload(), text), name)
            assertFailed(ENCODING, records(stored, text), name)
        }
    }

    @Test
    fun `a DER signature where raw r and s belong fails`() {
        val body = payload()
        val der = JcaFixtures.sign("SHA384withECDSA", key.private, prefix + body)
        // A P-384 ECDSA-Sig-Value is 96 bytes only when r and s lose 4 leading bytes between them (p ≈ 2^-32).
        if (der.size == RawSignature.RAW_BYTES) return
        assertFailed(ENCODING, raw(body, url.encodeToString(der)))
        assertFailed(ENCODING, raw(body, Base64.getEncoder().withoutPadding().encodeToString(der)))
    }

    @Test
    fun `a signature with another hash fails`() {
        val message = prefix + payload()
        for (algorithm in listOf(
            "SHA256withECDSAinP1363Format",
            "SHA512withECDSAinP1363Format",
            "SHA1withECDSAinP1363Format",
        )) {
            assertFailed(INVALID, raw(payload(), sign(message, algorithm = algorithm)), algorithm)
        }
    }

    @Test
    fun `a key on another curve, or not an EC key, fails`() {
        val message = prefix + payload()
        // A P-256 or P-521 signature is 64 or 132 bytes raw, never the 96 of P-384.
        for (curve in listOf("secp256r1", "secp521r1")) {
            val other = JcaFixtures.ec(curve)
            assertFailed(ENCODING, raw(payload(), sign(message, other)), curve)
            assertFailed(
                INVALID,
                raw(payload(), signPayload(), leaf = other.public.encoded),
                "P-384 signature, $curve leaf",
            )
        }
        val rsa = JcaFixtures.rsa().public.encoded
        assertFailed(INVALID, raw(payload(), signPayload(), leaf = rsa), "an RSA leaf")
        assertFailed(INVALID, raw(payload(), signPayload(), leaf = ByteArray(0)), "an empty SPKI")
        assertFailed(INVALID, raw(payload(), signPayload(), leaf = spki.copyOf(spki.size - 1)), "a truncated SPKI")
        val otherP384 = JcaFixtures.pair("other-p384") { JcaFixtures.generate("EC", ECGenParameterSpec("secp384r1")) }
        assertFailed(INVALID, raw(payload(), signPayload(), leaf = otherP384.public.encoded), "another P-384 key")
    }

    @Test
    fun `the raw records json is hashed unchanged, so a space that decodes the same fails`() {
        val body = payload()
        val signature = signPayload(body)
        val spaced = byteArrayOf(body[0], ' '.code.toByte()) + body.copyOfRange(1, body.size)
        assertEquals(Json.parse(body), Json.parse(spaced), "the spaced file decodes to the same tree")
        assertFailed(INVALID, raw(spaced, signature))
        val decoded = (Json.parse(spaced) as JsonObject)["data"] as JsonArray
        assertTrue(records(decoded.items.map { it as JsonObject }, signature).verified, "re-serialised, it verifies")
    }

    @Test
    fun `the timestamp is signed`() {
        val signature = signPayload()
        assertFailed(INVALID, records(stored, signature, ts = TS + 1))
        assertFailed(INVALID, records(stored, signature, ts = -TS))
    }

    @Test
    fun `a tombstone merges first, and only the merged set verifies`() {
        val changes =
            records(
                """[{"id":"b","deleted":true,"last_modified":5},{"id":"d","last_modified":6},
                   {"id":"c","last_modified":7,"v":"new"},{"id":"zz","deleted":true,"last_modified":8}]""",
            )
        val merged = checkNotNull(ContentSignature.merge(stored, changes))
        assertEquals(
            records(
                """[{"id":"a","last_modified":1,"n":[1.5,-0]},{"id":"c","last_modified":7,"v":"new"},{"id":"d","last_modified":6}]""",
            ),
            merged,
        )
        val signature = signPayload(payload(merged, TS + 8))
        assertTrue(records(merged, signature, ts = TS + 8).verified, "merged")
        // The stored set with the replaced and added records applied but the tombstone for b ignored.
        val unmerged = stored.filter { id(it) != "c" } + changes.filter { id(it) == "c" || id(it) == "d" }
        assertFailed(INVALID, records(unmerged, signature, ts = TS + 8), "the tombstone for b not merged")
        assertFailed(INVALID, records(changes, signature, ts = TS + 8), "the changes alone")
        assertFailed(RECORDS, records(stored + changes, signature, ts = TS + 8), "stored and changes concatenated")
    }

    @Test
    fun `merge keys by id, the last change winning`() {
        val changes = records("""[{"id":"e","v":1},{"id":"e","v":2},{"id":"a","deleted":true},{"id":"a","v":3}]""")
        assertEquals(
            records(
                """[{"id":"a","v":3},{"id":"b","last_modified":2},{"id":"c","last_modified":3,"v":"é"},{"id":"e","v":2}]""",
            ),
            ContentSignature.merge(stored, changes),
        )
        assertEquals(emptyList(), ContentSignature.merge(emptyList(), records("""[{"id":"x","deleted":true}]""")))
        assertEquals(
            records("""[{"id":"x","deleted":false}]"""),
            ContentSignature.merge(emptyList(), records("""[{"id":"x","deleted":false}]""")),
            "only deleted: true is a tombstone",
        )
        assertEquals(
            records("""[{"id":"y","v":2}]"""),
            ContentSignature.merge(
                records("""[{"id":"x","deleted":true},{"id":"y","v":1},{"id":"y","v":2}]"""),
                emptyList(),
            ),
            "a stored tombstone is removed and the last stored record of an id wins",
        )
    }

    @Test
    fun `a record without a string id has no payload`() {
        for (bad in listOf("""{"v":1}""", """{"id":1}""", """{"id":null}""", """{"id":["a"]}""")) {
            val record = records("[$bad]")
            assertNull(ContentSignature.merge(stored, record), bad)
            assertNull(ContentSignature.merge(record, emptyList()), bad)
            assertNull(ContentSignature.recordsJson(stored + record, TS), bad)
            assertFailed(RECORDS, records(stored + record, signPayload()), bad)
        }
        assertNull(ContentSignature.recordsJson(stored + stored.first(), TS), "two records with one id")
        assertNull(
            ContentSignature.merge(records("""[{"id":"x","deleted":true,"v":1}]"""), records("""[{"deleted":true}]""")),
        )
    }

    @Test
    fun `the verifier gets ecdsa-with-SHA384, the leaf SPKI, the prefixed payload and the DER signature`() {
        val body = payload()
        val signature = signPayload(body)
        val calls = mutableListOf<List<ByteArray>>()
        val recording =
            stub { sigAlg, key, message, sig ->
                calls += listOf(sigAlg, key, message, sig)
                VerifyResult.VERIFIED
            }
        assertTrue(raw(body, signature, with = recording).verified)
        val call = calls.single()
        assertContentEquals(JcaFixtures.algId(ECDSA_SHA384), call[0])
        assertContentEquals(spki, call[1])
        assertContentEquals(prefix + body, call[2])
        assertContentEquals(RawSignature.toDer(Base64.getUrlDecoder().decode(signature)), call[3])
    }

    @Test
    fun `anything but VERIFIED fails, and a verifier throw is INVALID with its message`() {
        val signature = signPayload()
        assertFailed(UNSUPPORTED, raw(payload(), signature, with = stub { _, _, _, _ -> VerifyResult.UNSUPPORTED }))
        assertFailed(INVALID, raw(payload(), signature, with = stub { _, _, _, _ -> VerifyResult.INVALID }))
        val threw =
            raw(
                payload(),
                signature,
                with =
                    stub {
                        _,
                        _,
                        _,
                        _,
                        ->
                        throw IllegalStateException("provider broke")
                    },
            )
        assertFailed(INVALID, threw)
        assertEquals("provider broke", threw.verifierError)
        assertEquals("ContentSignatureResult(INVALID, provider broke)", threw.toString())
        assertFailsWith<OutOfMemoryError> {
            raw(
                payload(),
                signature,
                with =
                    stub {
                        _,
                        _,
                        _,
                        _,
                        ->
                        throw OutOfMemoryError()
                    },
            )
        }
    }

    @Test
    fun `a malformed signature or mode never reaches the verifier`() {
        val never = stub { _, _, _, _ -> error("called") }
        assertFailed(MODE, raw(payload(), signPayload(), mode = "p256ecdsa", with = never))
        assertFailed(ENCODING, raw(payload(), "x", with = never))
    }

    private fun id(record: JsonObject): String = (record["id"] as JsonString).value

    private fun flip(
        bytes: ByteArray,
        index: Int,
        mask: Int,
    ): ByteArray = bytes.copyOf().also { it[index] = (it[index].toInt() xor mask).toByte() }

    private fun stub(answer: (ByteArray, ByteArray, ByteArray, ByteArray) -> VerifyResult): SignatureVerifier =
        object : SignatureVerifier {
            override fun verify(
                sigAlg: ByteArray,
                spki: ByteArray,
                message: ByteArray,
                signature: ByteArray,
            ): VerifyResult = answer(sigAlg, spki, message, signature)

            override fun unsupportedOids(): Set<String> = emptySet()
        }

    private companion object {
        const val TS = 1792587631204L
    }
}
