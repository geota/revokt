// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.store

import dev.revokt.CrliteChannel
import dev.revokt.Dataset
import dev.revokt.Freshness
import dev.revokt.RevoktLimits
import dev.revokt.engine.json.Json
import dev.revokt.engine.json.JsonObject
import dev.revokt.engine.verify.ContentSignature
import okio.ByteString.Companion.toByteString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The generation file's codec (spec §6.5 "the generation file", Load step 1). */
class GenerationFileTest {
    private val cap = GenerationFileJson.cap(RevoktLimits.MAX_JSON_BYTES)

    private fun text(bytes: ByteArray): String = bytes.decodeToString()

    /** [bytes] with [from] replaced by [to], once. */
    private fun edited(
        bytes: ByteArray,
        from: String,
        to: String,
    ): ByteArray {
        val s = text(bytes)
        assertEquals(1, s.split(from).size - 1, "$from once in $s")
        return s.replace(from, to).encodeToByteArray()
    }

    private fun read(bytes: ByteArray): GenerationFile? = GenerationFileJson.readUnhashed(bytes, cap)

    @Test
    fun `a sync's generation file is the canonical encoding of its members`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        assertEquals(
            """{"channel":"COMPAT","dataset":"CRLITE","freshness":"RECORD_LAST_MODIFIED","generationVersion":1,""" +
                """"records":{"data":[{"attachment":{"hash":"aa"},"id":"a","incremental":false},""" +
                """{"attachment":{"hash":"bb"},"id":"b","incremental":true}],"last_modified":"1762430400000"},""" +
                """"signature":"${"09".repeat(96)}","signerLeafSha256":"${"07".repeat(32)}"}""",
            text(bytes),
        )
        val back = assertNotNull(read(bytes))
        assertContentEquals(bytes, GenerationFileJson.write(back))
        assertEquals(1_762_430_400_000, back.lastModified)
        assertEquals(Freshness.RECORD_LAST_MODIFIED, back.freshness)
        assertNull(back.seedFormat)
    }

    @Test
    fun `the records member serialises to the signed payload, the seed's records json`() {
        val file = Generations.sync()
        assertContentEquals(ContentSignature.recordsJson(file.records, file.lastModified), file.payload)
        val member =
            text(
                GenerationFileJson.write(file),
            ).substringAfter("\"records\":").substringBefore(",\"signature\"")
        assertEquals(text(file.payload), member)
    }

    @Test
    fun `a seed's file carries seedFormat, and only a seed's does`() {
        val seed = Generations.seed()
        val bytes = GenerationFileJson.write(seed)
        assertTrue("\"seedFormat\":1" in text(bytes))
        assertEquals(1, assertNotNull(read(bytes)).seedFormat)
        assertNull(read(edited(bytes, ",\"seedFormat\":1", "")), "a seed's file without seedFormat")
        val sync = GenerationFileJson.write(Generations.sync())
        assertNull(read(edited(sync, "\"records\"", "\"seedFormat\":1,\"records\"")), "a sync's file with one")
        assertFailsWith<IllegalArgumentException> { Generations.sync(seedFormat = 1) }
        assertFailsWith<IllegalArgumentException> { Generations.seed(seedFormat = null) }
        assertFailsWith<IllegalArgumentException> { Generations.seed(seedFormat = 0) }
    }

    @Test
    fun `identical inputs give identical bytes and the same name, a re-sign or a seed another`() {
        val a = GenerationFileJson.write(Generations.sync())
        val b = GenerationFileJson.write(Generations.sync())
        assertContentEquals(a, b)
        val name = GenerationFileJson.name(a)
        assertTrue(GenerationNames.isSha256Hex(name), name)
        val resigned = GenerationFileJson.write(Generations.sync(signature = ByteArray(96) { 8 }))
        val seed = GenerationFileJson.write(Generations.seed())
        assertTrue(GenerationFileJson.name(resigned) != name && GenerationFileJson.name(seed) != name)
    }

    @Test
    fun `an unknown, missing or wrong member is malformed`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        assertNull(read(edited(bytes, "\"signature\"", "\"collection\":\"x\",\"signature\"")), "unknown member")
        for (member in listOf("channel", "dataset", "freshness", "generationVersion", "records", "signature")) {
            val s = text(bytes)
            val start = s.indexOf("\"$member\":")
            val valueEnd = if (member == "records") s.indexOf(",\"signature\"") else s.indexOf(',', start)
            val without = (s.substring(0, start) + s.substring(valueEnd + 1)).encodeToByteArray()
            assertNull(read(without), "without $member")
        }
        assertNull(read(edited(bytes, ",\"signerLeafSha256\":\"${"07".repeat(32)}\"", "")), "without signerLeafSha256")
        assertNull(read(edited(bytes, "\"generationVersion\":1", "\"generationVersion\":2")), "a newer version")
        assertNull(read(edited(bytes, "\"generationVersion\":1", "\"generationVersion\":\"1\"")), "a string version")
        assertNull(read(edited(bytes, "\"channel\":\"COMPAT\"", "\"channel\":\"compat\"")), "an enum by another name")
        assertNull(read(edited(bytes, "\"last_modified\"", "\"x\":1,\"last_modified\"")), "an extra records member")
    }

    @Test
    fun `only canonical bytes read, so whitespace, key order and a duplicate key are malformed`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        assertNull(read(edited(bytes, "{\"channel\"", "{ \"channel\"")), "whitespace")
        assertNull(
            read(
                edited(
                    bytes,
                    "\"channel\":\"COMPAT\",\"dataset\":\"CRLITE\"",
                    "\"dataset\":\"CRLITE\",\"channel\":\"COMPAT\"",
                ),
            ),
        )
        assertNull(read(edited(bytes, "\"channel\":\"COMPAT\"", "\"channel\":\"COMPAT\",\"channel\":\"COMPAT\"")))
        assertNull(read(edited(bytes, "\"aa\"", "\"\\u0061a\"")), "an escape the canonical form does not use")
    }

    @Test
    fun `records that are not the signed payload's are malformed`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        val a = """{"attachment":{"hash":"aa"},"id":"a","incremental":false}"""
        val b = """{"attachment":{"hash":"bb"},"id":"b","incremental":true}"""
        assertNull(read(edited(bytes, "$a,$b", "$b,$a")), "unsorted")
        assertNull(read(edited(bytes, "$a,$b", "$a,$a")), "a repeated id")
        assertNull(
            read(edited(bytes, "\"incremental\":true}", "\"incremental\":true,\"deleted\":true}")),
            "a tombstone",
        )
        // A tombstone with a number that has no canonical form: refused, never thrown (#332's fuzz finding).
        val decimal = edited(bytes, "\"incremental\":true}", "\"incremental\":true,\"deleted\":true,\"n\":1.5}")
        assertNull(read(decimal), "a tombstone holding a decimal")
        assertNull(read(edited(bytes, "\"incremental\":true}", "\"incremental\":true,\"n\":1.5}")), "a decimal")
        assertNull(read(edited(bytes, "\"data\":[$a,$b]", "\"data\":{}")), "data not an array")
        assertNull(read(edited(bytes, "\"data\":[$a,$b]", "\"data\":[$a,1]")), "a record not an object")
        for (stamp in listOf("01762430400000", "-1", "1.5", "x", "")) {
            assertNull(read(edited(bytes, "\"1762430400000\"", "\"$stamp\"")), "last_modified $stamp")
        }
        assertNull(read(edited(bytes, "\"1762430400000\"", "1762430400000")), "last_modified not a string")
    }

    @Test
    fun `a signature or leaf hash that is not lowercase hex of the right length is malformed`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        val sig = "09".repeat(96)
        for (bad in listOf("", "0", "09".repeat(95) + "0", "0A".repeat(96), "zz" + sig.drop(2))) {
            assertNull(read(edited(bytes, "\"$sig\"", "\"$bad\"")), "signature '$bad'")
        }
        assertNull(read(edited(bytes, "\"${"07".repeat(32)}\"", "\"${"07".repeat(31)}\"")), "a 31-byte leaf hash")
        for (size in listOf(64, 132)) {
            val file = Generations.sync(signature = ByteArray(size) { 9 })
            assertNotNull(read(GenerationFileJson.write(file)), "a $size-byte signature, any EC curve (§7.1)")
        }
    }

    @Test
    fun `the cap is the configured maxJsonBytes plus 64 KiB, checked before anything is parsed`() {
        assertEquals(RevoktLimits.MAX_JSON_BYTES + 65_536, cap)
        assertEquals(Long.MAX_VALUE, GenerationFileJson.cap(Long.MAX_VALUE - 1))
        assertFailsWith<IllegalArgumentException> { GenerationFileJson.cap(0) }
        val bytes = GenerationFileJson.write(Generations.sync())
        val name = GenerationFileJson.name(bytes)
        assertNotNull(GenerationFileJson.read(bytes, name, bytes.size.toLong()), "exactly at the cap")
        assertNull(GenerationFileJson.read(bytes, name, bytes.size - 1L), "one byte over")
        assertNull(GenerationFileJson.readUnhashed(bytes, bytes.size - 1L), "one byte over, unnamed")
    }

    @Test
    fun `the cap reaches the JSON reader, so a file over MAX_JSON_BYTES but under the cap reads`() {
        val pad = "x".repeat(RevoktLimits.MAX_JSON_BYTES.toInt())
        val records = listOf(Json.parse("{\"id\":\"a\",\"pad\":\"$pad\"}".encodeToByteArray(), cap) as JsonObject)
        val bytes = GenerationFileJson.write(Generations.sync(records = records))
        assertTrue(bytes.size > RevoktLimits.MAX_JSON_BYTES && bytes.size <= cap, "${bytes.size}")
        assertNotNull(GenerationFileJson.read(bytes, GenerationFileJson.name(bytes), cap))
    }

    @Test
    fun `the cap is checked at the write, and write and read agree at it`() {
        val file = Generations.sync()
        val bytes = GenerationFileJson.write(file)
        val size = bytes.size.toLong()
        assertContentEquals(bytes, GenerationFileJson.write(file, size))
        assertNull(GenerationFileJson.write(file, size - 1))
        assertNotNull(GenerationFileJson.read(bytes, GenerationFileJson.name(bytes), size))
        assertNull(GenerationFileJson.read(bytes, GenerationFileJson.name(bytes), size - 1))
    }

    @Test
    fun `a file is re-hashed against its name, so damage that still parses is no generation`() {
        val bytes = GenerationFileJson.write(Generations.sync())
        val name = GenerationFileJson.name(bytes)
        assertNotNull(GenerationFileJson.read(bytes, name, cap))
        // A delta's flag flipped: still a canonical generation file, but another one, under the wrong name.
        val damaged = edited(bytes, "\"incremental\":true", "\"incremental\":false")
        assertNotNull(read(damaged), "the damaged bytes still parse")
        assertNull(GenerationFileJson.read(damaged, name, cap), "the re-hash refuses them")
        assertNull(GenerationFileJson.read(bytes, "0".repeat(64), cap))
        assertNull(GenerationFileJson.read(bytes.copyOf(bytes.size / 2), name, cap), "truncated")
    }

    @Test
    fun `the constructor refuses records that are not the payload as given`() {
        val records = Generations.records()
        assertFailsWith<IllegalArgumentException> { Generations.sync(records = records.reversed()) }
        assertFailsWith<IllegalArgumentException> { Generations.sync(lastModified = -1) }
        assertFailsWith<IllegalArgumentException> { Generations.sync(signature = ByteArray(95)) }
        assertFailsWith<IllegalArgumentException> { Generations.sync(signature = ByteArray(0)) }
    }
}

/** Generation files for the codec and store tests. */
internal object Generations {
    fun records(): List<JsonObject> =
        listOf(
            """{"id":"a","incremental":false,"attachment":{"hash":"aa"}}""",
            """{"id":"b","incremental":true,"attachment":{"hash":"bb"}}""",
        ).map { Json.parse(it.encodeToByteArray()) as JsonObject }

    fun sync(
        records: List<JsonObject> = records(),
        lastModified: Long = 1_762_430_400_000,
        signature: ByteArray = ByteArray(96) { 9 },
        seedFormat: Int? = null,
        channel: CrliteChannel = CrliteChannel.COMPAT,
    ): GenerationFile =
        GenerationFile(
            dataset = Dataset.CRLITE,
            channel = channel,
            freshness = Freshness.RECORD_LAST_MODIFIED,
            seedFormat = seedFormat,
            signature = signature.toByteString(),
            signerLeafSha256 = ByteArray(32) { 7 }.toByteString(),
            records = records,
            lastModified = lastModified,
        )

    fun seed(seedFormat: Int? = 1): GenerationFile =
        GenerationFile(
            dataset = Dataset.CRLITE,
            channel = CrliteChannel.COMPAT,
            freshness = Freshness.SEED_SIGNED_TIME,
            seedFormat = seedFormat,
            signature = ByteArray(96) { 9 }.toByteString(),
            signerLeafSha256 = ByteArray(32) { 7 }.toByteString(),
            records = records(),
            lastModified = 1_762_430_400_000,
        )
}
