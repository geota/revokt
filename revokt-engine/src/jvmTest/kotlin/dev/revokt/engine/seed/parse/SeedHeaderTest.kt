// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.engine.seed.parse

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** `seed.json` as the header read reads it (spec §6.5; #138): each member of its type, nothing else checked here. */
class SeedHeaderTest {
    private val good =
        mapOf(
            "seedFormat" to "1",
            "channel" to "\"COMPAT\"",
            "dataset" to "\"CRLITE\"",
            "filterFormat" to "\"V3\"",
            "recordsLastModified" to "1792587631204",
            "engineFloor" to "1",
        )

    private fun json(members: Map<String, String>): ByteArray =
        members.entries.joinToString(",", "{", "}") { (k, v) -> "\"$k\":$v" }.encodeToByteArray()

    private fun rejects(
        bytes: ByteArray,
        message: String,
    ) {
        val e = assertFailsWith<SeedFormatException> { SeedHeader.read(bytes) }
        assertTrue(message in e.message.orEmpty(), "${e.message} does not say $message")
    }

    @Test
    fun `a header reads every member, and ignores others`() {
        val header = SeedHeader.read(json(good + ("comment" to "\"weekly\"")))
        assertEquals(
            listOf<Any>(1L, "COMPAT", "CRLITE", "V3", 1_792_587_631_204L, 1L),
            listOf(
                header.seedFormat,
                header.channel,
                header.dataset,
                header.filterFormat,
                header.recordsLastModified,
                header.engineFloor,
            ),
        )
        assertTrue("COMPAT" in header.toString())
    }

    @Test
    fun `anything but an object of typed members is rejected`() {
        rejects("{".encodeToByteArray(), "not JSON")
        rejects("[]".encodeToByteArray(), "not an object")
        rejects(ByteArray((64 shl 10) + 1) { ' '.code.toByte() }, "not JSON")
        rejects(json(good + ("seedFormat" to "1.0")), "seedFormat is not an integer")
        rejects(json(good + ("engineFloor" to "18446744073709551616")), "engineFloor is not an integer")
        rejects(json(good - "recordsLastModified"), "recordsLastModified is not an integer")
        rejects(json(good + ("channel" to "1")), "channel is not a string")
        rejects(json(good - "dataset"), "dataset is not a string")
    }
}
