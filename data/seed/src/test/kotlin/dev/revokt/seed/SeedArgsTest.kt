// SPDX-FileCopyrightText: 2026 revokt contributors
// SPDX-License-Identifier: Apache-2.0

package dev.revokt.seed

import dev.revokt.CrliteChannel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The job entry's arguments (#145): each name once, nothing unknown, and the channels by wire name. */
class SeedArgsTest {
    private val names = setOf("--channel", "--version", "--out")

    @Test
    fun `each name once and nothing else`() {
        assertEquals(
            mapOf("--channel" to "compat", "--version" to "2026.11.23", "--out" to "x.zip"),
            SeedArgs.parse(arrayOf("--channel", "compat", "--version", "2026.11.23", "--out", "x.zip"), names),
        )
        assertNull(SeedArgs.parse(arrayOf("--channel", "compat", "--version", "2026.11.23"), names))
        assertNull(SeedArgs.parse(arrayOf("--channel", "compat", "--channel", "default", "--out", "x.zip"), names))
        assertNull(SeedArgs.parse(arrayOf("--channel", "compat", "--version", "v", "--pin", "x.zip"), names))
        assertNull(SeedArgs.parse(arrayOf("--channel", "compat", "--version", "v", "--out"), names))
    }

    @Test
    fun `channels by their wire names only`() {
        assertEquals(CrliteChannel.COMPAT, SeedArgs.channel("compat"))
        assertEquals(CrliteChannel.DEFAULT, SeedArgs.channel("default"))
        assertNull(SeedArgs.channel("COMPAT"))
        assertNull(SeedArgs.channel(""))
    }
}
